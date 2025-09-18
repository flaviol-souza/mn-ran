#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UcvController v0:
- OpenFlow 1.3; learning + classificação:
    * UDP/14550 ou DSCP EF(46) => Queue 0 (C2)
    * demais => Queue 1 (ISR)
- Laço de política (thread):
    * detection_mode: "netem" => considera 'degraded' se tc qdisc netem presente
    * aplica perfis de QoS (baseline/degraded) nas queues 0 e 1 das portas listadas
      no policy.yaml, via 'ovs-vsctl set queue <uuid> other-config:min-rate=...'
"""

import os, re, json, time, threading, subprocess, shlex, statistics, collections, yaml
from pathlib import Path

from ryu.lib import hub
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, udp

C2_UDP_PORT = 14550
DSCP_EF = 46

# Parse MAVLink seq from hex payload (supports v1/v2)
def _mavlink_seq_from_hex(hexstr: str):
    try:
        b = bytes.fromhex(hexstr.replace(':',''))
    except Exception:
        return None
    if not b:
        return None
    # v1: 0xFE, LEN, SEQ, SYSID, COMPID, MSGID
    # v2: 0xFD, LEN, INCOMP, COMP, SEQ, SYSID, COMPID, MSGID(3)
    if b[0] == 0xFE and len(b) >= 6:
        return b[2]
    if b[0] == 0xFD and len(b) >= 8:
        return b[4]
    # fallback: try to find 0xFE/0xFD and re-evaluate
    for i in range(len(b)-8):
        if b[i] == 0xFE and i+6 <= len(b): return b[i+2]
        if b[i] == 0xFD and i+8 <= len(b): return b[i+4]
    return None

class KpiState:
    def __init__(self):
        self.lock = threading.Lock()
        self.loss_pct = 0.0
        self.jitter_p95_ms = 0.0
        self.samples = 0
        self.last_change = time.time()
        self.state = 'baseline'  # or 'degraded'

def sh(cmd):
    """Run shell cmd, return (rc, out)."""
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    out, _ = p.communicate()
    return p.returncode, out.strip()

def load_policy(path="policy.yaml"):
    with open(path, "r") as f:
        return yaml.safe_load(f)

def has_netem(intf):
    rc, out = sh(f"tc qdisc show dev {intf}")
    # procura por 'netem' em qualquer qdisc root
    return (" netem " in out) or out.strip().startswith("qdisc netem")

def get_queue_ids_for_port(port_name):
    """
    Retorna (q0_uuid, q1_uuid) da porta 'port_name'.
    Lê Port->qos->queues via ovs-vsctl.
    """
    rc, qos_uuid = sh(f"ovs-vsctl -- if-exists get Port {port_name} qos")
    if rc != 0 or not qos_uuid or qos_uuid.strip() in ("[]", "[]\n", "null"):
        return (None, None)
    qos_uuid = qos_uuid.strip()
    rc, queues_map = sh(f"ovs-vsctl get QoS {qos_uuid} queues")
    # Ex.: "{0=c1b4b4d8-..., 1=00a1...}"
    m0 = re.search(r"0=([0-9a-fA-F-]{36})", queues_map)
    m1 = re.search(r"1=([0-9a-fA-F-]{36})", queues_map)
    q0 = m0.group(1) if m0 else None
    q1 = m1.group(1) if m1 else None
    return (q0, q1)

def set_queue_rates(queue_uuid, min_rate, max_rate):
    if not queue_uuid:
        return
    sh(f"ovs-vsctl set queue {queue_uuid} other-config:min-rate={int(min_rate)}")
    sh(f"ovs-vsctl set queue {queue_uuid} other-config:max-rate={int(max_rate)}")

class UcvController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(UcvController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        # política
        self.policy_path = os.environ.get("UCV_POLICY", "policy.yaml")
        self.policy = load_policy(self.policy_path)
        self.detection_mode = self.policy.get("detection_mode", "netem")
        self.kpi_cfg = self.policy.get("kpi", {})
        self.interfaces = self.policy.get("interfaces", ['s1-eth2', 's1-eth3', 's1-eth4', 's1-eth5'])
        self.qos_profiles = self.policy.get("qos_profiles", {})
        self.poll_seconds = int(self.policy.get("poll_seconds", 2))

        self._last_state = None
        self._policy_stop = False
        self.logger.info(f"Policy loaded: {self.policy}")

        # inicia thread de política
        self.policy_thread = threading.Thread(target=self._policy_loop, daemon=True)
        self.policy_thread.start()

        # --- KPI config & state (bem alinhado) ---
        self.kpi = KpiState()
        self.kpi_if = 'root-eth0'   # interface no host onde o C2 chega
        self.kpi_port = 14550
        self.kpi_window = 200
        self.kpi_degrade_loss = 2.0  # %
        self.kpi_recover_loss = 1.0  # %
        self.kpi_degrade_jit = 60.0  # ms (p95)
        self.kpi_recover_jit = 40.0  # ms (p95)
        self.kpi_degrade_hold = 5.0  # s
        self.kpi_recover_hold = 10.0 # s

        # Iniciar monitor KPI apenas quando usado
        if self.detection_mode in ('kpi', 'kpi_or_netem'):
            self.logger.info("[kpi] starting live KPI monitor on %s udp/%d",
                            self.kpi_if, self.kpi_port)
            hub.spawn(self._kpi_loop)
        else:
            self.logger.info("[kpi] detection_mode=%s -> KPI monitor disabled", self.detection_mode)

    def _state_from_kpi_file(self, last_state):
        path = self.kpi_cfg.get("source_file", "/tmp/kpi_state.tsv")
        enter = self.kpi_cfg.get("enter", {})
        exitc = self.kpi_cfg.get("exit", {})

        try:
            with open(path, "r") as f:
                lines = [ln.strip() for ln in f if ln.strip()]
            if not lines:
                return last_state or "baseline"
            # lê última linha útil (ignora cabeçalho)
            row = lines[-1]
            if row.startswith("ts_epoch"):
                if len(lines) == 1:
                    return last_state or "baseline"
                row = lines[-2]
            parts = row.split("\t")
            # ts, loss, jitter, kbps
            ts = float(parts[0]); loss = float(parts[1]); jitter = float(parts[2]); kbps = float(parts[3])

            if last_state == "degraded":
                ok = True
                if "c2_loss_pct" in exitc:      ok &= (loss <= float(exutc := exitc["c2_loss_pct"]))
                if "c2_jitter_ms" in exitc:     ok &= (jitter <= float(exitc["c2_jitter_ms"]))
                if "video_kbps_min" in exitc:   ok &= (kbps  >= float(exitc["video_kbps_min"]))
                return "baseline" if ok else "degraded"
            else:
                bad = False
                if "c2_loss_pct" in enter:      bad |= (loss >= float(enter["c2_loss_pct"]))
                if "c2_jitter_ms" in enter:     bad |= (jitter >= float(enter["c2_jitter_ms"]))
                if "video_kbps_min" in enter:   bad |= (kbps  <  float(enter["video_kbps_min"]))
                return "degraded" if bad else "baseline"

        except Exception as e:
            self.logger.warning(f"[kpi] parse fail: {e}")
            return last_state or "baseline"

    def _kpi_loop(self):
        """
        Live KPI monitor:
        - runs tshark on root-eth0 udp/14550
        - computes loss% and p95 jitter over a sliding window
        - updates self.kpi.state with hysteresis
        """
        # Use tshark line mode; fields: epoch time, payload hex
        cmd = f'tshark -l -i {self.kpi_if} -f "udp port {self.kpi_port}" ' \
              f'-T fields -e frame.time_epoch -e data.data'
        self.logger.info("[kpi] exec: %s", cmd)
        try:
            p = subprocess.Popen(shlex.split(cmd),
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL,
                                 text=True, bufsize=1)
        except Exception as e:
            self.logger.error("[kpi] cannot start tshark: %s", e)
            return

        last_ts = None
        last_seq = None
        ia_ms = collections.deque(maxlen=self.kpi_window)  # inter-arrival ms
        loss_cnt = 0
        total_cnt = 0

        for line in p.stdout:
            parts = line.strip().split('\t')
            if len(parts) < 2:
                continue
            try:
                t = float(parts[0])
            except:
                continue
            seq = _mavlink_seq_from_hex(parts[1])
            if seq is None:
                continue

            total_cnt += 1
            # inter-arrival
            if last_ts is not None:
                ia_ms.append((t - last_ts) * 1000.0)
            last_ts = t

            # loss via seq gaps (mod 256)
            if last_seq is not None:
                diff = (seq - last_seq) & 0xFF
                if diff > 1:
                    loss_cnt += (diff - 1)
            last_seq = seq

            # compute KPIs every ~1s
            if total_cnt % 50 == 0 and ia_ms:
                with self.kpi.lock:
                    self.kpi.samples = len(ia_ms)
                    # jitter approximation: p95 of inter-arrival delta deviation
                    try:
                        p95 = statistics.quantiles(list(ia_ms), n=20)[18]  # ~95th
                    except Exception:
                        p95 = sorted(ia_ms)[int(0.95*len(ia_ms))-1]
                    self.kpi.jitter_p95_ms = p95
                    # loss% over observed packets
                    recv = total_cnt
                    self.kpi.loss_pct = (100.0 * loss_cnt) / max(recv + loss_cnt, 1)

                    # hysteresis decision
                    now = time.time()
                    prev = self.kpi.state
                    if (self.kpi.loss_pct > self.kpi_degrade_loss or
                        self.kpi.jitter_p95_ms > self.kpi_degrade_jit):
                        if prev != 'degraded' and now - self.kpi.last_change >= self.kpi_degrade_hold:
                            self.kpi.state = 'degraded'
                            self.kpi.last_change = now
                            self.logger.info("[kpi] degrade: loss=%.2f%% jitter_p95=%.1f ms",
                                             self.kpi.loss_pct, self.kpi.jitter_p95_ms)
                    elif (self.kpi.loss_pct < self.kpi_recover_loss and
                          self.kpi.jitter_p95_ms < self.kpi_recover_jit):
                        if prev != 'baseline' and now - self.kpi.last_change >= self.kpi_recover_hold:
                            self.kpi.state = 'baseline'
                            self.kpi.last_change = now
                            self.logger.info("[kpi] recover: loss=%.2f%% jitter_p95=%.1f ms",
                                             self.kpi.loss_pct, self.kpi.jitter_p95_ms)

        self.logger.warning("[kpi] tshark terminated")

    def _kpi_current_state(self):
        with self.kpi.lock:
            return (self.kpi.state, self.kpi.loss_pct, self.kpi.jitter_p95_ms, self.kpi.samples)

    def _policy_loop(self):
        """
        Periodicamente decide 'baseline' ou 'degraded' e aplica o perfil QoS
        (somente aplica quando TODAS as portas em self.interfaces já tiverem queues 0/1)
        Suporta detection_mode: 'netem' | 'kpi' | 'kpi_or_netem'
        """
        last_state = None  # 'baseline' ou 'degraded'
        last_kpi_log = 0

        while not getattr(self, "_policy_stop", False):
            try:
                # 1) Decidir estado-alvo conforme detection_mode
                mode = getattr(self, "detection_mode", "netem")
                state = "baseline"

                if mode == "netem":
                    state = "degraded" if any(has_netem(intf) for intf in self.interfaces) else "baseline"

                elif mode == "kpi":
                    st, loss, jit, n = self._kpi_current_state()   # definido no patch KPI
                    state = st
                    # log leve de KPI a cada ~5s
                    now = time.time()
                    if now - last_kpi_log > 5:
                        self.logger.debug("[kpi] n=%d loss=%.2f%% jitter_p95=%.1fms -> %s",
                                        n, loss, jit, state)
                        last_kpi_log = now
                
                elif mode == "kpi_file":
                    state = self._state_from_kpi_file(last_state)

                elif mode in ("kpi_or_netem", "both"):
                    # degrada se KPI OU NETEM indicar degradação
                    kst, loss, jit, n = self._kpi_current_state()
                    net = any(has_netem(intf) for intf in self.interfaces)
                    state = "degraded" if (kst == "degraded" or net) else "baseline"

                else:
                    # default seguro
                    state = "baseline"

                # 2) Preparar mapa de filas (garante que existem antes de aplicar)
                ready = True
                qmap = {}
                for intf in self.interfaces:
                    q0, q1 = get_queue_ids_for_port(intf)
                    if not q0 or not q1:
                        ready = False
                        break
                    qmap[intf] = (q0, q1)

                if not ready:
                    # ainda não há filas; tenta no próximo ciclo
                    time.sleep(self.poll_seconds)
                    continue

                # 3) Aplicar perfil apenas quando mudar de estado
                if state != last_state:
                    prof = self.qos_profiles.get(state, {})
                    self.logger.info("[policy] Applying QoS profile: %s -> %s", state, prof)
                    for intf, (q0, q1) in qmap.items():
                        set_queue_rates(q0, prof.get("q0_min", 0), prof.get("q0_max", 0))
                        set_queue_rates(q1, prof.get("q1_min", 0), prof.get("q1_max", 0))
                    last_state = state

            except Exception as e:
                self.logger.exception("[policy] loop error: %s", e)

            time.sleep(self.poll_seconds)


    def close(self):
        self._policy_stop = True
        try:
            self.policy_thread.join(timeout=1.0)
        except Exception:
            pass

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        # table-miss -> controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, match, actions)

        # ARP -> NORMAL (prioridade 50)
        match = parser.OFPMatch(eth_type=0x0806)
        actions = [parser.OFPActionOutput(ofp.OFPP_NORMAL)]
        self.add_flow(dp, 50, match, actions, idle=0, hard=0)

        # ICMP -> NORMAL (prioridade 40)
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=1)
        actions = [parser.OFPActionOutput(ofp.OFPP_NORMAL)]
        self.add_flow(dp, 40, match, actions, idle=0, hard=0)

        # UDP/14550 (C2) proactive: Queue 0 + L2 NORMAL (ambos sentidos)
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, udp_dst=14550)
        actions = [parser.OFPActionSetQueue(0), parser.OFPActionOutput(ofp.OFPP_NORMAL)]
        self.add_flow(dp, 60, match, actions, idle=0, hard=0)

        match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, udp_src=14550)
        actions = [parser.OFPActionSetQueue(0), parser.OFPActionOutput(ofp.OFPP_NORMAL)]
        self.add_flow(dp, 60, match, actions, idle=0, hard=0)

        # UDP/5600 (vídeo) proactive: Queue 1 + L2 NORMAL (ambos sentidos)
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, udp_dst=5600)
        actions = [parser.OFPActionSetQueue(1), parser.OFPActionOutput(ofp.OFPP_NORMAL)]
        self.add_flow(dp, 55, match, actions, idle=0, hard=0)

        match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, udp_src=5600)
        actions = [parser.OFPActionSetQueue(1), parser.OFPActionOutput(ofp.OFPP_NORMAL)]
        self.add_flow(dp, 55, match, actions, idle=0, hard=0)

    def add_flow(self, datapath, priority, match, actions, idle=30, hard=60):
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst,
                                idle_timeout=idle, hard_timeout=hard)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        in_port = msg.match['in_port']
        dpid = dp.id
        self.mac_to_port.setdefault(dpid, {})

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth.ethertype == 0x88cc:  # LLDP
            return

        dst = eth.dst
        src = eth.src
        self.mac_to_port[dpid][src] = in_port

        # saída: learning básico
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofp.OFPP_FLOOD

        actions = []
        ip = pkt.get_protocol(ipv4.ipv4)
        q = 1  # default ISR
        if ip:
            ip_dscp = (ip.tos >> 2) & 0x3F
            udp_hdr = pkt.get_protocol(udp.udp)
            is_c2 = udp_hdr and (udp_hdr.src_port == C2_UDP_PORT or udp_hdr.dst_port == C2_UDP_PORT)
            if is_c2 or ip_dscp == DSCP_EF:
                q = 0
            actions.append(parser.OFPActionSetQueue(q))
        actions.append(parser.OFPActionOutput(out_port))

        # instala fluxo
        match_fields = dict(in_port=in_port, eth_src=src, eth_dst=dst)
        if ip:
            match_fields.update(eth_type=0x0800, ipv4_src=ip.src, ipv4_dst=ip.dst)
            udp_hdr = pkt.get_protocol(udp.udp)
            if udp_hdr:
                match_fields.update(ip_proto=17, udp_src=udp_hdr.src_port, udp_dst=udp_hdr.dst_port)
        match = parser.OFPMatch(**match_fields)
        self.add_flow(dp, 10, match, actions)

        # encaminha o pacote atual
        out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions,
                                  data=None if msg.buffer_id != ofp.OFP_NO_BUFFER else msg.data)
        dp.send_msg(out)
