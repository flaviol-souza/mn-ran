#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import yaml
import time
import json
import math
import queue
import shlex
import signal
import logging
import subprocess
from collections import deque

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub


# --------- Utilidades simples ---------

def _pct(p, total):
    if total <= 0:
        return 0.0
    return 100.0 * p / total

def pctl(vals, q=0.95):
    """percentil simples (q ∈ (0,1)) sem numpy."""
    n = len(vals)
    if n == 0:
        return 0.0
    s = sorted(vals)
    # método nearest-rank
    k = max(1, int(math.ceil(q * n)))
    return float(s[k - 1])

def run_cmd(cmd):
    """Executa comando e retorna (rc, stdout, stderr)."""
    proc = subprocess.Popen(
        cmd, shell=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True
    )
    out, err = proc.communicate()
    return proc.returncode, out.strip(), err.strip()

def has_netem(intf):
    """Detecta se há qdisc netem ativo naquela interface."""
    rc, out, _ = run_cmd(f"tc qdisc show dev {shlex.quote(intf)}")
    return (rc == 0) and (" netem " in out or out.strip().startswith("qdisc netem"))

def ovs_port_queues(intf):
    """
    Retorna (q0_uuid, q1_uuid) das filas configuradas no Port intf.
    Requer que 'ucv.py' já tenha criado QoS/Queue (linux-htb) nas portas.
    """
    # Descobrir o QoS UUID associado à porta
    rc, out, err = run_cmd(f"ovs-vsctl get Port {shlex.quote(intf)} qos")
    if rc != 0 or out in ("[]", ""):
        return (None, None)

    qos_uuid = out.replace(" ", "").strip()
    # Ex.: out = 6a4e... (um UUID) ou [_uuid] — ambos aceitos pelo 'get'
    # Listar o objeto QoS e extrair o mapeamento queues:{0=uuid0,1=uuid1}
    rc, out2, _ = run_cmd(f"ovs-vsctl list QoS {qos_uuid}")
    if rc != 0:
        return (None, None)

    # Procurar linha 'queues              : {0=UUID0, 1=UUID1}'
    q0 = q1 = None
    for line in out2.splitlines():
        if line.strip().startswith("queues"):
            # capturar pares 0=..., 1=...
            for tok in line.split("{")[-1].split("}")[0].split(","):
                tok = tok.strip()
                if not tok:
                    continue
                if tok.startswith("0="):
                    q0 = tok.split("=", 1)[1]
                elif tok.startswith("1="):
                    q1 = tok.split("=", 1)[1]
    return (q0, q1)

def set_queue_rates(queue_uuid, min_rate, max_rate):
    """Ajusta min/max (bits/s) da Queue UUID."""
    if not queue_uuid:
        return False
    min_rate = int(max(0, min_rate))
    max_rate = int(max(0, max_rate))
    rc, _, err = run_cmd(
        f"ovs-vsctl set Queue {queue_uuid} "
        f"other-config:min-rate={min_rate} other-config:max-rate={max_rate}"
    )
    return rc == 0


# --------- Controlador Ryu ---------

class UcvController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(UcvController, self).__init__(*args, **kwargs)

        # ---- Carrega policy.yaml ----
        policy_file = os.environ.get("UCV_POLICY", "policy.yaml")
        with open(policy_file, "r") as f:
            self.policy = yaml.safe_load(f) or {}

        # Interfaces onde aplicar QoS/filas (devem ter QoS criado pelo ucv.py)
        self.interfaces = self.policy.get("interfaces", ["s1-eth2", "s1-eth3"])
        self.intf_to_portno = {}
        self._flows_installed = False
        self._policy_stop = False

        # Perfiles de QoS (HTB) por estado
        self.qos_profiles = self.policy.get("qos_profiles", {
            "baseline": {"q0_min": 2_000_000, "q0_max": 5_000_000,
                         "q1_min":   500_000, "q1_max": 98_000_000},
            "degraded": {"q0_min": 4_000_000, "q0_max": 8_000_000,
                         "q1_min":   200_000, "q1_max":  5_000_000}
        })

        self.detection_mode = self.policy.get("detection_mode", "kpi").lower()
        self.poll_seconds   = int(self.policy.get("poll_seconds", 2))

        # KPI (tempo real) config
        kpi_blk = self.policy.get("kpi", {})
        ent = kpi_blk.get("enter", {})
        exi = kpi_blk.get("exit", {})

        self.kpi_if        = self.policy.get("iface_c2", self.interfaces[0] if self.interfaces else "s1-eth1")
        self.kpi_window_ms = int(self.policy.get("windows_ms", 5000))

        # taxa esperada de MAVLink (Hz)
        self.c2_rate_hz    = float(self.policy.get("c2_expected_rate_hz", 50.0))

        # NOVO: IPs para filtro unidirecional UAV->HOST
        self.c2_src_ip     = self.policy.get("c2_src_ip", None)  # UAV
        self.c2_dst_ip     = self.policy.get("c2_dst_ip", None)  # HOST/QGC

        self.kpi_degrade_jit  = float(ent.get("jitter_p95_ms", 30.0))
        self.kpi_degrade_loss = float(ent.get("loss_p95_pct", 1.0))
        self.kpi_degrade_bps  = float(ent.get("bitrate_floor_mbps", 0.0))  # Mbps (0 = ignorar)
        self.kpi_hold_s       = float(ent.get("min_degraded_time_s", 0.0))

        self.kpi_recover_jit  = float(exi.get("jitter_p95_ms", 20.0))
        self.kpi_recover_loss = float(exi.get("loss_p95_pct", 0.5))
        self.kpi_recover_bps  = float(exi.get("bitrate_floor_mbps", 0.0))  # Mbps (0 = ignorar)
        self.kpi_cooldown_s   = float(exi.get("cooldown_s", 10.0))

        # buffers / métricas atuais
        self._kpi_timestamps = deque()
        self._kpi_lock = hub.Semaphore(1)
        self._kpi_jitter_p95_ms = 0.0
        self._kpi_loss_pct = 0.0
        self._kpi_bitrate_mbps = 0.0  # NOVO
        self._kpi_count = 0


        # Threads
        self._kpi_thr = None
        if self.detection_mode == "kpi":
            self._kpi_thr = hub.spawn(self._kpi_collector)

        self._policy_thr = hub.spawn(self._policy_loop)

    # ---------- OpenFlow setup ----------

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Instala fluxos proativos com SAÍDA EXPLÍCITA por porta.
        - Mantém ARP/ICMP em NORMAL
        - UDP/14550 (C2) -> fila 0 com Output(port_no)
        - UDP/5600 (Vídeo) -> fila 1 com Output(port_no)
        Portas são resolvidas via PortDesc (sem ovs-vsctl).
        """
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        # table-miss -> controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, match, actions)

        # ARP -> NORMAL (prio 50)
        match = parser.OFPMatch(eth_type=0x0806)
        actions = [parser.OFPActionOutput(ofp.OFPP_NORMAL)]
        self.add_flow(dp, 50, match, actions, idle=0, hard=0)

        # ICMP -> NORMAL (prio 40)
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=1)
        actions = [parser.OFPActionOutput(ofp.OFPP_NORMAL)]
        self.add_flow(dp, 40, match, actions, idle=0, hard=0)

        # Solicita descrição de portas para mapear nome->port_no
        req = parser.OFPPortDescStatsRequest(dp, 0)
        dp.send_msg(req)
        self.logger.info("[flows] requisitado PortDesc para mapear ofports...")

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_reply_handler(self, ev):
        """Recebe PortDesc e instala fluxos com saída explícita por porta."""
        dp = ev.msg.datapath
        mp = {}
        for p in ev.msg.body:
            name = p.name if isinstance(p.name, str) else getattr(p, 'name', b'')
            if not isinstance(name, str):
                try:
                    name = name.decode('utf-8', 'ignore')
                except Exception:
                    name = str(name)
            mp[name] = p.port_no
        self.intf_to_portno = mp
        pretty = {k: v for k, v in sorted(mp.items()) if k.startswith('s1-eth')}
        self.logger.info("[flows] PortDesc recebido (nome->port_no): %s", pretty)
        self._install_queued_flows(dp)

    def _install_queued_flows(self, dp):
        """Instala fluxos com set_queue + Output(port_no) para C2 e Vídeo."""
        if self._flows_installed:
            return
        parser = dp.ofproto_parser

        def portno(name): return self.intf_to_portno.get(name)

        ints = self.interfaces
        pairs = []
        if len(ints) >= 2:
            pairs.append(('c2', ints[0], ints[1], 14550, 0))  # fila 0
        if len(ints) >= 4:
            pairs.append(('vid', ints[2], ints[3], 5600, 1))  # fila 1

        for typ, a, b, udp_port, qid in pairs:
            pA, pB = portno(a), portno(b)
            if pA is None or pB is None:
                self.logger.warning("[flows] par %s incompleto (%s=%s, %s=%s)", typ, a, pA, b, pB)
                continue
            prio = 60 if typ == 'c2' else 55

            # A->B
            match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, udp_dst=udp_port, in_port=pA)
            actions = [parser.OFPActionSetQueue(qid), parser.OFPActionOutput(pB)]
            self.add_flow(dp, prio, match, actions, idle=0, hard=0)

            match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, udp_src=udp_port, in_port=pA)
            actions = [parser.OFPActionSetQueue(qid), parser.OFPActionOutput(pB)]
            self.add_flow(dp, prio, match, actions, idle=0, hard=0)

            # B->A
            match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, udp_dst=udp_port, in_port=pB)
            actions = [parser.OFPActionSetQueue(qid), parser.OFPActionOutput(pA)]
            self.add_flow(dp, prio, match, actions, idle=0, hard=0)

            match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, udp_src=udp_port, in_port=pB)
            actions = [parser.OFPActionSetQueue(qid), parser.OFPActionOutput(pA)]
            self.add_flow(dp, prio, match, actions, idle=0, hard=0)

            self.logger.info("[flows] %s(%d) fila=%d entre %s<->%s (%d<->%d)",
                            "C2" if typ == 'c2' else "Vídeo", udp_port, qid, a, b, pA, pB)

        self._flows_installed = True


    def add_flow(self, datapath, priority, match, actions, idle=0, hard=0):
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath,
                                priority=priority,
                                match=match,
                                instructions=inst,
                                idle_timeout=idle,
                                hard_timeout=hard)
        datapath.send_msg(mod)

    # ---------- KPI collector (tempo real) ----------

    def _kpi_collector(self):
        """
        Coleta timestamps e tamanhos de pacotes MAVLink (UDP/14550) **unidirecionais**
        usando tshark no lado do HOST (iface_c2). Calcula:
        - jitter_p95_ms: p95 dos inter-arrivals (ms)
        - loss_p95_pct:  perda estimada vs taxa esperada (self.c2_rate_hz)
        - bitrate_mbps:  throughput na janela
        """
        import shutil
        iface = self.kpi_if
        window_ms = max(500, self.kpi_window_ms)
        window_s = window_ms / 1000.0

        # Filtro BPF **direcional** (UAV -> HOST)
        bpf = "udp port 14550"
        if self.c2_src_ip:
            bpf = f"udp dst port 14550 and src host {self.c2_src_ip}"
            if self.c2_dst_ip:
                bpf += f" and dst host {self.c2_dst_ip}"

        # tshark disponível?
        if shutil.which("tshark") is None:
            self.logger.error("[kpi] tshark não encontrado; alterando detection_mode='netem'")
            self.detection_mode = "netem"
            return

        cmd = (
            f"tshark -l -i {shlex.quote(iface)} -f \"{bpf}\" "
            f"-T fields -e frame.time_epoch -e frame.len"
        )
        self.logger.info("[kpi] starting tshark on iface=%s bpf='%s'", iface, bpf)

        try:
            proc = subprocess.Popen(
                cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
        except Exception as e:
            self.logger.exception("[kpi] could not start tshark: %s; fallback to detection_mode='netem'", e)
            self.detection_mode = "netem"
            return

        # Buffers da janela deslizante
        times = deque()
        sizes = deque()
        last_stats_ts = 0.0

        try:
            while True:
                line = proc.stdout.readline()
                if not line:
                    err = proc.stderr.read() if proc.stderr else ""
                    if err:
                        self.logger.error("[kpi] tshark encerrado: %s", err.strip())
                    break

                parts = line.strip().split()
                if not parts:
                    continue

                # timestamp
                try:
                    ts = float(parts[0])
                except ValueError:
                    continue

                # tamanho do frame (bytes)
                size = 0
                if len(parts) >= 2:
                    try:
                        size = int(parts[1])
                    except ValueError:
                        size = 0

                # adiciona amostra
                times.append(ts)
                sizes.append(size)

                # mantém apenas a janela
                cutoff = ts - window_s
                while times and times[0] < cutoff:
                    times.popleft()
                    sizes.popleft()

                # atualiza ~10 Hz
                now = ts
                if (now - last_stats_ts) >= 0.1:
                    last_stats_ts = now
                    n = len(times)

                    # jitter p95 (ms) sobre inter-arrivals
                    if n >= 3:
                        diffs = [ (times[i] - times[i-1]) * 1000.0 for i in range(1, n) ]
                        diffs.sort()
                        k = (len(diffs) - 1) * 0.95
                        f = math.floor(k); c = math.ceil(k)
                        if f == c:
                            jitter_p95 = diffs[int(k)]
                        else:
                            jitter_p95 = diffs[f] + (diffs[c] - diffs[f]) * (k - f)
                    else:
                        jitter_p95 = 0.0

                    # perda estimada (%) vs taxa esperada
                    expected = max(1.0, self.c2_rate_hz * window_s)
                    loss_pct = max(0.0, min(100.0, (1.0 - (n / expected)) * 100.0))

                    # bitrate (Mbps) na janela
                    total_bytes = sum(sizes)
                    bitrate_mbps = (total_bytes * 8.0) / (window_s * 1e6)

                    with self._kpi_lock:
                        self._kpi_count = n
                        self._kpi_jitter_p95_ms = float(jitter_p95)
                        self._kpi_loss_pct = float(loss_pct)
                        self._kpi_bitrate_mbps = float(bitrate_mbps)

        except Exception as e:
            self.logger.exception("[kpi] collector error: %s", e)
        finally:
            try:
                proc.terminate()
            except Exception:
                pass


    def _read_kpi_snapshot(self):
        """Copia métricas atuais sob lock."""
        with self._kpi_lock:
            return (self._kpi_count, self._kpi_jitter_p95_ms, self._kpi_loss_pct, self._kpi_bitrate_mbps)


    # ---------- Policy loop ----------

    def _policy_loop(self):
        """
        Aplica perfis de QoS (baseline/degraded) conforme modo de detecção:
          - 'netem'  : se qualquer porta de 'interfaces' tiver qdisc netem -> degraded
          - 'kpi'    : thresholds de histerese em jitter p95 e perda (%)
        Só aplica quando encontrar filas 0/1 em TODAS as portas listadas.
        """
        self._last_state = None
        self._last_change_ts = 0.0

        while not self._policy_stop:
            try:
                # Verifica se filas existem em todas as portas
                ready = True
                qmap = {}
                for itf in self.interfaces:
                    q0, q1 = ovs_port_queues(itf)
                    if not q0 or not q1:
                        ready = False
                        break
                    qmap[itf] = (q0, q1)

                if not ready:
                    self.logger.debug("[policy] queues not found in all interfaces; waiting...")
                    hub.sleep(self.poll_seconds)
                    continue

                # Detecta estado
                state = "baseline"
                if self.detection_mode == "netem":
                    if any(has_netem(itf) for itf in self.interfaces):
                        state = "degraded"

                elif self.detection_mode == "kpi":
                    n, jit, loss, br = self._read_kpi_snapshot()
                    now = time.time()

                    def _degrade_condition():
                        cond_jl = (jit > self.kpi_degrade_jit) or (loss > self.kpi_degrade_loss)
                        cond_br = (self.kpi_degrade_bps > 0.0) and (br < self.kpi_degrade_bps)
                        return cond_jl or cond_br

                    def _recover_condition():
                        cond_jl = (jit < self.kpi_recover_jit) and (loss < self.kpi_recover_loss)
                        cond_br = (self.kpi_recover_bps <= 0.0) or (br >= self.kpi_recover_bps)
                        return cond_jl and cond_br

                    # Histerese
                    if self._last_state in (None, "baseline"):
                        if _degrade_condition():
                            if self._last_change_ts == 0.0:
                                self._last_change_ts = now
                            elif (now - self._last_change_ts) >= self.kpi_hold_s:
                                state = "degraded"
                                self._last_change_ts = now
                        else:
                            self._last_change_ts = 0.0
                    else:  # degraded
                        if _recover_condition():
                            if (now - self._last_change_ts) >= self.kpi_cooldown_s:
                                state = "baseline"
                                self._last_change_ts = now
                        else:
                            # ainda degradado; reinicia cooldown
                            self._last_change_ts = now

                # Aplica apenas em mudança de estado
                if state != self._last_state:
                    prof = self.qos_profiles.get(state, {})
                    self.logger.info("[policy] Applying QoS profile '%s': %s", state, prof)
                    for itf, (q0, q1) in qmap.items():
                        set_queue_rates(q0, prof.get("q0_min", 0), prof.get("q0_max", 0))
                        set_queue_rates(q1, prof.get("q1_min", 0), prof.get("q1_max", 0))
                    self._last_state = state

            except Exception as e:
                self.logger.exception("[policy] loop error: %s", e)

            hub.sleep(self.poll_seconds)

    # ---------- Encerramento ----------

    def close(self):
        self._policy_stop = True
        hub.sleep(0.1)

        # ---------- Helpers de portas ----------
    def _get_ofport(self, ifname: str):
        """Resolve o ofport de uma Interface OVS pelo nome (ex.: s1-eth2 -> 2)."""
        rc, out, err = run_cmd(f"ovs-vsctl get Interface {shlex.quote(ifname)} ofport")
        if rc != 0:
            self.logger.error("[ports] falha ao obter ofport de %s: %s", ifname, err)
            return None
        try:
            return int(out)
        except Exception:
            self.logger.error("[ports] valor inválido de ofport para %s: %s", ifname, out)
            return None

    def _resolve_pairs(self):
        """
        Mapeia os pares (C2, Vídeo) a partir de self.interfaces.
        Espera: [c2_a, c2_b, vid_a, vid_b].
        Retorna dict com números de porta (ou None se não houver).
        """
        iflen = len(self.interfaces)
        c2_a = self.interfaces[0] if iflen >= 2 else None
        c2_b = self.interfaces[1] if iflen >= 2 else None
        vid_a = self.interfaces[2] if iflen >= 4 else None
        vid_b = self.interfaces[3] if iflen >= 4 else None

        pairs = {}
        if c2_a and c2_b:
            pairs["c2_a"] = (c2_a, self._get_ofport(c2_a))
            pairs["c2_b"] = (c2_b, self._get_ofport(c2_b))
        if vid_a and vid_b:
            pairs["vid_a"] = (vid_a, self._get_ofport(vid_a))
            pairs["vid_b"] = (vid_b, self._get_ofport(vid_b))
        return pairs
