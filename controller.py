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

import os, re, json, time, threading, subprocess
from pathlib import Path

import yaml

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, udp

C2_UDP_PORT = 14550
DSCP_EF = 46

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
        self.interfaces = self.policy.get("interfaces", ["s1-eth1", "s1-eth2"])
        self.qos_profiles = self.policy.get("qos_profiles", {})
        self.poll_seconds = int(self.policy.get("poll_seconds", 2))
        self._policy_stop = False
        self.logger.info(f"Policy loaded: {self.policy}")

        # inicia thread de política
        self.policy_thread = threading.Thread(target=self._policy_loop, daemon=True)
        self.policy_thread.start()

    def _policy_loop(self):
        """
        Periodicamente checa degradação e aplica perfil QoS (baseline/degraded)
        (Somente aplica quando todas as portas já tiverem queues 0/1 criadas)
        """
        last_state = None  # 'baseline' ou 'degraded'
        while not self._policy_stop:
            try:
                # detecta estado
                state = "baseline"
                if self.detection_mode == "netem":
                    if any(has_netem(intf) for intf in self.interfaces):
                        state = "degraded"

                # prepara mapa de filas (garante que existem antes de aplicar)
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

                # aplica só quando muda de estado
                if state != last_state:
                    prof = self.qos_profiles.get(state, {})
                    self.logger.info(f"[policy] Applying QoS profile: {state} -> {prof}")
                    for intf, (q0, q1) in qmap.items():
                        set_queue_rates(q0, prof.get("q0_min", 0), prof.get("q0_max", 0))
                        set_queue_rates(q1, prof.get("q1_min", 0), prof.get("q1_max", 0))
                    last_state = state

            except Exception as e:
                self.logger.exception(f"[policy] loop error: {e}")
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
