#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ryu controller:
- OpenFlow 1.3
- Learning switch básico (MAC -> port)
- Regras de classe:
    * UDP/14550 (MAVLink C2) ou DSCP EF(46) -> set_queue:0
    * Demais -> set_queue:1
- Instala flows bidirecionais com timeouts modestos
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, udp

C2_UDP_PORT = 14550
DSCP_EF = 46

class UcvController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(UcvController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        # Tabela miss -> enviar ao controller
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

        # Learning: decide out_port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofp.OFPP_FLOOD

        actions = []
        # Classificação: C2 (UDP/14550) ou DSCP EF -> queue 0; senão queue 1
        ip = pkt.get_protocol(ipv4.ipv4)
        if ip:
            # DSCP está em ip.tos (6 bits mais significativos)
            ip_dscp = (ip.tos >> 2) & 0x3F
            udp_hdr = pkt.get_protocol(udp.udp)
            is_c2 = udp_hdr and (udp_hdr.src_port == C2_UDP_PORT or udp_hdr.dst_port == C2_UDP_PORT)
            if is_c2 or ip_dscp == DSCP_EF:
                actions.append(parser.OFPActionSetQueue(0))
            else:
                actions.append(parser.OFPActionSetQueue(1))

        actions.append(parser.OFPActionOutput(out_port))

        # Instala fluxo direto (e inverso quando possível) para reduzir PacketIns
        match_fields = dict(in_port=in_port, eth_src=src, eth_dst=dst)
        # Refina match se IP/UDP presente:
        if ip:
            match_fields.update(eth_type=0x0800, ipv4_src=ip.src, ipv4_dst=ip.dst)
            udp_hdr = pkt.get_protocol(udp.udp)
            if udp_hdr:
                match_fields.update(ip_proto=17, udp_src=udp_hdr.src_port, udp_dst=udp_hdr.dst_port)
        match = parser.OFPMatch(**match_fields)
        self.add_flow(dp, 10, match, actions)

        # Envia o pacote atual
        out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=None if msg.buffer_id != ofp.OFP_NO_BUFFER else msg.data)
        dp.send_msg(out)
