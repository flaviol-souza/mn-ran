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

        self.kpi_if          = self.policy.get("iface_c2", "root-eth0")
        self.kpi_window_ms   = int(self.policy.get("windows_ms", 5000))
        self.c2_rate_hz      = float(self.policy.get("c2_expected_rate_hz", 50.0))

        self.kpi_degrade_jit = float(ent.get("jitter_p95_ms", 30.0))
        self.kpi_degrade_loss= float(ent.get("loss_p95_pct", 1.0))
        self.kpi_hold_s      = float(ent.get("min_degraded_time_s", 2.0))

        self.kpi_recover_jit = float(exi.get("jitter_p95_ms", 20.0))
        self.kpi_recover_loss= float(exi.get("loss_p95_pct", 0.5))
        self.kpi_cooldown_s  = float(exi.get("cooldown_s", 10.0))

        self.logger.info("Policy loaded: %s", json.dumps(self.policy, indent=2))

        # Estado do policy loop
        self._policy_stop = False
        self._last_state = None
        self._last_change_ts = 0.0

        # KPI buffers (tempo real)
        self._kpi_timestamps = deque()     # segundos (float)
        self._kpi_lock = hub.Semaphore(1)
        self._kpi_jitter_p95_ms = 0.0
        self._kpi_loss_pct = 0.0
        self._kpi_count = 0

        # Threads
        self._kpi_thr = None
        if self.detection_mode == "kpi":
            self._kpi_thr = hub.spawn(self._kpi_collector)

        self._policy_thr = hub.spawn(self._policy_loop)

    # ---------- OpenFlow setup ----------

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Instala fluxos proativos (C2/14550 → fila 0, Vídeo/5600 → fila 1)."""
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

        # UDP/14550 (C2) → fila 0 (ambos sentidos), prio 60
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, udp_dst=14550)
        actions = [parser.OFPActionSetQueue(0), parser.OFPActionOutput(ofp.OFPP_NORMAL)]
        self.add_flow(dp, 60, match, actions, idle=0, hard=0)

        match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, udp_src=14550)
        actions = [parser.OFPActionSetQueue(0), parser.OFPActionOutput(ofp.OFPP_NORMAL)]
        self.add_flow(dp, 60, match, actions, idle=0, hard=0)

        # UDP/5600 (Vídeo) → fila 1 (ambos sentidos), prio 55
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, udp_dst=5600)
        actions = [parser.OFPActionSetQueue(1), parser.OFPActionOutput(ofp.OFPP_NORMAL)]
        self.add_flow(dp, 55, match, actions, idle=0, hard=0)

        match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, udp_src=5600)
        actions = [parser.OFPActionSetQueue(1), parser.OFPActionOutput(ofp.OFPP_NORMAL)]
        self.add_flow(dp, 55, match, actions, idle=0, hard=0)

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
        Coleta timestamps de pacotes UDP/14550 na iface_c2 via tshark (não precisa dissector MAVLink),
        calcula jitter p95 (inter-arrival) e perda estimada vs taxa esperada (c2_rate_hz).
        """
        iface = self.kpi_if
        window_ms = max(500, self.kpi_window_ms)
        window_s = window_ms / 1000.0

        # tenta rodar tshark sem sudo (dumpcap costuma ter setcap)
        cmd = (
            f"tshark -l -i {shlex.quote(iface)} -f 'udp port 14550' "
            f"-T fields -e frame.time_epoch"
        )
        self.logger.info("[kpi] starting tshark on iface=%s", iface)
        try:
            proc = subprocess.Popen(
                cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
        except Exception as e:
            self.logger.exception("[kpi] could not start tshark: %s", e)
            return

        last_stats_ts = 0.0
        try:
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    ts = float(line)
                except:
                    continue

                # janela deslizante
                with self._kpi_lock:
                    self._kpi_timestamps.append(ts)
                    cutoff = ts - window_s
                    while self._kpi_timestamps and self._kpi_timestamps[0] < cutoff:
                        self._kpi_timestamps.popleft()

                    n = len(self._kpi_timestamps)
                    self._kpi_count = n

                    # inter-arrival (ms)
                    if n >= 2:
                        diffs = []
                        prev = None
                        for t in self._kpi_timestamps:
                            if prev is not None:
                                diffs.append((t - prev) * 1000.0)
                            prev = t
                        self._kpi_jitter_p95_ms = pctl(diffs, 0.95)
                    else:
                        self._kpi_jitter_p95_ms = 0.0

                    # perda estimada vs taxa esperada
                    expected = max(1.0, self.c2_rate_hz * window_s)
                    self._kpi_loss_pct = max(0.0, _pct(expected - n, expected))

                # log leve a cada ~5s
                now = time.time()
                if now - last_stats_ts > 5.0:
                    last_stats_ts = now
                    self.logger.debug(
                        "[kpi] win=%.1fs n=%d jitter_p95=%.1fms loss=%.2f%%",
                        window_s, self._kpi_count, self._kpi_jitter_p95_ms, self._kpi_loss_pct
                    )
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
            return (self._kpi_count, self._kpi_jitter_p95_ms, self._kpi_loss_pct)

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
                    n, jit, loss = self._read_kpi_snapshot()
                    now = time.time()
                    # Histerese: degrade se (jit > enter.jit) OU (loss > enter.loss) por hold;
                    # recupera se (jit < exit.jit) E (loss < exit.loss) por cooldown.
                    if self._last_state in (None, "baseline"):
                        if (jit > self.kpi_degrade_jit) or (loss > self.kpi_degrade_loss):
                            # Iniciar/checar temporização de hold
                            if self._last_state != "degraded":
                                if self._last_change_ts == 0.0:
                                    self._last_change_ts = now
                                elif (now - self._last_change_ts) >= self.kpi_hold_s:
                                    state = "degraded"
                                    self._last_change_ts = now
                            else:
                                state = "degraded"
                        else:
                            self._last_change_ts = 0.0
                    else:  # estado atual degraded
                        if (jit < self.kpi_recover_jit) and (loss < self.kpi_recover_loss):
                            if (now - self._last_change_ts) >= self.kpi_cooldown_s:
                                state = "baseline"
                                self._last_change_ts = now
                            else:
                                state = "degraded"
                        else:
                            # ainda degradado; reinicia cooldown
                            self._last_change_ts = now
                            state = "degraded"

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
