#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, re, yaml, time, json, math, queue, shlex, signal, logging, subprocess, glob
from collections import deque

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub

# --------- Utilidades simples ---------
def _resolve_out(run_dir, path, default_name):
    if not path:
        return os.path.join(run_dir, default_name)
    # se for diretório, gravo com nome padrão dentro dele
    if os.path.isdir(path):
        return os.path.join(path, default_name)
    # se for relativo, junto com run_dir
    if not os.path.isabs(path):
        return os.path.join(run_dir, path)
    return path

def _iface_exists(name: str) -> bool:
    return os.path.isdir(f"/sys/class/net/{name}")

def _ensure_dir(d: str):
    os.makedirs(d, exist_ok=True)

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

def _init_run_dir(policy):
    rd = policy.get("run_dir")
    if rd:
        os.makedirs(rd, exist_ok=True)
        return rd
    ts = time.strftime("%Y%m%d-%H%M%S")
    rd =+ "/" + ts + "/"
    os.makedirs(rd, exist_ok=True)
    return rd

def _append_jsonl(path, rec: dict):
    try:
        with open(path, "a") as fp:
            fp.write(json.dumps(rec) + "\n")
    except Exception:
        pass

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
        self.run_dir = _init_run_dir(self.policy)

        kpi_blk = self.policy.get("kpi", {})
        ent = kpi_blk.get("enter", {})
        exi = kpi_blk.get("exit", {})

        # Interfaces onde aplicar QoS/filas (devem ter QoS criado pelo ucv.py)
        self.interfaces = self.policy.get("interfaces", ["s1-eth1", "s1-eth2", "s1-eth3", "s1-eth4"])
        self.intf_to_portno = {}
        self._flows_installed = False
        self._policy_stop = False
        self._last_state = None        # último perfil aplicado: "baseline" ou "degraded"
        self._last_change_ts = 0.0     # timestamp da última troca (para hold/cooldown)

        self.kpi_export = _resolve_out(self.run_dir,
                               kpi_blk.get("export_jsonl_path", ""),
                               "controller_c2_kpi.jsonl")

        self.video_export = _resolve_out(self.run_dir,
                                        self.policy.get("video_export_jsonl_path", ""),
                                        "controller_video_kpi.jsonl")
        
        # Perfiles de QoS (HTB) por estado
        self.qos_profiles = self.policy.get("qos_profiles", {
            "baseline": {"q0_min": 2_000_000, "q0_max": 5_000_000,
                         "q1_min":   500_000, "q1_max": 98_000_000},
            "degraded": {"q0_min": 4_000_000, "q0_max": 8_000_000,
                         "q1_min":   200_000, "q1_max":  5_000_000}
        })

        self.qos_init_profile = self.policy.get("qos_init_profile", "baseline")
        self.detection_mode = self.policy.get("detection_mode", "kpi").lower()
        self.poll_seconds   = int(self.policy.get("poll_seconds", 2))

        self.video_if      = self.policy.get("iface_video", "s1-eth3")
        self.video_src_ip  = self.policy.get("video_src_ip", "10.1.0.2")
        self.video_dst_ip  = self.policy.get("video_dst_ip", "10.1.0.254")
        
        self.kpi_if   = self.policy.get("iface_c2", "s1-eth1")
        self.kpi_window_ms = int(self.policy.get("window_ms", 5000))

        # taxa esperada de MAVLink (Hz)
        self.c2_rate_hz    = float(self.policy.get("c2_expected_rate_hz", 50.0))
        self._kpi_continuity_up_pct = 100.0
        self._vid_lock = hub.Semaphore(1)
        self._vid_bitrate_mbps = 0.0

        self.kpi_degrade_jit  = float(ent.get("jitter_p95_ms", 30.0))
        self.kpi_degrade_loss = float(ent.get("loss_p95_pct", 1.0))
        self.kpi_degrade_bps  = float(ent.get("bitrate_floor_mbps", 0.0))  # Mbps (0 = ignorar)
        self.kpi_hold_s       = float(ent.get("min_degraded_time_s", 0.0))

        self.kpi_recover_jit  = float(exi.get("jitter_p95_ms", 20.0))
        self.kpi_recover_loss = float(exi.get("loss_p95_pct", 0.5))
        self.kpi_recover_bps  = float(exi.get("bitrate_floor_mbps", 0.0))  # Mbps (0 = ignorar)
        self.kpi_cooldown_s   = float(exi.get("cooldown_s", 10.0))

         # IPs para filtro unidirecional UAV->HOST
        self.c2_src_ip     = self.policy.get("c2_src_ip", None)  # UAV
        self.c2_dst_ip     = self.policy.get("c2_dst_ip", None)  # HOST/QGC   

        # período do C2 em ms
        T_ms = 1000.0 / max(1e-6, self.c2_rate_hz)

        # ler multiplicadores (se existirem)
        enter_mult = float(ent.get("jitter_T_mult", 0.0))
        exit_mult  = float(exi.get("jitter_T_mult", 0.0))

        # se definidos, sobrescrevem os thresholds absolutos
        if enter_mult > 0:
            self.kpi_degrade_jit = T_ms * enter_mult
        if exit_mult > 0:
            self.kpi_recover_jit = T_ms * exit_mult

        # continuidade (gap) derivada de K×T, com fallback em ms absoluto se preferir
        cont_mult = float(kpi_blk.get("continuity_gap_T_mult", 0.0))
        self.kpi_gap_ms = (T_ms * cont_mult) if cont_mult > 0 else float(kpi_blk.get("continuity_gap_ms", 500.0))

        # alvo de continuidade para decisão/relato
        self.kpi_cont_uptime_target = float(kpi_blk.get("continuity_min_uptime_pct", 0.0))

        # PCAP: ativar/desativar
        self.enable_pcap = bool(self.policy.get("pcap_enable", True))
        self._pcap_procs = []
        self._pcap_started = False

        # buffers / métricas atuais
        self._kpi_timestamps = deque()
        self._kpi_lock = hub.Semaphore(1)
        self._kpi_jitter_p95_ms = 0.0
        self._kpi_loss_pct = 0.0
        self._kpi_bitrate_mbps = 0.0
        self._kpi_count = 0

        self.logger.info( 
            "[kpi] T=%.1f ms | jitter_enter=%.1f ms | jitter_exit=%.1f ms | gap=%.1f ms | loss_enter=%.2f%% | loss_exit=%.2f%% | br_floor_enter=%.2f Mb/s | br_floor_exit=%.2f Mb/s",
            T_ms, self.kpi_degrade_jit, self.kpi_recover_jit, self.kpi_gap_ms, self.kpi_degrade_loss, self.kpi_recover_loss, self.kpi_degrade_bps, self.kpi_recover_bps
        )

        # Threads
        self._kpi_thr = None
        if self.detection_mode == "kpi":
            self._kpi_thr = hub.spawn(self._kpi_collector)

        self._policy_thr = hub.spawn(self._policy_loop)
        self._vid_thr  = hub.spawn(self._video_collector)
        self._qos_thr  = hub.spawn(self._qos_sampler)

    # ---------- OpenFlow setup ----------
    @set_ev_cls(ofp_event.EventOFPStateChange, [DEAD_DISPATCHER])
    def _switch_down(self, ev):
        # Switch caiu? pare os pcaps para evitar “adapter no longer attached”
        self._stop_pcaps()
        
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
        self._start_pcaps_if_needed()

    def _spawn_pcap(self, iface: str, bpf: str, outfile: str):
        # garante caminho absoluto
        outfile = os.path.abspath(outfile)
        outdir = os.path.dirname(outfile)
        _ensure_dir(outdir)

        if not _iface_exists(iface):
            self.logger.warning("[pcap] iface %s ainda não existe; adiando", iface)
            return False

        # dumpcap ring; -q = quiet (não afeta escrita), -b = ring (50 MB, 4 arquivos)
        cmd = (
            f'dumpcap -q -i {shlex.quote(iface)} -f "{bpf}" '
            f'-w {shlex.quote(outfile)} -b filesize:50000 -b files:4'
        )
        self.logger.info("[pcap] launching: %s", cmd)

        # log de erro do dumpcap vai para um arquivo ao lado do pcap
        errlog = outfile + ".stderr.log"
        try:
            with open(errlog, "ab", buffering=0) as errfp:
                p = subprocess.Popen(
                    cmd, shell=True,
                    stdout=subprocess.DEVNULL, stderr=errfp, preexec_fn=os.setsid
                )
        except Exception as e:
            self.logger.error("[pcap] falhou ao iniciar (%s): %s", iface, e)
            return False

        # watchdog rápido: em até 2s o proc não pode ter morrido
        # e o dumpcap costuma criar o primeiro arquivo do ring imediatamente.
        hub.sleep(0.5)
        if p.poll() is not None:
            self.logger.error("[pcap] processo encerrou cedo (rc=%s). Veja %s", p.returncode, errlog)
            return False

        # Nomeação do ring: dumpcap cria arquivos com sufixo numérico:
        #   <base>_00001_YYYY...pcapng
        # então validamos por prefixo "<outfile>_00001".
        base_prefix = outfile + "_00001"
        found = glob.glob(base_prefix + "*.pcapng")
        if not found:
            # ainda pode estar criando — espera mais um pouco
            hub.sleep(1.5)
            found = glob.glob(base_prefix + "*.pcapng")
        if not found:
            self.logger.warning("[pcap] não encontrei arquivo do ring ainda (prefixo=%s); seguirei assim mesmo", base_prefix)

        self._pcap_procs.append(p)
        self.logger.info("[pcap] %s -> %s (ring ativo)", iface, outfile)
        return True


    def _start_pcaps_if_needed(self):
        if not self.enable_pcap or self._pcap_started:
            return

        bpf_c2 = (f"udp dst port 14550 and src host {self.c2_src_ip} and dst host {self.c2_dst_ip}"
                if (self.c2_src_ip and self.c2_dst_ip) else "udp port 14550")
        bpf_vid = (f"udp dst port 5600 and src host {self.video_src_ip} and dst host {self.video_dst_ip}"
                if (self.video_src_ip and self.video_dst_ip) else "udp port 5600")

        ok1 = self._spawn_pcap(self.kpi_if, bpf_c2,  os.path.join(self.run_dir, "c2.pcapng"))
        ok2 = self._spawn_pcap(self.video_if, bpf_vid, os.path.join(self.run_dir, "video.pcapng"))
        self._pcap_started = bool(ok1 and ok2)

    def _stop_pcaps(self):
        for p in self._pcap_procs:
            try:
                p.terminate()
            except Exception as e:
                self.logger.exception("[pcap] erro ao encerrar: %s", e)
                pass
        self._pcap_procs = []
        self._pcap_started = False
        self.logger.info("[pcap] encerrados")


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
                if (now - last_stats_ts) >= 0.2:
                    last_stats_ts = now
                    n = len(times)

                    # jitter p95 (ms) sobre inter-arrivals
                    if n >= 3:
                        diffs = [ (times[i] - times[i-1]) * 1000.0 for i in range(1, n) ]
                        diffs.sort()
                        outage_time_s = sum(d/1000.0 for d in diffs if d >= self.kpi_gap_ms)
                        continuity_uptime_pct = max(0.0, 100.0 * (window_s - outage_time_s) / window_s)
                        k = (len(diffs) - 1) * 0.95
                        f = math.floor(k); c = math.ceil(k)
                        if f == c:
                            jitter_p95 = diffs[int(k)]
                        else:
                            jitter_p95 = diffs[f] + (diffs[c] - diffs[f]) * (k - f)
                    else:
                        jitter_p95 = 0.0
                        continuity_uptime_pct = 100.0

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
                        self._kpi_continuity_up_pct = float(continuity_uptime_pct)

                    if self.kpi_export:
                        _append_jsonl(self.kpi_export, {
                            "ts": now,
                            "n": n,
                            "jitter_p95_ms": float(jitter_p95),
                            "loss_pct": float(loss_pct),
                            "bitrate_mbps": float(bitrate_mbps),
                            "continuity_uptime_pct": float(continuity_uptime_pct)
                        })

        except Exception as e:
            self.logger.exception("[kpi] collector error: %s", e)
        finally:
            try:
                proc.terminate()
            except Exception:
                pass

    def _video_collector(self):
        """Bitrate do vídeo (UDP/5600) na janela self.kpi_window_ms."""
        import shutil
        if shutil.which("tshark") is None:
            self.logger.warning("[video] tshark ausente; sem coleta de bitrate de vídeo")
            return

        window_ms = max(500, self.kpi_window_ms)
        window_s = window_ms / 1000.0
        bpf = (f"udp dst port 5600 and src host {self.video_src_ip} and dst host {self.video_dst_ip}"
            if (self.video_src_ip and self.video_dst_ip) else "udp port 5600")
        cmd = f'tshark -l -i {shlex.quote(self.video_if)} -f "{bpf}" -T fields -e frame.time_epoch -e frame.len'
        self.logger.info("[video] starting tshark on iface=%s bpf='%s'", self.video_if, bpf)

        try:
            proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        except Exception as e:
            self.logger.warning("[video] não iniciou tshark: %s", e); return

        times, sizes = deque(), deque()
        last_emit = 0.0
        try:
            while True:
                line = proc.stdout.readline()
                if not line:
                    break
                parts = line.strip().split()
                if len(parts) < 2:
                    continue
                try:
                    ts = float(parts[0]); ln = int(parts[1])
                except Exception:
                    continue

                times.append(ts); sizes.append(ln)
                cutoff = ts - window_s
                while times and times[0] < cutoff:
                    times.popleft(); sizes.popleft()

                if ts - last_emit >= 0.2:
                    last_emit = ts
                    total_bytes = sum(sizes)
                    bitrate_mbps = (total_bytes * 8.0) / (window_s * 1e6)
                    pps = len(times) / window_s if window_s > 0 else 0.0
                    rec = {"ts": ts, "bitrate_mbps": round(bitrate_mbps, 3), "pps": round(pps, 1)}
                    _append_jsonl(self.video_export, rec)
                    with self._vid_lock:
                        self._vid_bitrate_mbps = float(bitrate_mbps)

        except Exception as e:
            self.logger.exception("[video] collector error: %s", e)
        finally:
            try: proc.terminate()
            except Exception: pass

    def _parse_qos_show(self, iface):
        rc, out, _ = run_cmd(f"ovs-appctl qos/show {shlex.quote(iface)}")
        if rc != 0 or not out.strip():
            return None

        stats = {}
        cur = None  # "q0" (Default) ou "q1" (Queue 1), etc.
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("Default:"):
                cur = "q0"
                stats.setdefault(cur, {})
            elif line.startswith("Queue "):
                qn = line.split()[1].rstrip(":")  # "1:" -> "1"
                cur = f"q{qn}"
                stats.setdefault(cur, {})
            elif cur:
                if "min-rate:" in line:
                    stats[cur]["min_rate"] = int(line.split(":")[1].strip())
                elif "max-rate:" in line:
                    stats[cur]["max_rate"] = int(line.split(":")[1].strip())
                elif "tx_packets:" in line:
                    stats[cur]["tx_packets"] = int(line.split(":")[1].strip())
                elif "tx_bytes:" in line:
                    stats[cur]["tx_bytes"] = int(line.split(":")[1].strip())

        # Preenche zeros se counters não existirem
        for k in list(stats.keys()):
            stats[k].setdefault("tx_packets", 0)
            stats[k].setdefault("tx_bytes", 0)

        return stats or None

    def _qos_sampler(self):
        last = {}
        while not self._policy_stop:
            ts = time.time()
            for itf in self.interfaces:
                st = self._parse_qos_show(itf)
                if not st:
                    # fallback tc -s
                    rc, out, _ = run_cmd(f"tc -s qdisc show dev {shlex.quote(itf)}")
                    if rc == 0 and "htb" in out:
                        _append_jsonl(os.path.join(self.run_dir, f"qos_{itf}.jsonl"), {"ts": ts, "raw": out})
                    continue
                rec = {"ts": ts, **st}
                _append_jsonl(os.path.join(self.run_dir, f"qos_{itf}.jsonl"), rec)
            hub.sleep(max(1, self.poll_seconds))

    def _read_kpi_snapshot(self):
        """Copia métricas atuais sob lock."""
        with self._kpi_lock:
            return (self._kpi_count, self._kpi_jitter_p95_ms, self._kpi_loss_pct, self._kpi_bitrate_mbps)

    def _read_video_bitrate(self):
        with self._vid_lock:
            return self._vid_bitrate_mbps

    # ---------- Policy loop ----------

    def _policy_loop(self):
        """
        Aplica perfis de QoS (baseline/degraded) conforme modo de detecção:
          - 'netem'  : se qualquer porta de 'interfaces' tiver qdisc netem -> degraded
          - 'kpi'    : thresholds de histerese em jitter p95 e perda (%)
        Só aplica quando encontrar filas 0/1 em TODAS as portas listadas.
        """
        self._current_profile = None
        self._last_state = None
        self._last_change_ts = 0.0
        init_state = self.qos_init_profile 

        while not self._policy_stop:
            try:
                # checa filas em todas as portas
                ready, qmap = True, {}
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

                # comece do estado anterior (não force baseline por default)
                state = self._last_state or init_state

                if self.detection_mode == "netem":
                    state = "degraded" if any(has_netem(itf) for itf in self.interfaces) else "baseline"

                elif self.detection_mode == "kpi":
                    n, jit, loss, br_c2 = self._read_kpi_snapshot()
                    vid_br = self._read_video_bitrate()
                    now = time.time()

                    def _degrade_condition():
                        cond_jl = (jit > self.kpi_degrade_jit) or (loss > self.kpi_degrade_loss)
                        cond_br = (self.kpi_degrade_bps > 0.0) and (vid_br < self.kpi_degrade_bps)
                        cond_ct = (getattr(self, "_kpi_continuity_up_pct", 100.0) < self.kpi_cont_uptime_target) if self.kpi_cont_uptime_target > 0 else False
                        return cond_jl or cond_br or cond_ct

                    def _recover_condition():
                        cond_jl = (jit < self.kpi_recover_jit) and (loss < self.kpi_recover_loss)
                        cond_br = (self.kpi_recover_bps <= 0.0) or (vid_br >= self.kpi_recover_bps)
                        cond_ct = (getattr(self, "_kpi_continuity_up_pct", 100.0) >= self.kpi_cont_uptime_target) if self.kpi_cont_uptime_target > 0 else True
                        return cond_jl and cond_br and cond_ct

                    if self._last_state in (None, "baseline"):
                        if _degrade_condition():
                            if self._last_change_ts == 0.0:
                                self._last_change_ts = now
                            elif (now - self._last_change_ts) >= self.kpi_hold_s:
                                state = "degraded"
                                self._last_change_ts = now
                        else:
                            self._last_change_ts = 0.0
                            state = "baseline"
                    else:  # estava degradado
                        if _recover_condition():
                            if (now - self._last_change_ts) >= self.kpi_cooldown_s:
                                state = "baseline"
                                self._last_change_ts = now
                        else:
                            state = "degraded"      # <— mantenha degradado
                            self._last_change_ts = now

                if state != self._last_state:
                    prof = self.qos_profiles.get(state, {})
                    self.logger.info("[policy] Applying QoS profile '%s': %s", state, prof)
                    for itf, (q0, q1) in qmap.items():
                        set_queue_rates(q0, prof.get("q0_min", 0), prof.get("q0_max", 0))
                        set_queue_rates(q1, prof.get("q1_min", 0), prof.get("q1_max", 0))

                    # trilha de mudança
                    n, jit, loss, br_c2 = self._read_kpi_snapshot()
                    vid_br = self._read_video_bitrate()
                    change = {
                        "ts": time.time(),
                        "new_state": state,
                        "profile": prof,
                        "kpi_snapshot": {
                            "n": n, "jitter_p95_ms": jit, "loss_pct": loss,
                            "bitrate_c2_mbps": br_c2, "bitrate_video_mbps": vid_br,
                            "continuity_uptime_pct": getattr(self, "_kpi_continuity_up_pct", None)
                        }
                    }
                    _append_jsonl(os.path.join(self.run_dir, "profile_changes.jsonl"), change)

                    self._last_state = state

            except Exception as e:
                self.logger.exception("[policy] loop error: %s", e)

            hub.sleep(self.poll_seconds)

    # ---------- Encerramento ----------

    def close(self):
        self._policy_stop = True
        hub.sleep(0.1)
        for p in getattr(self, "_pcap_procs", []):
            try:
                p.terminate()
            except Exception:
                pass

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
