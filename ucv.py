#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UCV Mininet Experiment:
- Topologia mínima: GCS <-> (UCV/OVS) <-> UAV
- OVS com QoS HTB: Queue 0 (C2 alta prioridade), Queue 1 (ISR/best-effort)
- Marcação DSCP no host UAV p/ C2 (EF/46) -> mapeado à fila 0
- Scheduler de eventos via tc netem (delay/jitter/perda/rate) a partir de YAML
- Controlador SDN: Ryu (RemoteController), OF 1.3
"""

import os, sys, time, subprocess, argparse, threading, json
from pathlib import Path

try:
    import yaml
    HAVE_YAML = True
except Exception:
    HAVE_YAML = False

from mininet.net import Mininet
from mininet.node import RemoteController, OVSBridge, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info

# ---------- Helpers ----------
def _init_run_dir(policy):
    rd = policy.get("run_dir")
    if rd:
        os.makedirs(rd, exist_ok=True)
        return rd
    ts = time.strftime("%Y%m%d-%H%M%S")
    rd =+ "/" + ts + "/"
    os.makedirs(rd, exist_ok=True)
    return rd

def sh(cmd: str, shell=True, check=True):
    """Run a shell command with nice logging."""
    info(f'*** $ {cmd}\n')
    return subprocess.run(cmd, shell=shell, check=check)

def apply_netem_on(host, intf: str, params: dict, action='add'):
    """Aplica netem dentro do namespace do *host* (Mininet)."""
    if action == 'del':
        host.cmd(f"tc qdisc del dev {intf} root || true")
        return

    cmd = netem_cmd(
        intf,
        delay=params.get('delay_ms'),
        jitter=params.get('jitter_ms'),
        loss=params.get('loss_pct'),
        loss_corr=params.get('corr_pct'),
        corrupt=params.get('corrupt_pct'),
        duplicate=params.get('dup_pct'),
        reorder=params.get('reorder_pct'),
        reorder_gap=params.get('reorder_gap_ms'),
        rate=params.get('rate_mbit'),
        seed=params.get('seed'),
        action=('change' if action=='change' else 'add')
    )
    host.cmd(cmd)

def apply_qos_ovs(bridge: str, ifaces, rates):
    """
    Configura QoS HTB e duas filas em cada interface egress do OVS.
    rates = dict(max_rate, q0_min, q0_max, q1_min, q1_max) em bits/s
    """
    # Define QoS/Queues por porta
    for iface in ifaces:
        # Limpa QoS antiga (idempotência)
        sh(f"ovs-vsctl -- clear Port {iface} qos || true", check=False)

        cmd = (
          "ovs-vsctl -- set Port {iface} qos=@qos "
          "-- --id=@qos create QoS type=linux-htb other-config:max-rate={maxr} "
          "queues:0=@q0 queues:1=@q1 "
          "-- --id=@q0 create Queue other-config:min-rate={q0min} other-config:max-rate={q0max} "
          "-- --id=@q1 create Queue other-config:min-rate={q1min} other-config:max-rate={q1max}"
        ).format(
            iface=iface,
            maxr=rates['max_rate'],
            q0min=rates['q0_min'],
            q0max=rates['q0_max'],
            q1min=rates['q1_min'],
            q1max=rates['q1_max']
        )
        sh(cmd)

    # Garante OpenFlow13
    sh(f"ovs-vsctl set bridge {bridge} protocols=OpenFlow13")

def mark_dscp_for_c2(host, sport=14550, dscp_class='EF'):
    """
    Marca DSCP (tabela mangle) para pacotes UDP de C2 (ex.: MAVLink UDP 14550).
    EF = 46. Outras classes: AF41=34, CS6=48, etc.
    """
    # Remove regras antigas
    host.cmd("iptables -t mangle -F OUTPUT")
    host.cmd("iptables -t mangle -F PREROUTING")
    # Marca saídas do host (ex.: UAV originando MAVLink)
    host.cmd(f"iptables -t mangle -A OUTPUT -p udp --sport {sport} -j DSCP --set-dscp-class {dscp_class}")
    # (Opcional) marca entradas destinadas ao host (ex.: GCS recebendo MAVLink)
    host.cmd(f"iptables -t mangle -A PREROUTING -p udp --dport {sport} -j DSCP --set-dscp-class {dscp_class}")

def netem_cmd(dev: str, delay=None, jitter=None, loss=None, rate=None,
              loss_corr=None, corrupt=None, duplicate=None,
              reorder=None, reorder_gap=None, seed=None, action='add'):
    parts = [f"tc qdisc {action} dev {dev} root netem"]
    if delay is not None:
        parts.append(f"delay {delay}ms" + (f" {jitter}ms" if jitter is not None else ""))
    if loss is not None:
        # suporta "loss X% [corr%]"
        parts.append(f"loss {loss}%" + (f" {loss_corr}%" if loss_corr is not None else ""))
    if corrupt is not None:
        parts.append(f"corrupt {corrupt}%")
    if duplicate is not None:
        parts.append(f"duplicate {duplicate}%")
    if reorder is not None:
        rg = f" gap {reorder_gap}ms" if reorder_gap is not None else ""
        parts.append(f"reorder {reorder}%{rg}")
    if rate is not None:
        parts.append(f"rate {rate}mbit")
    if seed is not None:
        parts.append(f"seed {seed}")
    return " ".join(parts)


def apply_netem(intf: str, params: dict, action='add'):
    """Aplica netem na interface fornecida."""
    # Remove qdisc se pedido 'clear'
    if action == 'del':
        sh(f"tc qdisc del dev {intf} root || true", check=False)
        return

    delay = params.get('delay_ms')
    jitter = params.get('jitter_ms')
    loss = params.get('loss_pct')
    rate = params.get('rate_mbit')
    cmd = netem_cmd(intf, delay, jitter, loss, rate, action=('change' if action=='change' else 'add'))
    sh(cmd)

def log_event(run_dir, t, action, target, params=None):
    rec = {"ts": float(t), "action": action, "target": target, "params": params or {}}
    try:
        with open(os.path.join(run_dir, "events.jsonl"), "a") as fp:
            fp.write(json.dumps(rec) + "\n")
    except Exception:
        pass

def run_events(events_file: str, iface_map: dict, host_map: dict, start_time: float, run_dir: str):
    """
    Lê events.yaml e aplica netem/cortes conforme timeline.
    Formato exemplo:
      - at: 15.0
        target: ucv_to_uav     # mapeia para interface s1-eth2
        netem:
          delay_ms: 80
          jitter_ms: 20
          loss_pct: 2
          rate_mbit: 5
      - at: 45.0
        target: ucv_to_uav
        clear: true
    """
    if not HAVE_YAML:
        info('*** PyYAML não disponível; eventos desabilitados.\n')
        return
    with open(events_file, 'r') as f:
        events = yaml.safe_load(f) or []

    info(f'*** Scheduler de eventos: {len(events)} eventos\n')
    for ev in events:
        t = float(ev.get('at', 0))

        # Preferir 'target' simbólico; aceitar 'iface' como fallback
        host = None
        intf = None
        if 'target' in ev:
            mapping = iface_map.get(ev.get('target'))
            if isinstance(mapping, tuple) and len(mapping) == 2:
                host = host_map.get(mapping[0])
                intf = mapping[1]
            else:
                # mapeamento antigo só com string de interface
                intf = mapping
        else:
            intf = ev.get('iface')

        # Inferência automática de host se vier só a interface
        if host is None and isinstance(intf, str):
            if intf.startswith('uav-'):
                host = host_map.get('uav')
            elif intf.startswith('root-'):
                host = host_map.get('root')

        if not host or not intf:
            info(f'*** [WARN] evento sem host/intf válido: {ev}\n')
            continue

        # Espera até o tempo do evento
        now = time.time()
        wait = start_time + t - now
        if wait > 0:
            time.sleep(wait)

        if ev.get('clear'):
            info(f'*** [{t:.2f}s] CLEAR netem em {intf}\n')
            apply_netem_on(host, intf, {}, action='del')
            log_event(run_dir, t, "CLEAR", ev.get('target') or intf)
        else:
            params = ev.get('netem', {})
            info(f'*** [{t:.2f}s] APPLY netem em {intf}: {params}\n')
            # se já existe, usar change; senão add
            rc = host.cmd(f"tc qdisc show dev {intf} | grep -q netem ; echo $?").strip()
            action = 'change' if rc == '0' else 'add'
            apply_netem_on(host, intf, params, action=action)
            log_event(run_dir, t, "APPLY", ev.get('target') or intf, params)

def main():
    parser = argparse.ArgumentParser(description="UCV Mininet Experiment")
    parser.add_argument('--ctrl_ip', default='127.0.0.1')
    parser.add_argument('--ctrl_port', type=int, default=6633)
    parser.add_argument('--events', default='events.yaml', help='arquivo YAML com timeline de eventos')
    parser.add_argument('--bw', type=float, default=100, help='bw nominal de cada link (Mbit/s)')
    parser.add_argument('--delay', type=str, default='10ms', help='delay inicial de cada link')
    parser.add_argument('--start_cli', action='store_true', help='iniciar CLI ao final')
    
    parser.add_argument('--video_relay', action='store_true', help='iniciar socat no UAV para relé de vídeo 5600 -> host')
    parser.add_argument('--video_listen_port', type=int, default=5600)
    parser.add_argument('--video_dest_ip', default='10.1.0.254')
    parser.add_argument('--video_dest_port', type=int, default=5600)

    parser.add_argument('--run_dir', type=str, default=None, help='Diretório da rodada para salvar logs (default: /tmp/runs/<ts>_<basename(yaml)>)')

    args = parser.parse_args()

    

    # --- Pré-clean para evitar "RTNETLINK: File exists" ao recriar a topo ---
    info('*** Pre-clean Mininet/OVS/ifaces\n')
    subprocess.run('mn -c', shell=True, check=False)
    subprocess.run('ovs-vsctl --if-exists del-br s1', shell=True, check=False)
    for dev in ('root-eth0','root-eth1','uav-eth0','uav-eth1'):
        subprocess.run(f'ip link del {dev}', shell=True, check=False)


    # --- Carrega policy.yaml para unificar os perfis de QoS ---
    policy_file = os.environ.get("UCV_POLICY", "policy.yaml")
    policy = {}
    if HAVE_YAML and Path(policy_file).exists():
        with open(policy_file, "r") as f:
            policy = yaml.safe_load(f) or {}
    
    run_dir = _init_run_dir(policy)
    print(f"*** Run dir: {run_dir}")

    qos_profiles = policy.get("qos_profiles", {
        "baseline": {"q0_min": 2_000_000, "q0_max": 5_000_000,
                    "q1_min":   500_000, "q1_max": 98_000_000},
        "degraded": {"q0_min": 4_000_000, "q0_max": 8_000_000,
                    "q1_min":   200_000, "q1_max":  5_000_000}
    })
    init_profile = policy.get("qos_init_profile", "baseline")
    profile = qos_profiles.get(init_profile, list(qos_profiles.values())[0])
    # portas nas quais aplicar QoS (mesmas do controller/policy)
    qos_ifaces = policy.get("interfaces", ["s1-eth1","s1-eth2","s1-eth3","s1-eth4"])

    setLogLevel('info')

    # --- Cria rede ---
    net = Mininet(controller=None, link=TCLink, switch=OVSSwitch, autoStaticArp=True)

    info('*** Adicionando controlador remoto (Ryu)\n')
    c0 = net.addController('c0', controller=RemoteController, ip=args.ctrl_ip, port=args.ctrl_port)

    info('*** Adicionando hosts\n')
    uav = net.addHost('uav', ip='10.0.0.2/24')

    info('*** Adicionando switch (UCV/OVS)\n')
    s1 = net.addSwitch('s1', protocols='OpenFlow13')

    # depois de criar s1
    root = net.addHost('root', inNamespace=False)
    net.addLink(root, s1) # root-eth0 <-> s1-eth1 (host, 10.0.0.254)
    root.setIP('10.0.0.254/24', intf='root-eth0') 

    info('*** Criando links (TCLink)\n')
    # Links com atraso inicial; banda nominal controlada por OVS/queues em egress
    net.addLink(uav, s1, bw=args.bw, delay=args.delay)  # uav-eth0 <-> s1-eth2

    info('*** Criando links para Video (TCLink)\n')
    net.addLink(root, s1) # root-eth1 <-> s1-eth3
    net.addLink(uav, s1)  # uav-eth1  <-> s1-eth4

    # sub-rede do VÍDEO
    root.setIP('10.1.0.254/24', intf='root-eth1')  # host (QGC no host)
    uav.setIP('10.1.0.2/24',    intf='uav-eth1')   # UAV (fonte do vídeo)

    # Descobre IPs efetivos (evita erro se mudar sub-rede no futuro)
    uav_video_ip  = uav.IP(intf='uav-eth1')      # ex.: 10.1.0.2
    host_video_ip = root.IP(intf='root-eth1')    # ex.: 10.1.0.254

    info('*** Iniciando rede\n')
    net.start()

    root = net.get('root')
    root.cmd('ip addr flush dev root-eth0')
    root.cmd('ip addr add 10.0.0.254/24 dev root-eth0')
    root.cmd('ip link set root-eth0 up')

    # --- QoS no OVS (duas filas) puxando de policy.yaml ---
    info('*** Configurando QoS/Queues no OVS (policy.yaml)\n')
    rates = {
        "max_rate": int(args.bw * 1_000_000),  # largura de banda nominal do link (bps)
        "q0_min": int(profile.get("q0_min", 2_000_000)),
        "q0_max": int(profile.get("q0_max", 5_000_000)),
        "q1_min": int(profile.get("q1_min",   500_000)),
        "q1_max": int(profile.get("q1_max", 98_000_000)),
    }
    apply_qos_ovs('s1', qos_ifaces, rates)

    # --- Marcação DSCP para C2 (no UAV e no GCS) ---
    info('*** Marcando DSCP EF (46) para tráfego C2 (UDP/14550)\n')
    mark_dscp_for_c2(uav, sport=14550, dscp_class='EF')
    
    # --- Rotas básicas (ARP/ICMP ok) ---
    uav.cmd('ip route add default dev uav-eth0 || true')

    # --- Mapeamento de interfaces para eventos ---
    iface_map = {
        'ucv_to_gcs'   : ('root', 'root-eth0'),  # C2 lado host (GCS)
        'ucv_to_uav'   : ('uav',  'uav-eth0'),   # C2 lado UAV
        'video_to_host': ('root', 'root-eth1'),  # VÍDEO lado host (QGC)
        'video_to_uav' : ('uav',  'uav-eth1'),   # VÍDEO lado UAV (câmera)
    }
    host_map = {'root': root, 'uav': uav}

    procs = []  # processos que vamos limpar no final
    if args.video_relay:
        #uav socat -dd -u UDP4-RECV:5600,bind=127.0.0.1,reuseaddr UDP4-SENDTO:10.1.0.254:5600,bind=10.1.0.2
        socat_cmd = (
            f"socat -dd -u "
            f"UDP4-RECV:{args.video_listen_port},bind=127.0.0.1,reuseaddr,so-rcvbuf=2097152 "
            f"UDP4-SENDTO:{args.video_dest_ip}:{args.video_dest_port},bind={uav_video_ip} "
            f"2>{run_dir}/video_socat.log;"
        )
        info(f'*** Iniciando relé de vídeo no UAV: {socat_cmd}\n')
        p = uav.popen(socat_cmd, shell=True)
        procs.append(('uav_socat5600', p))

    # --- Scheduler de eventos (thread) ---
    if args.events and Path(args.events).exists():
        info(f'*** Carregando eventos de {args.events}\n')
        t0 = time.time()
        th = threading.Thread(target=run_events, args=(args.events, iface_map, host_map, t0, run_dir), daemon=True)
        th.start()
    else:
        info('*** Sem arquivo de eventos; execução contínua.\n')

    info('*** Pronto. Use ping entre hosts ou rode seus apps (PX4/QGC) nos hosts Mininet.\n')
    if args.start_cli:
        CLI(net)
    else:
        # Mantém rodando até Ctrl+C (para permitir execução de apps externos via mnexec, etc.)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass

    info('*** Encerrando rede\n')
    for name, p in procs:
        try:
            if p and p.poll() is None:
                info(f'*** Encerrando processo {name}\n')
                p.terminate()
                # fallback forte, se necessário:
                uav.cmd('pkill -f "socat .*UDP4-RECV:{port}"'.format(port=args.video_listen_port))
        except Exception:
            pass

    net.stop()

if __name__ == '__main__':
    main()