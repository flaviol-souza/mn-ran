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

import os, sys, time, subprocess, argparse, threading
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

def sh(cmd: str, shell=True, check=True):
    """Run a shell command with nice logging."""
    info(f'*** $ {cmd}\n')
    return subprocess.run(cmd, shell=shell, check=check)

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

def netem_cmd(dev: str, delay=None, jitter=None, loss=None, rate=None, action='add'):
    """
    Monta comando tc netem (delay, jitter, loss, rate). action: add/change/del
    """
    parts = [f"tc qdisc {action} dev {dev} root netem"]
    if delay is not None:
        if jitter is not None:
            parts.append(f"delay {delay}ms {jitter}ms")
        else:
            parts.append(f"delay {delay}ms")
    if loss is not None:
        parts.append(f"loss {loss}%")
    if rate is not None:
        parts.append(f"rate {rate}mbit")
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

def run_events(events_file: str, iface_map: dict, start_time: float):
    """
    Lê events.yaml e aplica netem/cortes conforme timeline.
    Formato exemplo:
      - at: 15.0
        target: ucv_to_uav     # mapeia para interface s1-eth3
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

        # aceitar 'target' (preferência) ou 'iface' (compatibilidade)
        if 'target' in ev:
            intf = iface_map.get(ev.get('target'))
        else:
            intf = ev.get('iface')

        if not intf:
            info(f'*** [WARN] evento sem target/iface mapeado: {ev}\n')
            continue

        # Espera até o tempo do evento
        now = time.time()
        wait = start_time + t - now
        if wait > 0:
            time.sleep(wait)

        if ev.get('clear'):
            info(f'*** [{t:.2f}s] CLEAR netem em {intf}\n')
            apply_netem(intf, {}, action='del')
        else:
            params = ev.get('netem', {})
            info(f'*** [{t:.2f}s] APPLY netem em {intf}: {params}\n')
            # se já existe, use change; senão add (tentamos change e caímos em add)
            rc = subprocess.run(f"tc qdisc show dev {intf} | grep netem", shell=True)
            action = 'change' if rc.returncode == 0 else 'add'
            apply_netem(intf, params, action=action)

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

    args = parser.parse_args()

    setLogLevel('info')

    # --- Cria rede ---
    net = Mininet(controller=None, link=TCLink, switch=OVSSwitch, autoStaticArp=True)

    info('*** Adicionando controlador remoto (Ryu)\n')
    c0 = net.addController('c0', controller=RemoteController, ip=args.ctrl_ip, port=args.ctrl_port)

    info('*** Adicionando hosts\n')
    gcs = net.addHost('gcs', ip='10.0.0.1/24')
    uav = net.addHost('uav', ip='10.0.0.2/24')

    info('*** Adicionando switch (UCV/OVS)\n')
    s1 = net.addSwitch('s1', protocols='OpenFlow13')

    # depois de criar s1
    root = net.addHost('root', inNamespace=False)
    net.addLink(root, s1) # root-eth0 <-> s1-eth1 (host, 10.0.0.254)
    root.setIP('10.0.0.254/24', intf='root-eth0') 

    info('*** Criando links (TCLink)\n')
    # Links com atraso inicial; banda nominal controlada por OVS/queues em egress
    net.addLink(gcs, s1, bw=args.bw, delay=args.delay)  # gcs-eth0 <-> s1-eth2
    net.addLink(uav, s1, bw=args.bw, delay=args.delay)  # uav-eth0 <-> s1-eth3

    info('*** Criando links para Video (TCLink)\n')
    net.addLink(root, s1) # root-eth1 <-> s1-eth4
    net.addLink(uav, s1)  # uav-eth1  <-> s1-eth5

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

    # --- QoS no OVS (duas filas) ---
    info('*** Configurando QoS/Queues no OVS\n')
    # valores exemplo (ajuste conforme cenário)
    rates = dict(
        max_rate=int(args.bw * 1_000_000),  # bps
        q0_min=2_000_000,   # C2 garantido
        q0_max=5_000_000,
        q1_min=500_000,     # ISR mínimo
        q1_max=int(args.bw * 1_000_000) - 2_000_000
    )
    apply_qos_ovs('s1', ['s1-eth2', 's1-eth3', 's1-eth4', 's1-eth5' ], rates)

    # --- Marcação DSCP para C2 (no UAV e no GCS) ---
    info('*** Marcando DSCP EF (46) para tráfego C2 (UDP/14550)\n')
    mark_dscp_for_c2(uav, sport=14550, dscp_class='EF')
    mark_dscp_for_c2(gcs, sport=14550, dscp_class='EF')

    # --- Rotas básicas (ARP/ICMP ok) ---
    gcs.cmd('ip route add default dev gcs-eth0 || true')
    uav.cmd('ip route add default dev uav-eth0 || true')

    # --- Mapeamento de interfaces para eventos ---
    iface_map = {
        'ucv_to_gcs': 's1-eth2',   # C2: uplink/downlink GCS <-> OVS
        'ucv_to_uav': 's1-eth3',   # C2: OVS <-> UAV
        'video_to_host': 's1-eth4',# VÍDEO: OVS -> host (root-eth1)
        'video_to_uav': 's1-eth5', # VÍDEO: OVS -> UAV (uav-eth1)
    }

    procs = []  # processos que vamos limpar no final

    if args.video_relay:
        socat_cmd = (
            f"socat -d -d -u "
            f"UDP4-RECV:{args.video_listen_port},reuseaddr,ipv6only=0 "
            f"UDP4-SENDTO:{args.video_dest_ip}:{args.video_dest_port}"
        )
        info(f'*** Iniciando relé de vídeo no UAV: {socat_cmd}\n')
        p = uav.popen(socat_cmd, shell=True)
        procs.append(('uav_socat5600', p))



    # --- Scheduler de eventos (thread) ---
    if args.events and Path(args.events).exists():
        info(f'*** Carregando eventos de {args.events}\n')
        t0 = time.time()
        th = threading.Thread(target=run_events, args=(args.events, iface_map, t0), daemon=True)
        th.start()
    else:
        info('*** Sem arquivo de eventos; execução contínua.\n')

    info('*** Pronto. Use ping entre hosts ou rode seus apps (PX4/QGC) nos hosts Mininet.\n')
    info('    Ex.: mininet> gcs ping -c 3 10.0.0.2\n')

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
