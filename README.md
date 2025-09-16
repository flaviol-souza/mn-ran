```markdown
# UCV SDN Testbed for UAS C2/ISR KPI Experiments

This repository emulates a **UAV Control Vehicle (UCV)** with **Mininet + Open vSwitch (OVS)** and a **Ryu** SDN controller to prioritize **C2 (MAVLink/UDP 14550)** over **ISR best-effort** traffic.  
An **event scheduler** injects controlled degradations (delay/jitter/loss/rate) via `tc netem`.  
A new `scripts/analyze.sh` extracts **C2 OWD/jitter** **without requiring the MAVLink dissector** (parses payload) and, if present, summarizes **RTP** streams.

---

## Architecture

**Control Plane (decisions)**
```

+-----------------------+        OpenFlow TCP/6653        +-----------+
\|   Ryu (UcvController) | <-----------------------------> |  OVS s1   |
+-----------------------+                                  +-----------+

```

**Data Plane (mission packets)**
```

+-----+      link GCS       +-----------+       link UAV       +-----+
\| GCS | <-----------------> |   OVS s1  | <-----------------> | UAV |
+-----+                      +-----------+                      +-----+
^                             ^     ^                          ^
\|                             |     |                          |
\|       (per-port HTB queues) |     |       (per-port HTB queues)
\|              s1-eth-GCS     |     |             s1-eth-UAV
+-----------------------------+-----+-----------------------------+

````

> A porta **`root-eth0`** no host é conectada à bridge `s1` (criada pelo Mininet). O **QGC roda no host**, e o **PX4 SITL** roda no host **dentro do namespace `uav`** do Mininet.  
> **Fila 0** = C2 priorizado; **Fila 1** = ISR best-effort (HTB).

---

## Requirements (host)

```bash
sudo apt-get update
sudo apt-get install -y mininet openvswitch-switch iproute2 \
                        tshark xterm \
                        python3-venv
# (Opcional para testes de vídeo RTP)
sudo apt-get install -y gstreamer1.0-tools gstreamer1.0-plugins-{base,good,ugly}
````

**Known-good Ryu on Python 3.9**

```bash
python3.9 -m venv ~/venv-ryu39
source ~/venv-ryu39/bin/activate
pip install --upgrade pip setuptools wheel
pip install "ryu @ git+https://github.com/faucetsdn/ryu@master" \
            eventlet==0.31.1 packaging==20.9 tinyrpc==1.0.4
```

> Para capturar com `tshark` sem `sudo`:
> `sudo dpkg-reconfigure wireshark-common` e adicione seu usuário ao grupo `wireshark` (deslogar/logar).
> **Não é necessário o dissector MAVLink** para análise; o script novo parseia o payload.

---

## Files you will use

* `controller.py` – Ryu app (classificação C2, filas HTB, políticas baseline/degraded, loop por KPI/netem, regras proativas opcionais).
* `ucv.py` – constrói topologia Mininet (GCS, UAV, OVS s1, root-eth0), aplica QoS/queues e agenda eventos netem de `events*.yaml`.
* `policy.yaml` – interfaces monitoradas, perfis de QoS, modo de detecção (`netem`, `kpi`, `kpi_or_netem`).
* `events.yaml` / `events_lowloss.yaml` / `events_congest.yaml` / `events_burst.yaml` – perfis de degradação.
* `scripts/analyze.sh` – **novo analisador** (bash) que **não depende do dissector** MAVLink; gera KPIs e `report.md`.

> Execute `scripts/*.sh` sempre com **bash** (não `sh`), pois usam `set -o pipefail`.

---

## Quick start (3 terminals)

### Terminal A — Ryu controller (host)

```bash
source ~/venv-ryu39/bin/activate
sudo fuser -k 6653/tcp 2>/dev/null || true
~/venv-ryu39/bin/ryu-manager --ofp-tcp-listen-port 6653 controller.py --verbose
```

### Terminal B — Mininet + OVS (host)

```bash
xhost +SI:localuser:root      # permite janelas X para namespaces root (xterm)
sudo python3 ucv.py --ctrl_port 6653 --start_cli --events events.yaml
```

No prompt `mininet>`:

```bash
# Garanta IP/UP no host-port ligado à bridge s1
mininet> sh ip addr add 10.0.0.254/24 dev root-eth0 || true
mininet> sh ip link set root-eth0 up
# (Opcional) ver links/nomes de portas:
mininet> links
```

### Terminal C — Regras proativas (host)

Para que os **primeiros pacotes** C2 já tenham caminho/priority:

```bash
sudo ovs-ofctl -O OpenFlow13 add-flow s1 "priority=60,udp,tp_dst=14550,actions=set_queue:0,NORMAL"
sudo ovs-ofctl -O OpenFlow13 add-flow s1 "priority=60,udp,tp_src=14550,actions=set_queue:0,NORMAL"
sudo ovs-ofctl -O OpenFlow13 add-flow s1 "priority=50,arp,actions=NORMAL"
sudo ovs-ofctl -O OpenFlow13 add-flow s1 "priority=40,icmp,actions=NORMAL"
```

Verifique:

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1 | egrep 'tp_(src|dst)=14550|arp|icmp|set_queue'
```

---

## Run PX4 and QGC

### Iniciar PX4 SITL no `uav` (dentro do Mininet)

```bash
mininet> xterm uav
```

No xterm:

```bash
cd ~/PX4-Autopilot
make px4_sitl jmavsim          # ou HEADLESS=1 make px4_sitl jmavsim
# pxh>
mavlink stop-all
mavlink start -x -u 14550 -r 20 -t 10.0.0.254 -p
mavlink status                 # partner: 10.0.0.254:14550; contadores TX subindo
```

### Rodar QGroundControl no host

Abra o QGC normalmente. Ele deve detectar o fluxo UDP/14550.
Checar no host:

```bash
ss -lun | grep 14550
sudo tcpdump -ni root-eth0 udp port 14550 -c 5
```

---

## Packet capture (C2)

> Para **PX4 → QGC (uav→host)**: capture **no host `root-eth0`** (RX) e **no `uav-eth0`** (TX).

**Mininet (TX lado PX4)**

```bash
mininet> uav tshark -i uav-eth0 -f "udp port 14550" -w /tmp/uav_c2.pcap &
```

**Host (RX lado QGC)**

```bash
sudo tshark -i root-eth0 -f "udp port 14550" -w /tmp/host_c2.pcap &
```

> Para **QGC → PX4 (host→uav)**, a mesma dupla de capturas vale; você analisará invertendo a ordem dos pcaps (ver próxima seção).

**(Opcional) RTP ISR**
Se você também gerar vídeo RTP (porta 5004), capture no destino e, se quiser, force decode-as:

```bash
mininet> gcs tshark -i gcs-eth0 -d udp.port==5004,rtp -w /tmp/gcs_rtp.pcap &
```

---

## KPI extraction (novo `analyze.sh`)

O script **não depende** do dissector MAVLink: ele parseia `data.data`, identifica frames MAVLink v1/v2 e casa sequências.

**Instale a versão nova (bash)** de `scripts/analyze.sh`:

````bash
cat > scripts/analyze.sh <<'BASH'
#!/usr/bin/env bash
set -euo pipefail

# Usage: ./scripts/analyze.sh <PCAP_RX> <PCAP_TX>
# RX = lado que RECEBE (ex.: host root-eth0 quando PX4->QGC)
# TX = lado que ENVIA  (ex.: uav-eth0 quando PX4->QGC)

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <PCAP_RX> <PCAP_TX>"
  exit 1
fi

PCAP_RX="$1"
PCAP_TX="$2"

command -v tshark >/dev/null 2>&1 || { echo "[ERR] tshark not found"; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "[ERR] python3 not found"; exit 2; }

ts() { date +"%Y%m%d_%H%M%S"; }
OUTDIR="logs/run_$(ts)"
mkdir -p "$OUTDIR"
echo "[*] Output dir: $OUTDIR"

cp -v "$PCAP_RX" "$OUTDIR/gcs.pcap" 2>/dev/null || cp -v "$PCAP_RX" "$OUTDIR/rx.pcap"
cp -v "$PCAP_TX" "$OUTDIR/uav.pcap" 2>/dev/null || cp -v "$PCAP_TX" "$OUTDIR/tx.pcap"

echo "[*] RTP streams (RX side)"
tshark -r "$PCAP_RX" -q -d udp.port==5004,rtp -z rtp,streams > "$OUTDIR/rtp_streams.txt" || true

echo "[*] C2 OWD (payload-based) ..."
RX_TSV="$OUTDIR/c2_rx_seq.tsv"
TX_TSV="$OUTDIR/c2_tx_seq.tsv"
OWD_TSV="$OUTDIR/c2_owd_ms.tsv"
JIT_TSV="$OUTDIR/c2_jitter_ms.tsv"
REPORT="$OUTDIR/report.md"

tshark -r "$PCAP_RX" -T fields -e frame.time_epoch -e data.data -Y "udp.port==14550 and data" > "$OUTDIR/rx_raw.tsv" || true
tshark -r "$PCAP_TX" -T fields -e frame.time_epoch -e data.data -Y "udp.port==14550 and data" > "$OUTDIR/tx_raw.tsv" || true

python3 - "$OUTDIR/rx_raw.tsv" > "$RX_TSV" <<'PY'
import sys, binascii
def seqs_from_bytes(b):
    out=[]; i=0; n=len(b)
    while i<n:
        byte=b[i]
        if byte==0xFE and i+6<=n: out.append(b[i+2]); i+=6; continue
        if byte==0xFD and i+8<=n: out.append(b[i+4]); i+=10 if i+10<=n else 8; continue
        i+=1
    return out
with open(sys.argv[1],'r') as f:
    for ln in f:
        p=ln.strip().split('\t')
        if len(p)<2: continue
        try: t=float(p[0])
        except: continue
        x=p[1].replace(':','')
        if len(x)<4: continue
        try: b=binascii.unhexlify(x)
        except: continue
        s=seqs_from_bytes(b)
        if s: print(f"{t}\t{int(s[0])}")
PY

python3 - "$OUTDIR/tx_raw.tsv" > "$TX_TSV" <<'PY'
import sys, binascii
def seqs_from_bytes(b):
    out=[]; i=0; n=len(b)
    while i<n:
        byte=b[i]
        if byte==0xFE and i+6<=n: out.append(b[i+2]); i+=6; continue
        if byte==0xFD and i+8<=n: out.append(b[i+4]); i+=10 if i+10<=n else 8; continue
        i+=1
    return out
with open(sys.argv[1],'r') as f:
    for ln in f:
        p=ln.strip().split('\t')
        if len(p)<2: continue
        try: t=float(p[0])
        except: continue
        x=p[1].replace(':','')
        if len(x)<4: continue
        try: b=binascii.unhexlify(x)
        except: continue
        s=seqs_from_bytes(b)
        if s: print(f"{t}\t{int(s[0])}")
PY

python3 - "$RX_TSV" "$TX_TSV" > "$OWD_TSV" <<'PY'
import sys, statistics
rx_path, tx_path = sys.argv[1], sys.argv[2]
def load(path):
    d={}
    for ln in open(path):
        if not ln.strip() or ln.startswith('#'): continue
        t,s = ln.strip().split('\t')
        try: t=float(t); s=int(s)
        except: continue
        if s not in d: d[s]=t
    return d
rx,tx=load(rx_path),load(tx_path)
pairs=[]
for s,t_tx in tx.items():
    t_rx=rx.get(s)
    if t_rx is None: continue
    pairs.append((s,(t_rx-t_tx)*1000.0))
pairs.sort(key=lambda x:x[0])
for s,owd in pairs: print(f"{s}\t{owd:.3f}")
if pairs:
    arr=sorted([owd for _,owd in pairs])
    import math
    p50 = (arr[len(arr)//2] if len(arr)%2 else (arr[len(arr)//2-1]+arr[len(arr)//2])/2)
    p95 = arr[max(0,int(math.floor(0.95*(len(arr)-1))))]
    p99 = arr[max(0,int(math.floor(0.99*(len(arr)-1))))]
    sys.stderr.write(f"# OWD: n={len(arr)} p50={p50:.1f}ms p95={p95:.1f}ms p99={p99:.1f}ms min={min(arr):.1f} max={max(arr):.1f}\n")
else:
    sys.stderr.write("# OWD: n=0 (no seq matches)\n")
PY

python3 - "$RX_TSV" > "$JIT_TSV" <<'PY'
import sys, statistics, math
ts=[]
for ln in open(sys.argv[1]):
    if not ln.strip() or ln.startswith('#'): continue
    t,_=ln.strip().split('\t')
    try: ts.append(float(t))
    except: pass
ts.sort()
ia=[(ts[i]-ts[i-1])*1000.0 for i in range(1,len(ts))]
for i,v in enumerate(ia,1): print(f"{i}\t{v:.3f}")
if ia:
    arr=sorted(ia)
    p50 = (arr[len(arr)//2] if len(arr)%2 else (arr[len(arr)//2-1]+arr[len(arr)//2])/2)
    p95 = arr[max(0,int(math.floor(0.95*(len(arr)-1))))]
    p99 = arr[max(0,int(math.floor(0.99*(len(arr)-1))))]
    sys.stderr.write(f"# JITTER(RX): n={len(arr)} p50={p50:.1f}ms p95={p95:.1f}ms p99={p99:.1f}ms min={min(arr):.1f} max={max(arr):.1f}\n")
else:
    sys.stderr.write("# JITTER(RX): n=0\n")
PY

{
  echo "# KPI Report"
  echo
  echo "RX pcap: \`$PCAP_RX\`"
  echo "TX pcap: \`$PCAP_TX\`"
  echo
  echo "## RTP (RX side)"
  if [[ -s "$OUTDIR/rtp_streams.txt" ]]; then
    echo '```'
    sed -n '1,200p' "$OUTDIR/rtp_streams.txt"
    echo '```'
  else
    echo "_no RTP streams detected (ok if you didn't stream video)_"
  fi
  echo
  echo "## C2 OWD (ms) by seq"
  if [[ -s "$OWD_TSV" ]]; then
    echo '```'
    head -n 20 "$OWD_TSV"
    echo '...'
    tail -n 5 "$OWD_TSV"
    echo '```'
  else
    echo "_no OWD pairs (no matching sequences found)_"
  fi
  echo
  echo "## C2 Inter-arrival Jitter at RX (ms)"
  if [[ -s "$JIT_TSV" ]]; then
    echo '```'
    head -n 20 "$JIT_TSV"
    echo '...'
    tail -n 5 "$JIT_TSV"
    echo '```'
  else
    echo "_no RX packets parsed for jitter_"
  fi
} > "$REPORT"

echo "[OK] Report: $REPORT"
BASH
chmod +x scripts/analyze.sh
````

**Rodar (PX4→QGC)**

```bash
sudo ./scripts/analyze.sh /tmp/host_c2.pcap /tmp/uav_c2.pcap
```

**Rodar (QGC→PX4) — invertendo a ordem**

```bash
sudo ./scripts/analyze.sh /tmp/uav_c2.pcap /tmp/host_c2.pcap
```

Checar saídas:

```bash
LATEST=$(ls -1td logs/run_* | head -1)
wc -l $LATEST/c2_owd_ms.tsv  $LATEST/c2_jitter_ms.tsv
sed -n '1,80p' $LATEST/report.md
```

---

## Events & policy

**Exemplos de eventos**

```yaml
# events_lowloss.yaml
- at: 10.0  ; iface: s1-ethUAV ; netem: { delay_ms: 40, jitter_ms: 10, loss_pct: 0.2, rate_mbit: 10 }
- at: 40.0  ; iface: s1-ethUAV ; clear: true
- at: 60.0  ; iface: s1-ethGCS ; netem: { delay_ms: 40, jitter_ms: 10, loss_pct: 0.2, rate_mbit: 10 }
- at: 90.0  ; iface: s1-ethGCS ; clear: true
```

```yaml
# events_congest.yaml
- at: 10.0  ; iface: s1-ethUAV ; netem: { delay_ms: 120, jitter_ms: 30, loss_pct: 1, rate_mbit: 5 }
- at: 40.0  ; iface: s1-ethUAV ; clear: true
- at: 60.0  ; iface: s1-ethGCS ; netem: { delay_ms: 120, jitter_ms: 30, loss_pct: 1, rate_mbit: 5 }
- at: 90.0  ; iface: s1-ethGCS ; clear: true
```

```yaml
# events_burst.yaml
- at: 20.0  ; iface: s1-ethUAV ; netem: { delay_ms: 30, jitter_ms: 5, loss_pct: 5 }
- at: 30.0  ; iface: s1-ethUAV ; clear: true
- at: 50.0  ; iface: s1-ethGCS ; netem: { delay_ms: 30, jitter_ms: 5, loss_pct: 5 }
- at: 55.0  ; iface: s1-ethGCS ; clear: true
```

**Política (policy.yaml)**

```yaml
interfaces: [s1-eth2, s1-eth3]   # confirme com 'mininet> links'
poll_seconds: 2
detection_mode: kpi_or_netem     # 'netem' | 'kpi' | 'kpi_or_netem'
qos_profiles:
  baseline: { q0_min: 2000000, q0_max: 5000000, q1_min: 500000,  q1_max: 98000000 }
  degraded: { q0_min: 4000000, q0_max: 8000000, q1_min: 200000,  q1_max: 5000000 }
```

> Em modo `kpi`/`kpi_or_netem`, o controlador mede KPIs (via `root-eth0`) e alterna perfis. Observe logs como:
> `[kpi] degrade: loss=2.4% jitter_p95=65.1 ms` / `[kpi] recover: ...`.

---

## Minimal smoke test (coleta)

1. Inicie Ryu e Mininet (com `root-eth0` up).
2. Capturas:

   * Mininet: `uav tshark -i uav-eth0 -f "udp port 14550" -w /tmp/uav_c2.pcap &`
   * Host:    `sudo tshark -i root-eth0 -f "udp port 14550" -w /tmp/host_c2.pcap &`
3. PX4 no `uav`: `make px4_sitl jmavsim` → `mavlink start -x -u 14550 -r 20 -t 10.0.0.254 -p`.
4. Após \~15 s, pare capturas (uav/host).
5. Verifique pacotes:
   `sudo tshark -r /tmp/host_c2.pcap -Y "udp.port==14550" -c 5`
   `mininet> uav tshark -r /tmp/uav_c2.pcap -Y "udp.port==14550" -c 5`
6. Analise: `sudo ./scripts/analyze.sh /tmp/host_c2.pcap /tmp/uav_c2.pcap`
   Confirme `c2_owd_ms.tsv`, `c2_jitter_ms.tsv` e `report.md` **não vazios**.

---

## Useful checks

```bash
# OVS ports & link roles
sudo ovs-ofctl -O OpenFlow13 show s1
# QoS/queues por porta
sudo ovs-appctl qos/show s1
# Flows de priorização C2
sudo ovs-ofctl -O OpenFlow13 dump-flows s1 | egrep 'set_queue|14550'
# Netem ativo?
tc qdisc show dev s1-eth2
tc qdisc show dev s1-eth3
```

---

## Troubleshooting

* **Arquivos .tsv vazios**: use a **nova** `scripts/analyze.sh` (payload-based). Confirmar que *há* pacotes nos pcaps (passo 5 do smoke test).
* **QGC no Mininet**: não suportado (rodar no host).
* **`root-eth0` não existe**: só existe enquanto a topologia está ativa.
* **Sem caminho para primeiros pacotes**: adicione **regras proativas** (seção “Regras proativas”).
* **Avisos HTB “quantum is big”**: inócuos nesse cenário; ignore ou ajuste taxas.

---

## Clean up

```bash
# dentro do Mininet:
mininet> exit
# opcional (após sair do Mininet): limpar QoS objetos
sudo ovs-vsctl -- --all destroy QoS -- --all destroy Queue
```

---

## Next steps

* Rodar matriz de cenários (`events_*`) e comparar KPIs com/sem `detection_mode: kpi_or_netem`.
* Integrar pipelines RTP de verdade (GStreamer) e incluir RTCP.
* Multi-UE, múltiplos caminhos e fast failover.
* Marcação DSCP por app, QoE-aware policies e capability-based planning.

---

```
::contentReference[oaicite:0]{index=0}
```
