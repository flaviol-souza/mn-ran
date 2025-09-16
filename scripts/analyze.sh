#!/usr/bin/env bash
set -euo pipefail

# Usage: ./scripts/analyze.sh <PCAP_RX> <PCAP_TX>
# RX = lado que RECEBE (ex.: host root-eth0 quando PX4->QGC)
# TX = lado que ENVIA  (ex.: uav-eth0 quando PX4->QGC)
# Para cobrir as duas direções de MAVLink (bidirecional), rode duas vezes invertendo os argumentos.

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <PCAP_RX> <PCAP_TX>"
  exit 1
fi

PCAP_RX="$1"
PCAP_TX="$2"

# deps
command -v tshark >/dev/null 2>&1 || { echo "[ERR] tshark not found"; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "[ERR] python3 not found"; exit 2; }

ts() { date +"%Y%m%d_%H%M%S"; }
OUTDIR="logs/run_$(ts)"
mkdir -p "$OUTDIR"
echo "[*] Output dir: $OUTDIR"

# copia pcaps (só para referenciar no relatório)
cp -v "$PCAP_RX" "$OUTDIR/gcs.pcap" 2>/dev/null || cp -v "$PCAP_RX" "$OUTDIR/rx.pcap"
cp -v "$PCAP_TX" "$OUTDIR/uav.pcap" 2>/dev/null || cp -v "$PCAP_TX" "$OUTDIR/tx.pcap"

# --- RTP (opcional, se houver) ---
echo "[*] RTP streams (RX side)"
# tenta decodificar 5004 como RTP; se não houver, arquivo ficará vazio (ok)
tshark -r "$PCAP_RX" -q -d udp.port==5004,rtp -z rtp,streams > "$OUTDIR/rtp_streams.txt" || true

# --- C2 (MAVLink) sem dissector: extrai time_epoch + data.data e parseia seq no Python ---
echo "[*] C2 OWD (payload-based) ..."

RX_TSV="$OUTDIR/c2_rx_seq.tsv"
TX_TSV="$OUTDIR/c2_tx_seq.tsv"
OWD_TSV="$OUTDIR/c2_owd_ms.tsv"
JIT_TSV="$OUTDIR/c2_jitter_ms.tsv"
REPORT="$OUTDIR/report.md"

# Extração crua (tempo + payload) – sem depender de dissector
tshark -r "$PCAP_RX" -T fields -e frame.time_epoch -e data.data -Y "udp.port==14550 and data" > "$OUTDIR/rx_raw.tsv" || true
tshark -r "$PCAP_TX" -T fields -e frame.time_epoch -e data.data -Y "udp.port==14550 and data" > "$OUTDIR/tx_raw.tsv" || true

# Python: parser MAVLink v1 (0xFE) / v2 (0xFD) com varredura do payload
python3 - "$OUTDIR/rx_raw.tsv" > "$RX_TSV" <<'PY'
import sys
import binascii

def seqs_from_bytes(b: bytes):
    out=[]
    i=0
    n=len(b)
    while i < n:
        byte=b[i]
        if byte==0xFE and i+6<=n:   # v1: 0xFE len seq sys comp msgid
            out.append(b[i+2])
            i += 6
            continue
        if byte==0xFD and i+8<=n:   # v2: 0xFD len inc comp seq sys comp msgid[3]
            out.append(b[i+4])
            i += 10 if i+10<=n else 8
            continue
        i+=1
    return out

rx_in = sys.argv[1]
with open(rx_in,'r') as f:
    for line in f:
        parts=line.strip().split('\t')
        if len(parts)<2: continue
        try:
            t=float(parts[0])
        except:
            continue
        hexdata=parts[1].replace(':','')
        if len(hexdata)<4: continue
        try:
            b=binascii.unhexlify(hexdata)
        except:
            continue
        seqs=seqs_from_bytes(b)
        # use o primeiro frame MAVLink do datagrama (suficiente p/ casar seq)
        if seqs:
            print(f"{t}\t{int(seqs[0])}")
PY

python3 - "$OUTDIR/tx_raw.tsv" > "$TX_TSV" <<'PY'
import sys
import binascii

def seqs_from_bytes(b: bytes):
    out=[]
    i=0
    n=len(b)
    while i < n:
        byte=b[i]
        if byte==0xFE and i+6<=n:
            out.append(b[i+2])
            i += 6
            continue
        if byte==0xFD and i+8<=n:
            out.append(b[i+4])
            i += 10 if i+10<=n else 8
            continue
        i+=1
    return out

tx_in = sys.argv[1]
with open(tx_in,'r') as f:
    for line in f:
        parts=line.strip().split('\t')
        if len(parts)<2: continue
        try:
            t=float(parts[0])
        except:
            continue
        hexdata=parts[1].replace(':','')
        if len(hexdata)<4: continue
        try:
            b=binascii.unhexlify(hexdata)
        except:
            continue
        seqs=seqs_from_bytes(b)
        if seqs:
            print(f"{t}\t{int(seqs[0])}")
PY

# Calcula OWD casando seq (TX->RX)
python3 - "$RX_TSV" "$TX_TSV" > "$OWD_TSV" <<'PY'
import sys, statistics

rx_path, tx_path = sys.argv[1], sys.argv[2]
def load(path):
    d={}
    for ln in open(path):
        ln=ln.strip()
        if not ln or ln.startswith('#'): continue
        t,s = ln.split('\t')
        try:
            t=float(t); s=int(s)
        except:
            continue
        # mantém o primeiro timestamp visto para cada seq
        if s not in d: d[s]=t
    return d

rx=load(rx_path)
tx=load(tx_path)
pairs=[]
for s,t_tx in tx.items():
    t_rx = rx.get(s)
    if t_rx is None: continue
    owd_ms = (t_rx - t_tx)*1000.0
    pairs.append((s, owd_ms))

pairs.sort(key=lambda x: x[0])
for s,owd in pairs:
    print(f"{s}\t{owd:.3f}")

# resumo no stderr
if pairs:
    arr=[owd for _,owd in pairs]
    arr_sorted=sorted(arr)
    p50 = statistics.median(arr)
    p95 = arr_sorted[int(0.95*len(arr_sorted))-1]
    p99 = arr_sorted[int(0.99*len(arr_sorted))-1] if len(arr_sorted)>=100 else arr_sorted[-1]
    sys.stderr.write(f"# OWD: n={len(arr)} p50={p50:.1f}ms p95={p95:.1f}ms p99={p99:.1f}ms min={min(arr):.1f} max={max(arr):.1f}\n")
else:
    sys.stderr.write("# OWD: n=0 (sem casamento de seq)\n")
PY

# Jitter no RX (inter-chegada)
python3 - "$RX_TSV" > "$JIT_TSV" <<'PY'
import sys, statistics
ts=[]
for ln in open(sys.argv[1]):
    ln=ln.strip()
    if not ln or ln.startswith('#'): continue
    t,_ = ln.split('\t')
    try:
        ts.append(float(t))
    except:
        pass
ts.sort()
ia=[(ts[i]-ts[i-1])*1000.0 for i in range(1,len(ts))]
for i,v in enumerate(ia, start=1):
    print(f"{i}\t{v:.3f}")
if ia:
    arr=sorted(ia)
    p50=statistics.median(arr)
    p95=arr[int(0.95*len(arr))-1]
    p99=arr[int(0.99*len(arr))-1] if len(arr)>=100 else arr[-1]
    sys.stderr.write(f"# JITTER(RX): n={len(arr)} p50={p50:.1f}ms p95={p95:.1f}ms p99={p99:.1f}ms min={min(arr):.1f} max={max(arr):.1f}\n")
else:
    sys.stderr.write("# JITTER(RX): n=0\n")
PY

# Gera report.md
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
