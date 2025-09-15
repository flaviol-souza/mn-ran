#!/usr/bin/env bash
set -euo pipefail

GCS_PCAP=${1:-/tmp/gcs.pcap}
UAV_PCAP=${2:-/tmp/uav.pcap}
OUTDIR=${3:-./logs/run_$(date +%Y%m%d_%H%M%S)}
mkdir -p "$OUTDIR"

echo "[*] Copiando pcaps..."
cp -v "$GCS_PCAP" "$OUTDIR/gcs.pcap"
cp -v "$UAV_PCAP" "$OUTDIR/uav.pcap"

echo "[*] RTP streams (gcs)"
tshark -r "$GCS_PCAP" -q -z rtp,streams > "$OUTDIR/rtp_streams.txt" || true

echo "[*] C2 OWD (MAVLink seq) ..."
tshark -r "$GCS_PCAP" -Y "udp.port==14550 && mavlink && ip.dst==10.0.0.2" \
  -T fields -e frame.time_epoch -e mavlink.seq > "$OUTDIR/c2_tx.tsv" || true
tshark -r "$UAV_PCAP" -Y "udp.port==14550 && mavlink && ip.src==10.0.0.1" \
  -T fields -e frame.time_epoch -e mavlink.seq > "$OUTDIR/c2_rx.tsv" || true

awk '{print $2"\t"$1}' "$OUTDIR/c2_tx.tsv" | sort -k1,1n > "$OUTDIR/c2_tx_byseq.tsv" || true
awk '{print $2"\t"$1}' "$OUTDIR/c2_rx.tsv" | sort -k1,1n > "$OUTDIR/c2_rx_byseq.tsv" || true
join "$OUTDIR/c2_tx_byseq.tsv" "$OUTDIR/c2_rx_byseq.tsv" \
  | awk '{print $1" "$3-$2}' > "$OUTDIR/c2_owd.tsv" || true

# métricas C2
MEAN=$(awk '{s+=$2} END{if(NR>0) printf("%.6f", s/NR); else print "NA"}' "$OUTDIR/c2_owd.tsv")
P95=$(sort -k2,2n "$OUTDIR/c2_owd.tsv" | awk '{a[NR]=$2} END{if(NR>0) printf("%.6f", a[int(0.95*NR)]); else print "NA"}')
P99=$(sort -k2,2n "$OUTDIR/c2_owd.tsv" | awk '{a[NR]=$2} END{if(NR>0) printf("%.6f", a[int(0.99*NR)]); else print "NA"}')

# jitter estilo RFC3550
JIT=$(sort -k1,1n "$OUTDIR/c2_owd.tsv" | awk 'NR==1{prev=""; J=0; next} {t=$2; if(NR>1){d=t-prev; if(d<0)d=-d; J+=(d-J)/16} prev=t} END{if(NR>1) printf("%.6f", J); else print "NA"}')

# perda C2 (por seq)
LOSS=$(awk '{seq=$1; if(NR==1){prev=seq; next} diff=seq-prev; if(diff<0){diff+=256} if(diff>1){lost+=diff-1} prev=seq} END{if(NR>0) printf("%d", lost); else print "NA"}' "$OUTDIR/c2_owd.tsv")
PKT=$(awk 'END{print NR}' "$OUTDIR/c2_owd.tsv")
LOSSRATE=$(awk -v L="$LOSS" -v P="$PKT" 'BEGIN{if(P+L>0) printf("%.3f", (L*100.0)/(P+L)); else print "NA"}')

# RTP "sanity" (pega primeira linha com jitter/perda agregada)
RTP_SUM=$(awk 'NR==1{print}' "$OUTDIR/rtp_streams.txt" 2>/dev/null || true)

# cria relatório
cat > "$OUTDIR/report.md" <<EOF
# KPI Report

## C2 (MAVLink/UDP 14550)
- OWD mean: ${MEAN}s
- OWD p95:  ${P95}s
- OWD p99:  ${P99}s
- Jitter (RFC3550-like): ${JIT}s
- Loss: ${LOSS} packets (on ${PKT} matched), rate ≈ ${LOSSRATE}%

## RTP (gcs -> summary)
\`\`\`
${RTP_SUM}
\`\`\`

Arquivos:
- c2_owd.tsv (seq, owd_s)
- rtp_streams.txt (tshark rtp summary)
EOF

echo "[OK] Relatório em $OUTDIR/report.md"
