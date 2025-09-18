#!/usr/bin/env bash
# KPIs em tempo real para fechar o loop
# Requisitos: tcpdump, awk

C2_IF="root-eth0"     # caminho C2 (UAV->GCS no host/UCV)
VID_IF="root-eth1"    # caminho Vídeo (UAV->GCS no host/UCV)
WINDOW=5              # janela em segundos (ajuste conforme seu gosto)
EXPECTED_PPS=50       # MAVLink ~50Hz (ajuste se usar outra taxa)

set -euo pipefail

echo "ts_epoch	c2_loss_pct	c2_jitter_ms	video_kbps" | tee /tmp/kpi_state.tsv

while true; do
  TS=$(date +%s)

  # --- C2: perda e jitter ---
  # Perda: conta pacotes em WINDOW e compara com EXPECTED_PPS*WINDOW
  C2_PKTS=$(timeout "${WINDOW}s" tcpdump -tt -n -i "$C2_IF" udp port 14550 -c 999999 2>/dev/null | wc -l)
  EXP_TOTAL=$((EXPECTED_PPS * WINDOW))
  if [ "$EXP_TOTAL" -gt 0 ]; then
    LOSS=$(awk -v got="$C2_PKTS" -v exp="$EXP_TOTAL" 'BEGIN{p=(100.0*(exp-got))/exp; if(p<0)p=0; printf("%.2f",p)}')
  else
    LOSS="0.00"
  fi

  # Jitter aproximado: média das diferenças inter-chegada
  JITTER=$(timeout "${WINDOW}s" tcpdump -tt -n -i "$C2_IF" udp port 14550 -c 999999 2>/dev/null \
    | awk 'NR>1{d=$1-last; if(d>=0){sum+=d; n++} last=$1} NR==1{last=$1} END{if(n>0) printf("%.1f", (sum/n)*1000); else print "0.0"}')

  # --- Vídeo: bitrate KBPS ---
  # Soma dos comprimentos UDP em WINDOW (kbps)
  BYTES=$(timeout "${WINDOW}s" tcpdump -n -i "$VID_IF" udp port 5600 -vv -c 999999 2>/dev/null \
    | awk '/length/ {for(i=1;i<=NF;i++) if($i=="length"){s+=$(i+1)}} END{print s+0}')
  KBPS=$(awk -v b="$BYTES" -v w="$WINDOW" 'BEGIN{printf("%d", (b*8)/(w*1000))}')

  echo -e "${TS}\t${LOSS}\t${JITTER}\t${KBPS}" | tee /tmp/kpi_state.tsv

  # dorme um tiquinho para não “colar” janelas
  sleep 0.5
done
