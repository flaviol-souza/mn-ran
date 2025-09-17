#!/usr/bin/env bash
set -e

echo "[*] Limpando QoS/Queues do OVS..."
sudo ovs-vsctl -- --all destroy QoS -- --all destroy Queue || true

echo "[*] Limpando qdisc/netem (uplink/downlink)..."
sudo tc qdisc del dev s1-eth2 root 2>/dev/null || true
sudo tc qdisc del dev s1-eth3 root 2>/dev/null || true

echo "[*] (Opcional) Limpando flows s1..."
# sudo ovs-ofctl -O OpenFlow13 del-flows s1 || true

echo "[OK] Limpeza concluída."
