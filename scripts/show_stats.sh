#!/usr/bin/env bash
set -eu
( set -o pipefail ) 2>/dev/null || true

# Só roda se a bridge existir
if ! sudo ovs-vsctl br-exists s1 2>/dev/null; then
  echo "s1 não existe (Mininet encerrado?). Suba a topologia e rode de novo."
  exit 1
fi

echo "== OVS Ports =="
sudo ovs-ofctl -O OpenFlow13 dump-ports s1 | sed -n '1,120p'

echo
echo "== QoS + Queues por porta (qos/show) =="
sudo ovs-appctl qos/show s1

echo
echo "== Objetos Queue (min/max por UUID) =="
sudo ovs-vsctl list queue | sed -n '1,200p'

echo
echo "== tc qdisc (s1-eth1/s1-eth2) =="
tc qdisc show dev s1-eth1 || true
tc qdisc show dev s1-eth2 || true
