# UCV SDN Testbed for UAS C2/ISR KPI Experiments

This repository provides a **Mininet + OVS** emulation of a **UAV Control Vehicle (UCV)** that prioritizes **C2 (MAVLink/UDP 14550)** over **ISR best-effort** traffic, with a **Ryu** controller and an **event scheduler** that injects controlled impairments (delay/jitter/loss/rate) via `tc netem`.

- **Control plane:** Ryu (`controller.py`) programs OVS (OpenFlow 1.3), classifies C2 to **Queue 0**, ISR to **Queue 1**, and can shift QoS min/max between **baseline** and **degraded** profiles.
- **Data plane:** Mininet topology `gcs — s1(OVS) — uav` with HTB queues per port.
- **Events:** `events.yaml` applies/clears netem on OVS ports over time.
- **KPIs:** `tshark` pcaps + scripts to extract OWD/jitter for C2 and loss/jitter for RTP (if used).


Control Plane (decisions)
+-----------------------+        OpenFlow TCP/6653        +-----------+
|   Ryu (UcvController) | <-----------------------------> |  OVS s1   |
+-----------------------+                                  +-----------+


Data Plane (mission packets)
+-----+      link1       +-----------+       link2       +-----+
| GCS | <--------------> |   OVS s1  | <--------------> | UAV |
+-----+                   +-----------+                   +-----+
    ^                         ^    ^                          ^
    |                         |    |                          |
    |         (per-port queues)    |        (per-port queues) |
    |              s1-eth-GCS      |             s1-eth-UAV   |
    +------------------------------+--------------------------+

Notes:
- “per-port queues” = HTB queues (Queue 0 = C2 priority, Queue 1 = ISR).
- Interface names (e.g., s1-eth-GCS / s1-eth-UAV) may be s1-eth2 / s1-eth3 depending on the run.


## 0) Topology at a glance

```
     (host)                    (Mininet namespace)
```

\[root-eth0 10.0.0.254] <---> \[ s1 (OVS) ] <---> \[gcs 10.0.0.1]
\|               \[uav 10.0.0.2]
|\_ s1-eth1: root-eth0
|\_ s1-eth2: gcs
|\_ s1-eth3: uav
Queues (HTB) per user port:
Queue 0: C2 (priority, min-rate guaranteed)
Queue 1: ISR (best-effort)

````

## 1) Requirements

**On the host (Ubuntu 22.04+):**
```bash
# Base packages
sudo apt-get update
sudo apt-get install -y mininet openvswitch-switch iproute2 python3-venv \
                        tshark xterm

# (Recommended) Ryu in Python 3.9 virtualenv (Ryu is happiest on 3.9)
python3.9 -m venv ~/venv-ryu39
source ~/venv-ryu39/bin/activate
pip install --upgrade pip setuptools wheel
# Ryu build known-good combo for Py3.9
pip install "ryu @ git+https://github.com/faucetsdn/ryu@master" \
            eventlet==0.31.1 packaging==20.9 tinyrpc==1.0.4
````

**Optional (for RTP tests):**

```bash
sudo apt-get install -y gstreamer1.0-tools gstreamer1.0-plugins-{base,good,ugly}
```

**QGroundControl:** install the AppImage or Flatpak on the **host** (we recommend running QGC on the host instead of inside Mininet).


## 2) Start the testbed (three terminals)

> Replace paths if your venv name differs.

### Terminal A — **Ryu controller (host)**

```bash
source ~/venv-ryu39/bin/activate
# (Optional) free the OF port if reused
sudo fuser -k 6653/tcp
# Run controller
~/venv-ryu39/bin/ryu-manager --ofp-tcp-listen-port 6653 controller.py --verbose
```

**What it does:** starts the SDN control plane. It will learn MACs/ports, classify C2 (UDP/14550 or DSCP EF=46) to **Queue 0**, and run the policy loop (baseline↔degraded) based on events.


### Terminal B — **Mininet + OVS (host)**

```bash
# Allow root namespaces to open X apps (xterm) if needed
xhost +SI:localuser:root

# Launch the UCV topology with CLI and the event scheduler
sudo python3 ucv.py --ctrl_port 6653 --start_cli --events events.yaml
#sudo python3 ucv.py --ctrl_port 6653 --start_cli --events events_congest.yaml
```

**What it does:**

* creates `gcs`, `uav`, switch `s1` (OVS), and a **host root port** `root-eth0` on the bridge.
* configures **HTB QoS/Queues** on `s1-eth2` (gcs) and `s1-eth3` (uav).
* marks **DSCP EF(46)** for UDP/14550 on both hosts (C2).
* applies **OpenFlow13** on the bridge.
* starts the **event scheduler** per `events.yaml`.

After the topology comes up, in the **Mininet CLI** (`mininet>`), **verify the host-root interface**:

```bash
mininet> sh ip -br addr show root-eth0
# If needed, force the IP:
mininet> sh ip addr flush dev root-eth0
mininet> sh ip addr add 10.0.0.254/24 dev root-eth0
mininet> sh ip link set root-eth0 up
```

> **Why 10.0.0.254?** We connect the host (where QGC runs) to the Mininet L2 domain through `root-eth0` so all QGC↔PX4 traffic still traverses **s1/OVS** (and its queues).

---

### Terminal C — **Proactive OpenFlow (host)**

Install two **proactive flows** so the very first C2 packets already have a path and priority (Queue 0):

```bash
# C2 UDP → Queue 0 + L2 bridging (both dst and src 14550)
sudo ovs-ofctl -O OpenFlow13 add-flow s1 "priority=60,udp,tp_dst=14550,actions=set_queue:0,NORMAL"
sudo ovs-ofctl -O OpenFlow13 add-flow s1 "priority=60,udp,tp_src=14550,actions=set_queue:0,NORMAL"

# Also ensure ARP/ICMP forwarding (if not already installed by the controller)
sudo ovs-ofctl -O OpenFlow13 add-flow s1 "priority=50,arp,actions=NORMAL"
sudo ovs-ofctl -O OpenFlow13 add-flow s1 "priority=40,icmp,actions=NORMAL"
```

**What it does:** guarantees immediate L2 path for MAVLink and prioritizes it from the first packet. The controller will still install learned flows for finer matches.

**Check:**

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1 | egrep 'tp_(src|dst)=14550|arp|icmp|set_queue'
```

---

## 3) PX4 + QGC (C2 “real”)

### 3.1 Start PX4 SITL on **uav** (in Mininet)

From the **Mininet CLI**:

```bash
mininet> xterm uav
```

In the `uav` xterm:

```bash
cd ~/PX4-Autopilot
# First time: git submodule update --init --recursive
make px4_sitl jmavsim           # or HEADLESS=1 make px4_sitl jmavsim
```

Configure MAVLink to send to the **host** IP on `root-eth0`:
Inside the PX4 console (`pxh>`):

```text
mavlink stop-all
mavlink start -x -u 14550 -r 50 -t 10.0.0.254 -p
mavlink status   # partner: 10.0.0.254, tx increasing
```

### 3.2 Start **QGroundControl** on the **host**

Run QGC (AppImage or Flatpak) normally on the host. It should auto-detect the UDP stream on 14550.
Check the host is listening:

```bash
ss -lun | grep 14550
# and observe packets arriving:
sudo tcpdump -ni root-eth0 udp port 14550
```

> If QGC doesn’t auto-connect, add a **UDP Comm Link** listening on port **14550**.

---

## 4) Optional: Synthetic ISR traffic and packet capture (inside Mininet)

On the **Mininet CLI** (`mininet>`):

```bash
# Start iperf servers (avoid “did not receive ack” warnings)
gcs iperf -u -s -p 14550 &
uav iperf -u -s -p 5004  &

# Start captures (pcap files will be on each host’s /tmp)
gcs tshark -i gcs-eth0 -f "udp port 14550 or udp port 5004" -w /tmp/gcs.pcap &
uav tshark -i uav-eth0 -f "udp port 14550 or udp port 5004" -w /tmp/uav.pcap &

# Generate traffic
#   C2 (Queue 0): UAV -> GCS
uav iperf -u -b 300k -c 10.0.0.1 -p 14550 &
#   ISR (Queue 1): GCS -> UAV
gcs iperf -u -b 8M   -c 10.0.0.2 -p 5004  &
```

Stop and exit when done:

```bash
gcs pkill tshark ; uav pkill tshark
gcs pkill iperf  ; uav pkill iperf
exit   # leave Mininet CLI
```

---

## 5) KPI extraction

**On the host (repo root):**

```bash
# Copy and analyze (pcaps must exist: /tmp/gcs.pcap and /tmp/uav.pcap)
./scripts/analyze.sh /tmp/gcs.pcap /tmp/uav.pcap
# Output: ./logs/run_YYYYMMDD_HHMMSS/report.md
```

**Notes:**

* If your ISR is **RTP** (e.g., GStreamer), `tshark` will parse `-z rtp,streams`.
  If you used generic UDP (iperf), force **Decode As RTP** when capturing:

  ```bash
  gcs tshark -i gcs-eth0 -d udp.port==5004,rtp -w /tmp/gcs.pcap &
  ```
* If your `tshark` lacks the MAVLink dissector, the script falls back to **payload-based correlation** to compute C2 OWD/jitter.

---

## 6) Event scheduler

`events.yaml` controls **when** and **where** impairments are applied. Example:

```yaml
- at: 10.0   # seconds
  iface: s1-eth3   # toward UAV
  netem: { delay_ms: 80, jitter_ms: 20, loss_pct: 2, rate_mbit: 5 }
- at: 40.0
  iface: s1-eth3
  clear: true
- at: 60.0
  iface: s1-eth2   # toward GCS
  netem: { delay_ms: 120, jitter_ms: 30, loss_pct: 1 }
- at: 90.0
  iface: s1-eth2
  clear: true
```

**What happens:** the script applies `tc qdisc netem` to the selected interface at the requested times, then clears it. The controller’s policy loop sees “degraded” and tightens Queue 0 min/max accordingly.

---

## 7) Useful runtime checks

**Show OVS ports/ids (host):**

```bash
sudo ovs-ofctl -O OpenFlow13 show s1
```

**QoS/Queues per port (host, with topology UP):**

```bash
sudo ovs-appctl qos/show s1
```

**Flows that set queues or match 14550 (host):**

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1 | egrep 'set_queue|14550'
```

**Active netem (host):**

```bash
tc qdisc show dev s1-eth2
tc qdisc show dev s1-eth3
```

---

## 8) Troubleshooting

* **QGC won’t run inside Mininet**: it refuses to run as root. Prefer **QGC on host** (this README’s approach).
* **`root-eth0` missing:** only exists while Mininet is running. Start Mininet first; verify with `ip -br addr show root-eth0`.
* **Ping works but MAVLink doesn’t:** add the **proactive flows** (Section 2, Terminal C). Without them, the first UDP/14550 packets may not get a forwarding path immediately.
* **No RTP stats with iperf:** iperf is UDP generic. Use GStreamer to produce **RTP/RTCP**, or force “Decode As RTP” when capturing.
* **Do not run while topology is up:**

  ```bash
  sudo ovs-vsctl -- --all destroy QoS -- --all destroy Queue
  ```

  (This deletes QoS/Queue objects; the controller can’t adjust anything afterward.)

---

## 9) Clean up

```bash
# From Mininet CLI:
exit
# On host, if you need to reset QoS/Queues (only after exiting Mininet):
sudo ovs-vsctl -- --all destroy QoS -- --all destroy Queue
```

---

## 10) Next steps

* Drive the policy by **measured KPIs** (e.g., C2 OWD p95) instead of “netem present”.
* Add **RTP ISR** pipelines (UAV→GCS) for realistic video KPIs.
* Scale to **multi-UE** and add a second path for **fast failover/steering**.

```
```