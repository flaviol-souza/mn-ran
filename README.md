ryu-manager controller_ryu.py --verbose
sudo python3 ucv_mininet.py --start_cli --events events.yaml

sudo DEBIAN_FRONTEND=noninteractive apt-get install -y tshark

### RUN
sudo fuser -k 6653/tcp
source ~/venv-ryu39/bin/activate
~/venv-ryu39/bin/ryu-manager --ofp-tcp-listen-port 6653 controller.py --verbose
sudo python3 ucv.py --ctrl_port 6653 --start_cli --events events.yaml

mininet> gcs tshark -i gcs-eth0 -f "udp port 14550 or udp port 5004" -w /tmp/gcs.pcap &
mininet> uav tshark -i uav-eth0 -f "udp port 14550 or udp port 5004" -w /tmp/uav.pcap &


mininet> uav iperf -u -b 300k -c 10.0.0.1 -p 14550 &
mininet> gcs iperf -u -b 8M   -c 10.0.0.2 -p 5004 &


sudo ovs-vsctl -- --all destroy QoS -- --all destroy Queue




Control Plane (decisões)
 [Ryu (UcvController)]  <--- OpenFlow TCP/6653 --->  [OVS s1]

Data Plane (pacotes da missão)
 [GCS] <-- link1 --> [OVS s1] <-- link2 --> [UAV]
             ^             ^ 
             |             |
       (filas por porta)   |   (filas por porta)
          s1-eth1          |       s1-eth2

Scheduler de Eventos (fora do datapath):
  aplica `tc netem` em s1-eth1/s1-eth2 (muda o "link")
---------------
gcs tshark -i gcs-eth0 -f "udp port 14550 or udp port 5004" -w /tmp/gcs.pcap &
uav tshark -i uav-eth0 -f "udp port 14550 or udp port 5004" -w /tmp/uav.pcap &
uav iperf -u -b 300k -c 10.0.0.1 -p 14550 &
gcs iperf -u -b 8M   -c 10.0.0.2 -p 5004 &