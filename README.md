ryu-manager controller_ryu.py --verbose
sudo python3 ucv_mininet.py --start_cli --events events.yaml


sudo fuser -k 6653/tcp
~/venv-ryu39/bin/ryu-manager --ofp-tcp-listen-port 6653 controller.py --verbose
sudo python3 ucv.py --ctrl_port 6653 --start_cli --events events.yaml


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
