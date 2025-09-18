- forneça um codigo shell que realize a limpeza anteriores
- o passo 3 é desnecessário, pois foi encorporado ao codigo da ucv.py

[Terminal 1]
./scripts/cleanup.sh

[Terminal 2]
~/venv-ryu39/bin/ryu-manager --ofp-tcp-listen-port 6653 controller.py --verbose

[Terminal 3]
xhost +SI:localuser:root
xhost +SI:localuser:$USER
sudo python3 ucv.py --ctrl_port 6653 --start_cli --video_relay --events events/events_latency_jitter.yaml 

[Terminal 3 - Mininet CLI]
xterm uav

[Terminal 3 - Mininet CLI (UAV)]
export DISPLAY=:0
export QT_X11_NO_MITSHM=1

make px4_sitl jmavsim   
make px4_sitl gazebo-classic
make px4_sitl gazebo-classic_typhoon_h480

mavlink stop-all

[Terminal 3 - Mininet CLI]
uav tshark -i uav-eth0 -f "udp port 14550" -w /tmp/tx_uplink.pcap &

[Terminal 1]
sudo tshark -i s1-eth2 -f "udp port 14550" -w /tmp/rx_uplink.pcap &

[Terminal 3 - Mininet CLI]
uav tshark -i uav-eth0 -f "udp port 14550" -w /tmp/rx_downlink.pcap &

[Terminal 1]
sudo tshark -i root-eth0 -f "udp port 14550" -w /tmp/tx_downlink.pcap &

[Terminal 3 - Mininet CLI (UAV)]
mavlink start -x -u 14550 -r 50 -t 10.0.0.254 -p
# -x: cliente UDP
# -u 14550: porta destino
# -t 10.0.0.254: QGC/host bridge
# -r 50: rate (ajuste se quiser)
# -p: preferência para enviar parâmetros no startup

[Terminal 3 - Mininet CLI]
uav socat -d -d -u UDP4-RECV:5600,reuseaddr UDP4-SENDTO:10.1.0.254:5600

[Terminal 3 - Mininet CLI]
uav pkill tshark

[Terminal 1]
sudo pkill tshark
sudo ./scripts/analyze.sh /tmp/rx_uplink.pcap /tmp/tx_uplink.pcap
sudo ./scripts/analyze.sh /tmp/rx_downlink.pcap /tmp/tx_downlink.pcap
