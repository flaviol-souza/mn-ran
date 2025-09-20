- forneça um codigo shell que realize a limpeza anteriores
- o passo 3 é desnecessário, pois foi encorporado ao codigo da ucv.py

[Terminal 1]
sudo mn --clean
sudo python3 ucv.py --ctrl_port 6653 --start_cli --video_relay --events events/events_outage.yaml 

[Terminal 2]
sudo -E ~/venv-ryu39/bin/ryu-manager --ofp-tcp-listen-port 6653 controller.py --verbose

[Terminal 1 - Mininet CLI]
xterm uav

[Terminal 3 - Mininet CLI (UAV)]
cd <path-px4>
make px4_sitl gazebo-classic_typhoon_h480
mavlink stop-all
mavlink start -x -u 14550 -r 50 -t 10.0.0.254 -p

[Terminal 1 - Mininet CLI]
exit

[Terminal 1]
sudo ./scripts/transfer.sh /tmp/runs logs/events_outage-1