#!/bin/bash
while true
do
echo "start!"
sleep 5
sudo tcpdump -G 1 -W 1 -w packets.pcap
sudo python3 to_json.py && sudo python3 sender.py
done
