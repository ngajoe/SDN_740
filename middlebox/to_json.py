import sys
import dpkt
import json
import socket
import time


time0 = time.perf_counter()
pcap_file = "packets.pcap"
json_file = "packets.json"

packet_dir = {}
count = -1

for ts, pkt in dpkt.pcap.Reader(open(pcap_file, 'rb')):
    count += 1
    packet = {}
    eth = dpkt.ethernet.Ethernet(pkt)
    ip = eth.data


    if(type(ip) is dpkt.ip.IP):
        tcp = ip.data
        if(type(tcp) is dpkt.tcp.TCP):

            packet['Protocol'] = "tcp"

            dstIP = socket.inet_ntoa(ip.dst)
            srcIP = socket.inet_ntoa(ip.src)

            packet['Timestamp'] = ts
            packet['SrcIP'] = srcIP
            packet["SrcPort"] = tcp.sport
            packet["DstIP"] = dstIP
            packet["DstPort"] = tcp.dport

            packet_dir["packet"+str(count)] = packet

        elif(type(tcp) is dpkt.udp.UDP):
            packet['Protocol'] = "udp"

            dstIP = socket.inet_ntoa(ip.dst)
            srcIP = socket.inet_ntoa(ip.src)

            packet['Timestamp'] = ts
            packet['SrcIP'] = srcIP
            packet["SrcPort"] = tcp.sport
            packet["DstIP"] = dstIP
            packet["DstPort"] = tcp.dport

            packet_dir["packet"+str(count)] = packet

        elif(type(tcp) is dpkt.icmp.ICMP):
            packet['Protocol'] = "icmp"
            dstIP = socket.inet_ntoa(ip.dst)
            srcIP = socket.inet_ntoa(ip.src)

            packet['Timestamp'] = ts
            packet['SrcIP'] = srcIP
            packet["SrcPort"] = "null"
            packet["DstIP"] = dstIP
            packet["DstPort"] = "null"

            packet_dir["packet"+str(count)] = packet


with open(json_file, 'w', encoding='utf-8') as f:
    json.dump(packet_dir, f, ensure_ascii=False, indent=4)


time1 = time.perf_counter()
print(time1 - time0)