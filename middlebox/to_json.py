import sys
import dpkt
import json
import socket
import time
from collections import deque


time0 = time.perf_counter()
pcap_file = "synflood.pcap"
json_file = "packets2.json"

packet_dir = {}
count = -1

sf_list = {}
sf_report_list = list()
sf_output = ""

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

            # synflood
            if((tcp.flags & dpkt.tcp.TH_SYN) != 0):
                port = tcp.dport
                src = dpkt.socket.inet_ntoa(ip.src)
                srcAndPort = str(src) + str(port)
                if srcAndPort in sf_report_list:
                    continue
                if srcAndPort in sf_list:
                    while len(sf_list[srcAndPort]) > 0:
                        first_record = sf_list[srcAndPort][0]
                        if ts - first_record['ts'] >= 1:
                            sf_list[srcAndPort].popleft()
                        else:
                            break

                    sf_list[srcAndPort].append({'src': src, 'frame': count, 'port': port, 'ts': ts})

                    if len(sf_list[srcAndPort]) > 100:

                        packet['Protocol'] = "synflood"
                        packet['DstPort'] = port
                        packet['SrcIP'] = src
                        packet['DstIP'] = dpkt.socket.inet_ntoa(ip.dst)
                        packet['Timestamp'] = ts
                        packet['SrcPort'] = tcp.sport

                        packet_dir["packet"+str(count)] = packet

                        sf_report_list.append(srcAndPort)
                        sf_output += "SYN floods!\nSrc IP: " + src + "\nDst Port: " + str(port) + "\nPacket number: " + \
                                    str(sf_list[srcAndPort].popleft()['frame'])
                        for record in sf_list[srcAndPort]:
                            if record['src'] == src and record['port'] == port:
                                sf_output += ", " + str(record['frame'])
                        sf_output += "\n"

                else:
                    sf_list[srcAndPort] = deque([{'src': src, 'frame': count, 'port': port, 'ts': ts}])

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