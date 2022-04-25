#intel_script.py [IP]
#Joe Catudal
#CS740 Spring 2022
#

import json
import sys
import os
import time
from collections import Counter
import http.client
import socket

#GLOBALS
blockedIPs = {} # SrcIP and Timestamp
packetTrack = []
expireTrack = 60 #How long before removing packets in tracking (seconds)

#RULE VARIABLES
MAX_DstIP   = 2
MAX_DstPort = 3
MAX_Flows   = 10
MAX_TimeLive= 61 #TimeLive should be longer than expireTrack

expireBlock = 30 #How long before removing blocked IPs
fwController = sys.argv[1]
#fwController = "155.98.38.240" #Hardcoded - Switch out
mbPort = 1500

#PACKET CLASS
class Packet:
    def __init__(self, proto, ts, srcIP, srcPort, dstIP, dstPort):
        self.protocol = proto
        self.timestamp = ts
        self.srcIP = srcIP
        self.srcPort = srcPort
        self.dstIP = dstIP
        self.dstPort = dstPort
        
    def compare(self, compPkt):
        if (self.protocol != compPkt.protocol):
            return False
        elif (self.timestamp != compPkt.timestamp):
            return False
        elif (self.srcIP != compPkt.srcIP):
            return False
        elif (self.srcPort != compPkt.srcPort):
            return False
        elif (self.dstIP != compPkt.dstIP):
            return False
        elif (self.dstPort != compPkt.dstPort):
            return False
        return True

#READ IN FILE
def readfile(filename):
    packetlist = []
    f = open(filename)
    data = json.load(f)
    for i in data: #For each packet in json
        #print(i) 
        proto = data[i]["Protocol"]
        ts = data[i]["Timestamp"]
        SrcIP = data[i]["SrcIP"]
        SrcPort = data[i]["SrcPort"]
        DstIP = data[i]["DstIP"]
        DstPort = data[i]["DstPort"]
        packetlist.append(Packet(proto, ts, SrcIP, SrcPort, DstIP, DstPort))
        
        #for b in data[i]:
        #    print(data[i][b]) #Resulting Values
    f.close()
    return packetlist

#READ IN SOCKET
def listenport(port):
    packetlist = []
    sock = socket.socket()
    sock.bind(('', port))
    sock.listen(1)
    Print("Listening...")
    c, addr = sock.accept()
    j = c.recv(8192)
    c.close()
    try:
        data = jsonData(j)
        for i in data: #For each packet in json
            proto = data[i]["Protocol"]
            ts = data[i]["Timestamp"]
            SrcIP = data[i]["SrcIP"]
            SrcPort = data[i]["SrcPort"]
            DstIP = data[i]["DstIP"]
            DstPort = data[i]["DstPort"]
            packetlist.append(Packet(proto, ts, SrcIP, SrcPort, DstIP, DstPort))
    except:
        packetlist = []
    return packetlist


#Forever Loop - Read Stream's Packets
print("Ready for Action...")
newpackets = []

while True:
    newpackets = listenport(mbPort)
    if (len(newpackets) == 0):
        continue

    print("-START-")
    timepoint = time.time()

    #packetTrack.append(newpackets[0]) #For trial!
    print("Time: " + str(timepoint))
    print("Packets Received: " + str(len(newpackets)))

    #Remove any new packets that are blocked
    for badIP in blockedIPs:
        f_packets = list(filter(lambda pkt: pkt.srcIP != badIP, newpackets))
    print("After blocked filter: " + str(len(f_packets)))

    #Remove any new packets that are identical to those in the list
    for existing in packetTrack:
        f_packets = list(filter(lambda pkt: not pkt.compare(existing), f_packets))
    print("After compare filter: " + str(len(f_packets)))

    #Load new packets into tracker    
    packetTrack.extend(f_packets)
    print("Tracked Flows: " + str(len(packetTrack)))


    #Create a Source Packet Count
    allSourceIPs = []
            
    #Create an eval dict
    evalDict = {} # {Source IP: [ {Dest IP: [Dest Port] } ] }
    for packet in packetTrack:
        sIP = packet.srcIP
        dIP = packet.dstIP
        dPort = packet.dstPort
        
        allSourceIPs.append(sIP)
        
        if sIP not in evalDict.keys():
            evalDict[sIP] = {dIP: [dPort]}
            #print("Added: " + str(evalDict[sIP]))
        elif dIP not in evalDict[sIP].keys():
            evalDict[sIP][dIP] = [dPort]
        elif dPort not in evalDict[sIP][dIP]:
            evalDict[sIP][dIP].append(dPort)

    CountSourceIPs = Counter(allSourceIPs)        

    newBlocks = [] # what new IPs are we blocking

    # Create Blocks by Rules

    for s in evalDict:
        # RULE 1: Too Many DST IPs per SRC IP
        if (len(evalDict[s]) > MAX_DstIP):
            newBlocks.append(s)
            print("Exceeded MAX_DstIP: " + s)
        for d in evalDict[s]:
            # RULE 2: Too Many DST PORTS per SRC IP
            if (len(evalDict[s][d]) > MAX_DstPort):
                newBlocks.append(s)
                print("Exceeded MAX_DstPort: " + s)

    # RULE 3: Too many Flows
    for s, count in CountSourceIPs.items():
        if (count > MAX_Flows):
            newBlocks.append(s)
            print("Exceeded MAX_Flows: " + s)

    # RULE 4: Flow too long-lived
    for s in newpackets:
        if (s.timestamp > timepoint-MAX_TimeLive):
            newBlocks.append(s)
            print("Exceeded MAX_TimeLive: " + s)

    # Uniquify Blocks
    newBlocks = list(set(newBlocks))
            
    print("New Blocks:")
    print(newBlocks)

    #Issue new block commands
    for ip in newBlocks:
        conn = http.client.HTTPSConnection(fwController, 8080)
        payload = "{\n  \"ip\": \"" + ip +"\",\n}"
        headers = {
          'Content-Type': 'text/plain'
        }
        conn.request("POST", "/wm/ipblacklist/ipblacklist/json", payload, headers)
        res = conn.getresponse()
        data = res.read()
        print(data.decode("utf-8"))
        
    #Update Blocked List
    for ip in newBlocks:
        blockedIPs.update({ip, timepoint})

    #Time-based cleanup
    #Unblock IPs longer than expire time
    for ip, ts in blockedIPs.items():
        if (ts + expireBlock > timepoint):
            conn = http.client.HTTPSConnection(fwController, 8080)
            payload = "{\n  \"ip\": \"" + ip +"\",\n}"
            headers = {
              'Content-Type': 'text/plain'
            }
            conn.request("DELETE", "/wm/ipblacklist/ipblacklist/json", payload, headers)
            res = conn.getresponse()
            data = res.read()
            print(data.decode("utf-8"))
    #Remove unblocked IPs from list
    blockedIPs = {ip:ts for ip, ts in blockedIPs.items() if (ts + expireBlock > timepoint)}
    print("Blocked IPs:")
    print(blockedIPs)

    #Remove any packets that are older than expireTrack seconds
    for packet in packetTrack:
        packetTrack = list(filter(lambda pkt: pkt.timestamp > timepoint-expireTrack , packetTrack))
    print("Flows Tracked: " + str(len(packetTrack)))
    print("--END--")
