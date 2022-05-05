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
import requests
import struct

#GLOBALS
blockedIPs = {} # SrcIP and Timestamp
packetTrack = []
expireTrack = 60 #How long before removing packets in tracking (seconds)
timepoint = time.time()

#RULE VARIABLES
MAX_DstIP   = 20
MAX_DstPort = 2
MAX_Flows   = 20
MAX_TimeLive= 61 #TimeLive should be longer than expireTrack
whitelist = ['128.105.146.150', '155.98.38.240', '10.10.10.10', '172.16.7.1', '108.69.65.69']
SG_IPs = ['10.10.10.10', '172.16.7.1']
SG_Ports = [5202,5203]

expireBlock = 30 #How long before removing blocked IPs
fwController = sys.argv[1]
#fwController = "155.98.38.240" #Hardcoded - Switch out
mbPort = 8598
sock = socket.socket()
sock.bind(('', mbPort))

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
        #elif (self.timestamp != compPkt.timestamp):
        #    return False
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
        #ts = data[i]["Timestamp"]
        ts = timepoint
        SrcIP = data[i]["SrcIP"]
        SrcPort = data[i]["SrcPort"]
        DstIP = data[i]["DstIP"]
        DstPort = data[i]["DstPort"]
        packetlist.append(Packet(proto, ts, SrcIP, SrcPort, DstIP, DstPort))
        
        #for b in data[i]:
        #    print(data[i][b]) #Resulting Values
    f.close()
    return packetlist

def send_msg(sock, msg):
    # Prefix each message with a 4-byte length (network byte order)
    msg = struct.pack('>I', len(msg)) + msg
    sock.sendall(msg)

def recv_msg(sock):
    # Read message length and unpack it into an integer
    raw_msglen = recvall(sock, 4)
    if not raw_msglen:
        return None
    msglen = struct.unpack('>I', raw_msglen)[0]
    # Read the message data
    return recvall(sock, msglen)

def recvall(sock, n):
    # Helper function to recv n bytes or return None if EOF is hit
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return data


#READ IN SOCKET
def listenport():
    packetlist = []
    sock.settimeout(15)
    sock.listen(1)
    print("Listening...")

    try:
        c, addr = sock.accept()
        #timepoint = time.time()
        j = recv_msg(c)
        c.close()
    except socket.timeout :
        print("Timout occured...")
        #sock.close()
        #timepoint = time.time()
        return packetlist

    data = json.loads(j.decode("utf-8"))
    for i in data: #For each packet in json
            proto = data[i]["Protocol"]
            #print(proto)
            #ts = data[i]["Timestamp"]
            ts = timepoint
            #print(ts)
            SrcIP = data[i]["SrcIP"]
            #print(SrcIP)
            SrcPort = data[i]["SrcPort"]
            #print(SrcPort)
            DstIP = data[i]["DstIP"]
            #print(DstIP)
            DstPort = data[i]["DstPort"]
            #print(DstPort)
            packetlist.append(Packet(proto, ts, SrcIP, SrcPort, DstIP, DstPort))
    '''
    try:
        data = jsonData(j.decode("utf-8"))
        for i in data: #For each packet in json
            print(i)
            proto = data[i]["Protocol"]
            ts = data[i]["Timestamp"]
            SrcIP = data[i]["SrcIP"]
            SrcPort = data[i]["SrcPort"]
            DstIP = data[i]["DstIP"]
            DstPort = data[i]["DstPort"]
            packetlist.append(Packet(proto, ts, SrcIP, SrcPort, DstIP, DstPort))
    except:
        packetlist = []
    '''
    return packetlist


#Forever Loop - Read Stream's Packets
print("Ready for Action...")
newpackets = []


while True:
    newpackets = listenport()
    if (len(newpackets) == 0):
        print("No Packets Received")

    print("-START-")
    timepoint = time.time()
    


    #packetTrack.append(newpackets[0])
    print("Time: " + str(timepoint))
    print("Packets Received: " + str(len(newpackets)))

    f_packets = []
    #Flow compression filter - Remove identicals
    #for pkt in newpackets:
    #    if len(f_packets) == 0:
    #        f_packets.append(pkt)
    #        continue
    #    else:
    #        isUnique = True
    #        for f_pkt in f_packets:
    #            if pkt.compare(f_pkt):
    #                isUnique = False
    #                break
    #        if(isUnique):
    #            f_packets.append(pkt)

        #newpackets = list(set(newpackets))
    #print("After flow compression: " + str(len(newpackets)))


    
    ################################################
    #SAFEGUARD RULE #1- SERVER RETURNS COMMUNICATION ON GOOD IPs
    #find the server's packets
    b_packets = []

    addme = list(filter(lambda pkt: (pkt.srcIP in SG_IPs) and (pkt.srcPort in SG_Ports), newpackets))
    if len(addme) > 0:
        b_packets.extend(addme)
        
        #print("safeIP:" + safeIP)
        #print(addme)
        #print("---")
    print("Server SAFEGUARD packets found: "+ str(len(b_packets)))
    #print(b_packets[0])


    
    #get the dstIPs from these packets, and remove them from tracking
    for b_pkt in b_packets:
        newpackets = list(filter(lambda n_pkt: n_pkt.srcIP != b_pkt.dstIP, newpackets))
    print("After SAFEGUARD filter: "+  str(len(newpackets)))


    #Whitelisted IPs
    for goodIP in whitelist:
        newpackets = list(filter(lambda pkt: pkt.srcIP != goodIP, newpackets))
    print("After whitelist filter: "+ str(len(f_packets)))

    f_packets = newpackets

    #Remove any new packets that are already blocked
    for badIP, ts in blockedIPs.items():
        f_packets = list(filter(lambda pkt: pkt.srcIP != badIP, f_packets))
    print("After blocked filter: " + str(len(f_packets)))

    #Remove any new packets that are identical to those in the list
    #for existing in packetTrack:
    #    f_packets = list(filter(lambda pkt: not pkt.compare(existing), f_packets))
    #print("After compare filter: " + str(len(f_packets)))

    #Remove old packets if newer identical packets have arrived
    for new_pkt in f_packets:
        packetTrack = list(filter(lambda old_pkt: not old_pkt.compare(new_pkt), packetTrack))
    #print("After compare filter: " + str(len(f_packets)))

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

    for s, t in evalDict.items():
        # RULE 1: Too Many DST IPs per SRC IP
        if (len(evalDict[s]) > MAX_DstIP):
            newBlocks.append(s)
            print("Exceeded MAX_DstIP: " + str(s))
        for d in evalDict[s]:
        # RULE 2: Too Many DST PORTS per SRC IP
            if (len(evalDict[s][d]) > MAX_DstPort):
                newBlocks.append(s)
                print("Exceeded MAX_DstPort: " + str(s))

    # RULE 3: Too many Flows (Packets) - Disabled due to filter distribution
    #for s, count in CountSourceIPs.items():
    #    if (count > MAX_Flows):
    #        newBlocks.append(s)
    #        print("Exceeded MAX_Flows: " + str(s))

    # RULE 3A: Flagged as SYNFLOOD
    for p in f_packets:
        if ((p.protocol == "synflood") and (p.srcIP not in newBlocks) ):
            newBlocks.append(p.srcIP)
            print("SYNflood Match: " + str(p.srcIP))

    # RULE 4: Flow too long-lived - Disabled due to filter distribution
    #for s in f_packets:
    #    if (s.timestamp < timepoint-MAX_TimeLive):
    #        newBlocks.append(s.srcIP)
    #        print("Exceeded MAX_TimeLive: " + str(s.srcIP))

    # Uniquify Blocks
    newBlocks = list(set(newBlocks))
            
    print("New Blocks:")
    print(newBlocks)

    #Issue new block commands
    for ip in newBlocks:

        #try:
        url = "http://" + fwController + ":8080/wm/ipblacklist/ipblacklist/json"
        payload = "{\n  \"ip\": \"" + ip +"\",\n}"
        headers = { 'Content-Type': 'text/plain' }
        response = requests.request("POST", url, headers=headers, data=payload)
        print(response.text)
        #except:
        #print("!!HTTP sending error!!")
        #print(url)
        #print(headers)
        #print(payload)

        '''
        conn = http.client.HTTPSConnection(fwController, 8080)
        payload = "{\n  \"ip\": \"" + ip +"\",\n}"
        headers = {
          'Content-Type': 'text/plain'
        }
        conn.request("POST", "/wm/ipblacklist/ipblacklist/json", payload, headers)
        res = conn.getresponse()
        data = res.read()
        print(data.decode("utf-8"))
        '''
        
    #Update Blocked List
    for badIP in newBlocks:
        blockedIPs[badIP] = timepoint
        packetTrack = list(filter(lambda pkt: pkt.srcIP != badIP, packetTrack))


    #Time-based cleanup
    #Unblock IPs longer than expire time
    for ip, ts in blockedIPs.items():
        if (ts + expireBlock < timepoint):

            #try:
            url = "http://" + fwController + ":8080/wm/ipblacklist/ipblacklist/json"
            payload = "{\n  \"ip\": \"" + ip +"\",\n}"
            headers = { 'Content-Type': 'text/plain' }
            response = requests.request("DELETE", url, headers=headers, data=payload)
            print(response.text)
            #except:
            #    print("!!HTTP sending error!!")
            #    print(url)
            #    print(headers)
            #    print(payload)

            '''
            conn = http.client.HTTPSConnection(fwController, 8080)
            payload = "{\n  \"ip\": \"" + ip +"\",\n}"
            headers = {
              'Content-Type': 'text/plain'
            }
            conn.request("DELETE", "/wm/ipblacklist/ipblacklist/json", payload, headers)
            res = conn.getresponse()
            data = res.read()
            print(data.decode("utf-8"))
            '''

    #Remove unblocked IPs from list
    blockedIPs = {ip:ts for ip, ts in blockedIPs.items() if (ts + expireBlock > timepoint)}
    print("Blocked IPs:")
    print(blockedIPs)

    #Remove any packets that are older than expireTrack seconds
    #for packet in packetTrack:
    packetTrack = list(filter(lambda pkt: pkt.timestamp+expireTrack > timepoint , packetTrack))
    print("Flows Tracked: " + str(len(packetTrack)))
    print("--END--")
