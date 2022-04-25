import socket
import sys
import json
import struct

def send_msg(sock, msg):
    # Prefix each message with a 4-byte length (network byte order)
    msg = struct.pack('>I', len(msg)) + msg
    sock.sendall(msg)

json_file = "packets.json"
f = open(json_file, "rb")
data = f.read()

# jsonResult = {"first":"You're", "second":"Awsome!"}
# jsonResult = json.dumps(jsonResult)

try:
    sock = socket.socket()
except socket.error as err:
    print("Socket error")

#port = 1500
# address = "172.16.7.4"
port = 8598
address = "128.105.145.163"

try:
    print("ok")
    sock.connect((address, port))
    # sock.sendall(data)
    send_msg(sock, data)
    print("was sent!")
except socket.gaierror:

    print('There an error resolving the host')

    sys.exit()

sock.close()
