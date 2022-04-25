import socket

sock = socket.socket()
print("Socket created ...")

port = 1500
sock.bind(('', port))
sock.listen(5)

print('socket is listening')

while True:
    c, addr = sock.accept()
    print('got connection from ')

    jsonReceived = c.recv(102400)
    print("Json received -->")
    print(jsonReceived.decode("utf-8"))

    c.close()