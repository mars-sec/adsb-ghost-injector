
import socket
s = socket.socket()
s.connect(('127.0.0.1', 30002))
while True:
    print(s.recv(4096).decode('ascii', errors='ignore'), end='')
    

