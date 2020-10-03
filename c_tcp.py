#socket_echo_client.py
import socket
import sys
import numpy as np
from secret_sharing import *


    
# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect the socket to the port where the server is listening
server_address = ('localhost', 10000)
print('connecting to {} port {}'.format(*server_address))
sock.connect(server_address)



try:
    secret = gen_private_key()
    A = gen_public_key(secret)
    print(secret)
    print(A)
    # Send data
    print("sending A:")
    sock.sendall(str(A))
    data = sock.recv(4096)
    print("data:")
    print(data)
    key = establish_secret(int(data),secret)
    print("key is " + str(key))
    message = ' '
    
    while message != 'close':
        
        message = input()
        print('sending {!r}'.format(message))
        sock.sendall(message.encode())
        
finally:
    print('closing socket')
    sock.close()
