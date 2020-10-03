#socket_echo_server.py
import sys
import socket
from secret_sharing import *

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to the port
server_address = ('localhost', 10000)
print('starting up on {} port {}'.format(*server_address))
sock.bind(server_address)

#diffie constants
key = 0

# Listen for incoming connections
sock.listen(1)


while True:
    # Wait for a connection
    secret = gen_private_key()
    B = gen_public_key(secret)
    print(B)
    print('waiting for a connection')
    connection, client_address = sock.accept()
    
    data = connection.recv(4096)
    print("recv data:")
    print(data)
    key = establish_secret(int(data),secret)
    connection.sendall(str(B))
    print("key is " + str(key))
    print("")
    
    try:
        print('connection from', client_address)
        # Receive the data in small chunks and retransmit it
        while True:
            data = input()
            print('sending {!r}'.format(message))
            connection.sendall(data)

    finally:
        # Clean up the connection
        connection.close()

