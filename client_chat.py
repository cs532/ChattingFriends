# client_chat.py

import sys
import socket
import threading
from secret_sharing import *
from mass_encrypt import *

# define globals
key = 0
debug = 1


def debug_print(words):
    if debug != 0:
        print(str(words))


def enc_send(plaintext,sock1, secret):
    cipher_text = mass_encrypt(plaintext, secret)
#    print(plaintext)
#    print(cipher_text)
#    debug_print('sending {!r}'.format(cipher_text))
    sock1.sendall(cipher_text.encode('utf-8'))


def dec_recv(cipher_text,secret):
    plain_text = mass_decrypt(cipher_text,secret)
    return plain_text


def establish_secret_comm_chain(sock1):
    global key
    secret = gen_private_key()
    A = gen_public_key(secret)
    debug_print(secret)
    debug_print(A)
    # Send data
    debug_print("sending A:")
    sock.sendall(str(A).encode('utf-8'))
    data1 = sock1.recv(4096)
    debug_print("data:")
    data1 = data1.decode('utf-8')
    debug_print(data1)
    key = establish_secret(int(data1), secret)
    debug_print("key is " + str(key))
    return key


def recv_thread(sock1, secret):
    recv_msg = ''
    while recv_msg != 'close':
        recv_msg = sock1.recv(4096).decode('utf-8')
        debug_print(recv_msg)
        pltxt = dec_recv(recv_msg, secret)


if __name__ == "__main__":
    
    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the port where the server is listening
    server_address = ('localhost', 10002)
    print('connecting to {} port {}'.format(*server_address))
    sock.connect(server_address)

    try:
        key = establish_secret_comm_chain(sock)
        communication_thread = threading.Thread(target=recv_thread, args=(sock, key))
        communication_thread.start()
        data = ' '

        while data != 'close':

            data = input("enter text:\n")
            debug_print('coding {!r}'.format(data))
            enc_send(data, sock, key)

    finally:
        print('closing socket')
        sock.close()
