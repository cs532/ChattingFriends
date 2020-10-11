# chat_client.py
import sys
import socket
import threading
from secret_sharing import *
from mass_encrypt import *

# TODO: figure out best way to do IO for recv'd files from the server and storage for keyshards
# TODO: set a time out timer for ports already being listened on?

# define globals
key = 0        # shared secret for client/server communication
debug = 1      # debug mode on if 1, off if 0


#print if debug mode
def debug_print(words):
    if debug != 0:
        print(str(words))


def enc_send(plaintext, sock1, secret):
    cipher_text = mass_encrypt(plaintext, secret)
    sock1.sendall(cipher_text.encode('utf-8'))


def dec_recv(cipher_text, secret):
    plain_text = mass_decrypt(cipher_text, secret)
    return plain_text


def establish_secret_comm_chain(sock1):
    global key
    secret = gen_private_key()
    A = gen_public_key(secret)
    debug_print(secret)
    debug_print(A)
    # Send data
    debug_print("sending public message:")
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
        debug_print("message recvd")
        debug_print(recv_msg)
        pltxt = dec_recv(recv_msg, secret)
        print(pltxt)


if __name__ == "__main__":

    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    chosen_port = input("Enter a even port number between 2000 and 2024:\n")
    # Connect the socket to the port where the server is listening
    server_address = ('localhost', int(chosen_port))
    print('connecting to {} port {}'.format(*server_address))
    sock.connect(server_address)

    try:
        key = establish_secret_comm_chain(sock)
        rec_thread = threading.Thread(target=recv_thread, args=(sock, key))
        rec_thread.start()
        data = ' '

        while data != 'close':
            data = input("enter text:\n")
            debug_print('coding {!r}'.format(data))
            enc_send(data, sock, key)

    finally:
        print('closing socket')
        sock.close()
