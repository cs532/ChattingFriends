# chat_client.py
import sys
import socket
import threading
from secret_sharing import *
from mass_encrypt import *

# TODO: figure out best way to do IO for recv'd files from the server and storage for keyshards

# define globals
key = 0        # shared secret for client/server communication
debug = 0      # debug mode on if 1, off if 0
kill = 0       # global kill var


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
    global kill
    recv_msg = ''
    while recv_msg != '#CLOSE':
        recv_msg = sock1.recv(4096).decode('utf-8')
        debug_print("message recvd")
        if len(recv_msg) == 0:
            kill = 1
            sock1.close()
            sys.exit(0)
        debug_print(recv_msg)
        pltxt = dec_recv(recv_msg, secret)

        if pltxt == "#CLOSE":
            kill = 1
            sock1.close()
            sys.exit(0)

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
        print("\n Hi! Welcome to our chat service, Chatting Friends! If you need help with commands,\n"
              + " please type in #HELP for all possible commands. Thank you for being buddies!\n")

        data = ' '

        while True:
            data = input("enter text:\n")
            if kill == 1:
                sys.exit()
            if len(data) == 0:
                data = "#HELP"

            # GET_LOG needs a space at the end
            if data[0:8] == '#GET_LOG':
                if data[-1] != ' ':
                    data = data + ' '

            debug_print('coding {!r}'.format(data))
            enc_send(data, sock, key)
            if data == "#END":
                while kill != 1:
                    a = 1

                sys.exit()


    finally:
        print('closing socket')
        sock.close()
