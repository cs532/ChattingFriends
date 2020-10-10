# server_chat.py

import sys
import socket
import threading
from secret_sharing import *
from mass_encrypt import *


# Define globals
key = 0
debug = 1
IO_queue = []
sendq = []


def debug_print(words):
    if debug != 0:
        print(str(words))


def setup_sendq(num_of_port):

    global sendq

    for k in range(len(num_of_port)):
        sendq.append([k, num_of_port[k], "home"])

    print(sendq)


def dec_recv(cipher_text, secret):
    plain_text = mass_decrypt(cipher_text, secret)
    return plain_text


def establish_secret_comm_chain(sock):
    secret = gen_private_key()
    B = gen_public_key(secret)
    debug_print(B)
    # Wait for a connection
    debug_print('waiting for a connection')
    connection, cl_add = sock.accept()
    data = connection.recv(4096).decode('utf-8')
    debug_print("recv data:")
    debug_print(data)
    key = establish_secret(int(data),secret)
    connection.sendall(str(B).encode('utf-8'))
    debug_print("key is " + str(key))
    debug_print("")
    return connection, key, cl_add


def comm_thread(port,ind):
    # Create a TCP/IP socket
    global sendq
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to the port
    server_address = ('localhost', port)
    print('starting up on {} port {}'.format(*server_address))
    sock.bind(server_address)
    # Listen for incoming connections
    sock.listen(1)

    conn, key1, client_address = establish_secret_comm_chain(sock)
    send_thread1 = threading.Thread(target=send_thread, args=(conn, sendq, key1))
    send_thread1.start()

    try:
        debug_print('connection from ' + str(client_address))
        # Receive the data in small chunks and retransmit it
        while True:
            data = conn.recv(4096).decode('utf-8')
            plt = dec_recv(data, key)
            debug_print('recv {!r}'.format(data))
            debug_print('decoded: {!r}'.format(plt))
            splitmsg = plt.split()
            first_token = str(splitmsg[0])
            debug_print(first_token)

            if first_token[0:5] == "#HELP":
                sendq.append(first_token)


    finally:
        # Clean up the connection
        conn.close()


def send_thread(con,send_q, key, index):
    debug_print("send thread initiated")
    while True:
        if 0 < len(send_q):
            response = str(send_q[0])
            mesg = "sending response to request " + response
            debug_print(mesg)
            send_q.pop()


if __name__ == "__main__":

    # TODO: main thread becomes IO thread/reconnect thread.
    # TODO: come up with a way of dealing with sender queues

    ports = [10000, 10002]
    setup_sendq(ports)
    i, num_of_ports = 0, 2  # we want
    while i < num_of_ports:
        communication_thread = threading.Thread(target=comm_thread, args=(int(ports[i]),i))
        communication_thread.start()
        print("port " + str(ports[i]) + " created")
        i += 1

    while True:
        if 0 < len(IO_queue):
            new_msg_for_storage = IO_queue[0]


