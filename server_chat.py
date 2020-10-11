# chat_server.py

import sys
import socket
import threading
from secret_sharing import *
from mass_encrypt import *

# TODO: main thread becomes IO thread/reconnect thread. Figure out reconnection protocol.
# TODO: figure out best way to parse messages being recv'd.
# TODO: add rooms with keys.
# don't spend too much time on input validation

# Define globals
debug = 1               # debug mode on if 1, off if 0
IO_queue = []           # IO_queue for passing messages to IO thread
sendq = []              # sendq for sending message between recv threads, [index, port number] format
people = []             # people is used for storing information about people, i.e. names, connection number, room,
stop_pep8 = 8           # and if they are on/off line
rooms = [['home', 0]]   # list of rooms, [room name, Shamir secret key] format?
HELP_MSG = "Hello! Here are the current list of available functions:\n#HELP\n#NAME\n"


# debug utility functions
def debug_print(words):
    # if it is in debug mode (debug = 1), print the text
    if debug != 0:
        print(str(words))


# setup functions
def setup_sendq(num_of_port):

    global sendq, people

    for k in range(len(num_of_port)):
        sendq.append([])
        people.append([k, num_of_port[k], "home", str("default"+str(k)), 0])

    print(sendq)
    print(people)


# comm functions
def dec_recv(cipher_text, secret):
    # decrypt received message
    plain_text = mass_decrypt(cipher_text, secret)
    return plain_text


def enc_send(plaintext, sock1, secret):
    # encrypt message, then send
    print(plaintext)
    cipher_text = mass_encrypt(plaintext, secret)
    sock1.sendall(cipher_text.encode('utf-8'))


def send_to_room(room, name, mesg, ind):
    global people, sendq
    j = 0
    while j < len(people):  # for all people
        if j != ind:  # if they're not the person sending the message
            if people[j][4] == 1:  # if this connection is active
                if room == people[j][2]:  # if they are in the same room
                    msg_to_send = "#SEND " + str(name) + ": " + mesg
                    sendq[j].append(msg_to_send)
        j += 1


def establish_secret_comm_chain(sock):
    # the only unencrypted part of chat
    secret = gen_private_key()
    B = gen_public_key(secret)
    debug_print(B)
    # Wait for a connection
    debug_print('waiting for a connection')
    connection, cl_add = sock.accept()
    data = connection.recv(4096).decode('utf-8')
    debug_print("recv data:")
    debug_print(data)
    key = establish_secret(int(data), secret)
    connection.sendall(str(B).encode('utf-8'))
    debug_print("key is " + str(key))
    debug_print("")
    return connection, key, cl_add


def comm_thread(port, ind):
    # This thread creates and stores the shared secret, then creates a send_thread, then continues as a recv thread.
    # Create a TCP/IP socket
    global sendq, people
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Bind the socket to the port
    server_address = ('localhost', port)
    print('starting up on {} port {}'.format(*server_address))
    sock.bind(server_address)
    # Listen for incoming connections
    sock.listen(1)

    conn, key1, client_address = establish_secret_comm_chain(sock)
    people[ind][4] = 1
    send_thread1 = threading.Thread(target=send_thread, args=(conn, key1, ind))
    send_thread1.start()

    # now it's a recv thread.
    try:
        debug_print('connection from ' + str(client_address))
        # Receive the data
        while True:
            data = conn.recv(4096).decode('utf-8')
            plt = dec_recv(data, key1)
            debug_print('recv {!r}'.format(data))
            debug_print('decoded: {!r}'.format(plt))
            splitmsg = plt.split()
            ft = str(splitmsg[0])  # ft = first token
            debug_print(ft)

            if ft[0] == '#':
                # sends help message, who is online, and available rooms
                if ft[1:5] == "HELP" or ft[1:5] == "WHOM" or ft[1:6] == "ROOMS":
                    sendq[ind].append(ft)

                # sets name
                elif ft[1:5] == "NAME":
                    debug_print(people[ind][3] + " has been changed to " + splitmsg[1])
                    people[ind][3] = splitmsg[1]

                # debug send message queue for all sends
                elif ft[1:6] == "PRINT":
                    print(sendq)
                    print(people)


            else:
                send_to_room(people[ind][2], people[ind][3], plt, ind)


    finally:
        # Clean up the connection
        conn.close()


def send_thread(con, key, index):
    # this thread reads from a queue and does the appropriate action.
    debug_print("send thread initiated")
    global sendq, HELP_MSG
    while True:
        if 0 < len(sendq[index]):
            response = str(sendq[index][0]).split()
            mesg = "sending response to request " + response[0]
            debug_print(mesg)
            debug_print(response)
            debug_print(response[0][0:-1])
            if response[0][0:-1] == "#HELP":
                debug_print("Help initialized.")
                enc_send(HELP_MSG, con, key)
            elif response[0] == "#SEND":
                debug_print("Sending message to user")
                new_msg = " ".join(response[1:])
                enc_send(new_msg, con, key)

            else:
                debug_print("Connection " + str(index) + " does not understand: " + str(sendq[index][0]) + ", deleting")
            sendq[index].pop()


if __name__ == "__main__":

    ports = [2000, 2002, 2004, 2006, 2008, 2010, 2012, 2014, 2016, 2018, 2020, 2022, 2024]
    setup_sendq(ports)  # set up list for send_req for each thread
    i, num_of_ports = 0, 12
    while i < num_of_ports:  # from 0 to number of ports in the list, start a thread for each
        communication_thread = threading.Thread(target=comm_thread, args=(int(ports[i]), i))
        communication_thread.start()
        print("thread for port " + str(ports[i]) + " created")
        i += 1

    while True:
        if 0 < len(IO_queue):
            new_msg_for_storage = IO_queue[0]

