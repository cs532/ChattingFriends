# chat_server.py

import sys
import socket
import threading
from secret_sharing import *
from mass_encrypt import *


# TODO: add rooms with keys.
# don't spend too much time on input validation

# Define globals
debug = 1               # debug mode on if 1, off if 0
IO_queue = []           # IO_queue for passing messages to IO thread
sendq = []              # sendq for sending message between recv threads, [index, port number] format
people = []             # people is used for storing information about people, i.e. names, connection number, room,
stop_pep8 = 8           # and if they are on/off line. stop_pep8 is useless besides to stop pycharm yelling at me.
rooms = []   # list of rooms, [room name, Shamir secret key, number of shards to assemble, k-1 key shards for verification] format
HELP_MSG = "Hello! Here are the current list of available functions:\n#NAME: change name \n#END: end session\n#WHOM: " \
           "view list of people online\n#ROOMS: get a list of rooms\n#MAKE roomname creatorNames numToOpen: create ro" \
           "om\n#ROOM roomname: change room\n#GET_LOG shard1,shard2,...: gets the chat log of the current room"


# debug utility functions
def debug_print(words):
    # if it is in debug mode (debug = 1), print the text
    if debug != 0:
        print(str(words))


def graceful_end(index, connection):
    sendq[index].append("#CLOSE")
    time.sleep(5)
    connection.close()

    IO_queue.append("#RESTART " + str(index))
    sys.exit(0)

# setup functions
def setup_sendq(num_of_port):

    global sendq, people

    for k in range(len(num_of_port)):
        sendq.append([])
        people.append([k, num_of_port[k], "home", str("default"+str(k)), 0])

    debug_print(sendq)
    debug_print(people)


# comm functions
def dec_recv(cipher_text, secret):
    # decrypt received message
    plain_text = mass_decrypt(cipher_text, secret)
    return plain_text


def enc_send(plaintext, sock1, secret):
    # encrypt message, then send
    debug_print(plaintext)
    cipher_text = mass_encrypt(plaintext, secret)
    sock1.sendall(cipher_text.encode('utf-8'))


def send_to_room(room, name, mesg, ind):
    global people, sendq, IO_queue
    j = 0
    msg_to_send = "#SEND " + str(name) + ": " + mesg
    msg_to_IO   = "#SAVE " + str(room) + " " + str(name) + ": " + mesg
    while j < len(people):  # for all people
        if j != ind:  # if they're not the person sending the message
            if people[j][4] == 1:  # if this connection is active
                if room == people[j][2]:  # if they are in the same room
                    sendq[j].append(msg_to_send)
        j += 1
    IO_queue.append(msg_to_IO)


def find_name_index(name):
    global people
    for k in range(len(people)):
        if people[k][3] == name:
            return k
    return -1


def find_room_name_index(name):
    for j in range(len(rooms)):
        if rooms[j][0] == name:
            return j
    return -1


def establish_secret_comm_chain(sockit):
    # the only unencrypted part of chat
    secret = gen_private_key()
    pubkey = gen_public_key(secret)
    debug_print(pubkey.x)
    # Wait for a connection
    debug_print('waiting for a connection')
    connection, cl_add = sockit.accept()
    data = connection.recv(4096).decode('utf-8')
    debug_print("recv data:")
    debug_print(data)
    key_no_expand = establish_secret(data, secret)
    connection.sendall(str(pubkey).encode('utf-8'))
    all_keys = expand_key(proper_parser(key_no_expand))
    debug_print("key is " + str(key_no_expand))
    debug_print("")
    return connection, all_keys, cl_add


def server_connection_setup(port):

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Bind the socket to the port
    server_address = ('localhost', port)
    print('starting up on {} port {}'.format(*server_address))
    sock.bind(server_address)

    return sock


def comm_thread(sock, ind):
    # This thread creates and stores the shared secret, then creates a send_thread, then continues as a recv thread.
    # Create a TCP/IP socket
    global sendq, people, rooms
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

            if len(data) == 0: # reset connection
                people[ind][4] = 0
                people[ind][3] = "default"+str(ind)
                graceful_end(ind, conn)

            plt = dec_recv(data, key1)

            debug_print('recv {!r}'.format(data))
            debug_print('decoded: {!r}'.format(plt))
            splitmsg = plt.split()
            if len(splitmsg) == 0:
                splitmsg.append("#HELP")

            ft = str(splitmsg[0])  # ft = first token
            debug_print(ft)

            if ft[0] == '#':
                # sends help message, who is online, and available rooms
                if ft[1:5] == "HELP" or ft[1:5] == "WHOM" or ft[1:6] == "ROOMS":
                    sendq[ind].append(ft)

                # sets name
                elif ft[1:5] == "NAME":
                    splitmsg.append("HaCkeRmAN!.50210")
                    debug_print(people[ind][3] + " has been changed to " + splitmsg[1])
                    people[ind][3] = splitmsg[1]

                # debug send message queue for all sends
                elif ft[1:6] == "PRINT":
                    print(sendq)
                    print(people)
                    print(rooms)

                # creates a room and sends the shards to the creators
                elif ft[1:5] == "MAKE":
                    creators = splitmsg[2].split(",")
                    roomkey = int(np.random.rand() * prime - 1)
                    rooms.append([splitmsg[1], roomkey, int(splitmsg[3])])
                    debug_print(roomkey)
                    keyshards = generate_shard(len(creators), int(splitmsg[3][0]), roomkey)
                    for x in range(len(creators)):
                        sendq[find_name_index(creators[x])].append("#SEND Your key shard is: " +
                                                                   str(keyshards[x]) + " store this number in a "
                                                                                       "safe place")
                    debug_print("the following keyshards have been generated: " + str(keyshards))
                    update_room_info()

                # gets the log of the current room
                elif ft[1:8] == "GET_LOG":
                    shardnums = splitmsg[1].split(",")
                    shards = []
                    for q in range(len(shardnums)):
                        shards.append([q+1, int(shardnums[q])])
                    generatedkey = compile_shards(shards)
                    if int(generatedkey) == int(rooms[find_room_name_index(people[ind][3])][1]):
                        sendq[ind].append("#SEND The following is the log for the room- " +
                                            read_file_to_string(rooms[find_room_name_index(people[ind][3])][0]))
                    else:
                        sendq[ind].append("#SEND Log not fetched: incorrect key segments provided")

                elif ft[1:5] == "ROOM":
                    if len(splitmsg) == 2:
                        people[ind][2] = splitmsg[1]
                    else:
                        sendq[ind].append("#SEND Room not changed: insufficient arguments provided")

                elif ft[1:4] == "END": # End and reset connection / name
                    people[ind][4] = 0
                    people[ind][3] = "default" + str(ind)
                    graceful_end(ind, conn)

                else:
                    debug_print("# followed by nothing understandable, becoming a send so ppl can laugh in chat.")
                    send_to_room(people[ind][2], people[ind][3], plt, ind)

            else:
                debug_print("Interpreted as a general message. Sending to room.")
                send_to_room(people[ind][2], people[ind][3], plt, ind)


    finally:
        # Clean up the connection
        conn.close()


def send_thread(con, big_key, index):
    # this thread reads from a queue and does the appropriate action.
    debug_print("send thread initiated")
    global sendq, people, rooms, HELP_MSG
    while True:
        if 0 < len(sendq[index]):

            response = str(sendq[index][0]).split()
            mesg = "sending response to request " + response[0]
            debug_print(mesg)
            debug_print(response)
            debug_print(response[0])

            if response[0] == "#HELP":
                debug_print("Help initialized.")
                enc_send(HELP_MSG, con, big_key)

            elif response[0][0:-1] == "#WHOM":
                nu_msg = ""
                for p in range(len(people)):
                    if people[p][4] == 1:
                        nu_msg = nu_msg + people[p][3] + "\n"
                if nu_msg == "":
                    nu_msg = "Only you are online.\n"
                enc_send(nu_msg, con, big_key)

            elif response[0] == "#ROOMS":
                nu_msg = ""
                debug_print(str(rooms))
                for r in range(len(rooms)):
                    nu_msg = nu_msg + rooms[r][0] + "\n"

                enc_send(nu_msg, con, big_key)

            elif response[0] == "#SEND":
                debug_print("Sending message to user")
                nu_msg = " ".join(response[1:])
                enc_send(nu_msg, con, big_key)

            elif response[0] == "#CLOSE":
                debug_print("closing..." + str(index))
                nu_msg = "#CLOSE"
                enc_send(nu_msg, con, big_key)
                while 0 < len(sendq[index]):
                    sendq[index].pop()
                sys.exit(0)

            else:
                debug_print("Connection " + str(index) + " does not understand: " + str(sendq[index][0]) + ", deleting")
            sendq[index].pop()


# Makes a file with the associated room
def make_file_to_write(name):
    with open(name + "_log.txt", 'x') as f:
        f.write("")


# Write message to log file
def write_to_file(name, message):
    try:
        with open(name + "_log.txt", 'a') as f:
            f.write(message)
            f.write("| |")
    except FileNotFoundError:
        with open(name + "_log.txt", 'x') as f:
            f.write(message)
            f.write("")


# takes file contents and turns them into a string
def read_file_to_string(name):
    try:
        with open(name + "_log.txt", 'r') as f:
            text = f.read()
    except FileNotFoundError:
        return name + "_log.txt does not exist"
    return text


# populate rooms based on rooms_info.txt and create files if they do not already exist
def startup_room_info():
    global rooms
    try:
        with open("rooms_info.txt", 'r') as f:
            roomslist = f.read()[:-2].split(",,")
            for x in range(len(roomslist)):
                debug_print("room = ")
                room = roomslist[x].strip("[]").split(", ")
                rooms.append([room[0].strip("'"), int(room[1]), int(room[2])])

    except FileNotFoundError:
        rooms = [["home", 0, 1]]
        with open("rooms_info.txt", 'x') as f:
            for y in range(len(rooms)):
                f.write(str(rooms[y]) + ",,")

    try:
        with open("home_log.txt", 'r') as f:
            temp = list(f.read())
            print(temp)

    except FileNotFoundError:
        with open("home_log.txt", 'x') as f:
            f.write("")

    debug_print("rooms table is :")
    print(rooms)


# update rooms_info.txt with the current rooms
def update_room_info():
    global rooms
    try:
        with open("rooms_info.txt", 'w') as f:
            for x in range(len(rooms)):
                debug_print(str(rooms[x]))
                f.write(str(rooms[x]) + ",,")
    except FileNotFoundError:
        with open("rooms_info.txt", 'x') as f:
            for x in range(len(rooms)):
                f.write(str(rooms[x]) + ",,")


if __name__ == "__main__":

    ports = [2000, 2002, 2004, 2006, 2008, 2010, 2012, 2014, 2016, 2018, 2020, 2022, 2024, 2026]
    setup_sendq(ports)  # set up list for send_req for each thread
    startup_room_info()
    i, num_of_ports = 0, 14
    sock = []
    while i < num_of_ports:  # from 0 to number of ports in the list, start a thread for each
        sock.append(server_connection_setup(ports[i]))
        communication_thread = threading.Thread(target=comm_thread, args=(sock[i], i))
        communication_thread.start()
        print("thread for port " + str(ports[i]) + " created")
        i += 1

    while True:
        if 0 < len(IO_queue):
            IO_msg = str(IO_queue[0]).split()

            if IO_msg[0] == "#RESTART":  # a thread exited, meaning a session was terminated
                debug_print("restarting comm thread" + str(IO_msg[1]))
                communication_thread = threading.Thread(target=comm_thread, args=(sock[int(IO_msg[1])], int(IO_msg[1])))
                communication_thread.start()

            elif IO_msg[0] == "#MAKE":  # make the file for the requested room, parsed : [filename]
                fname = IO_msg[1]
                make_file_to_write(fname)

            elif IO_msg[0] == "#SAVE":  # store message to file, parsed [filename, reset of message]
                fname = IO_msg[1]
                new_msg = " ".join(IO_msg[2:])
                write_to_file(fname, new_msg)

            elif IO_msg[0] == "#GET":  # reads content of files into a string then sends it to
                fname = IO_msg[1]
                send_to = IO_msg[2]
                plain_text = read_file_to_string(fname)

            else:
                print("IO_thread does not understand command")

            IO_queue.pop()
