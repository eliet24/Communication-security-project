# Guy Rajwan, 322985409, Elihyo Etin, 205868771
import base64
import random
import socket
import sys
from _thread import *
import threading
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


counter = 0
messages = []  # array of all the messages in the server


def timer():         # function that shuffle the messages in the server and wait 60 seconds using timer before next send
    global messages
    global counter
    messages_copy = messages.copy()
    random.shuffle(messages_copy)   # shuffle messages
    for i in range(len(messages)):  # initialize original message array for next round
        messages[i] = []
    threading.Timer(60.0, timer).start()
    if counter != 0:
        for message in messages_copy:  # extract ip, port and the message from each full message in message array
            if len(message) != 0:
                ip = ""
                for i in range(4):
                    ip += str(message[i]) + "."
                ip = ip[:len(ip) - 1]
                port = int.from_bytes(message[4:6], byteorder='big')

                rest_message = message[6:len(message)]  # the encrypted message without ip and port of the next server

                ClientSocket = socket.socket()

                try:
                    ClientSocket.connect((ip, port))   # try create connection to next server
                except socket.error as e:
                    print(str(e))

                ClientSocket.send(base64.b64encode(rest_message))  # send rest of the message to next server
    counter += 1
    for i in range(len(messages_copy)):
        messages_copy[i] = []


def threaded_client(connection, address, server_number):  # thread function to apply to each client
    counter = 1
    while True:
        data = connection.recv(8192)  # getting the message data from client
        if len(data) != 0:
            with open("sk" + str(server_number) + ".pem", "r") as key_file:  # extract the secret key from the sk file
                private_key = serialization.load_pem_private_key(               # for the current server
                    key_file.read().encode(), None)
            original_message = private_key.decrypt(     # decrypt with secret key of the server to get original message
                data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            if len(original_message) != 0:  # add to counter for each received message
                counter += 1
                if not data:
                    break

                messages.append(original_message)    # add original message to messages array of the server
    connection.close()


try:
    ips_file = open('ips.txt', 'r')     # read the ips file and extract the current ip and the ip of the next server
    lines = ips_file.readlines()
    array = lines[int(sys.argv[1])-1].split(" ")
    port = int(array[1])
    timer()                             # activating the timer function before sending the messages to the next servers
    server_socket = socket.socket()
    number_of_clients = 0
    try:
        server_socket.bind(("", port))
    except socket.error as e:
        print(str(e))

    server_socket.listen()              # server waiting for bind with clients

    while True:          # infinite loop that wait for connection of clients to server and start new thread for each one
        client, address = server_socket.accept()
        start_new_thread(threaded_client, (client, address, sys.argv[1],))
        number_of_clients += 1
    server_socket.close()

except:
    print('a')
while 1:
    pass