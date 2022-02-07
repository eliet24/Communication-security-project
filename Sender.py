# Guy Rajwan, 322985409, Elihyo Etin, 205868771
import sys
import threading

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import socket
from _thread import *

messages_for_send = []
messages = []
counter = 0


def timer():  # function for Synchronizing messages to required round using timer
    global messages_for_send
    global messages
    global counter
    for specific_message in messages:  # loop that take the messages from the messages array
        message_array = specific_message.split(" ")
        round_number_for_message = int(message_array[2])  # taking the required round number
        if round_number_for_message == counter:          # if we in the right round...
            messages.remove(specific_message)          # delete message from messages array
            messages_for_send.append(specific_message)  # and add it to messages_for_send array
    for message_for_send in messages_for_send:
        send_message(message_for_send)            # sending messages to the server function for message_for_send
    messages_for_send = []
    counter += 1
    if len(messages) != 0:                      # while we still have messages in messages array
        threading.Timer(60.0, timer).start()    # loop to the timer function every 60 seconds(time of round)


def send_message(message_for_send):  # function for sending messages to the server
    ClientSocket = socket.socket()

    array = message_for_send.split(" ")  # split message_for_send to all needed components
    message = array[0]
    path = array[1]
    round_number = array[2]
    password = array[3]
    salt = array[4]
    destination_ip = array[5]
    destination_port = array[6]

    ip = destination_ip.split('.')  # split ip by .
    temp = b''                      # convert ip to binary representation...
    for num in ip:
        temp += int(num).to_bytes(1, 'big')
    ip = temp

    port = int(destination_port.replace('\n', ''))
    port = port.to_bytes(2, 'big')                  # convert port to binary representation

    path_array = path.split(",")                    # splitting path fo resnding message to ip and port..
    ip_and_port = ips[int(path_array[0]) - 1]
    ip_and_port_array = ip_and_port.split(" ")

    k = Fernet(base64.urlsafe_b64encode(            # creating K the symetric private key
        PBKDF2HMAC(algorithm=SHA256(),
                   length=32,
                   salt=salt.encode(),
                   iterations=100000,
                   backend=default_backend()).derive(password.encode())))
    encrypt_message = k.encrypt(message.encode())

    message_with_destination = ip + port + encrypt_message  # binary concatenation of the encrypted message with path

    with open("pk" + path_array[-1] + ".pem", "rb") as key_file:      # taking the Public key from the pk file
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    final_message = public_key.encrypt(         # creating final encrypted message for sending to next server
        message_with_destination,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    for server_number in range(len(path_array) - 2, -1, -1):     # now looping on the rest servers that the message pass
        ip_and_port_for_message = ips[int(path_array[server_number + 1]) - 1]
        ip_and_port_for_message_array = ip_and_port_for_message.split(" ")  # taking ip and port for next server to send

        ip = ip_and_port_for_message_array[0].split('.')  # convert ip to binary
        temp = b''
        for num in ip:
            temp += int(num).to_bytes(1, 'big')
        ip = temp

        port = int(ip_and_port_for_message_array[1].replace('\n', ''))  # convert port to binary
        port = port.to_bytes(2, 'big')
        # taking the Public key from the pk file
        with open("pk" + str(path_array[server_number]) + ".pem", "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        final_message = public_key.encrypt(              # creating final encrypted message for sending to next server
            ip + port + final_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    host = ip_and_port_array[0]
    port = int(ip_and_port_array[1])

    try:                                            # try connecting to next server
        ClientSocket.connect((host, port))
    except socket.error as e:
        print(str(e))

    ClientSocket.send(final_message)                # and send encrypted message
    ClientSocket.close()


ips = []                # array that holds all the ip's
servers = []            # array that holds all the server numbers
ips_file = open('ips.txt', 'r')   # open and extract servers ip's for use...
ips_lines = ips_file.readlines()
for line in ips_lines:
    servers.append(counter)  # add number of server to servers array for each server
    if line[len(line)-1] == '\n':
        ips.append(line[:len(line)-1])
    else:
        ips.append(line)        # add ip to ips array

messages_file = open('messages' + sys.argv[1] + '.txt', 'r')  # read the messages for send from the message file
messages_lines = messages_file.readlines()
for line in messages_lines:
    messages.append(line)                   # and add them to messages array
timer()

