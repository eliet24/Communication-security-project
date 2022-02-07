# Guy Rajwan, 322985409, Elihyo Etin, 205868771
import base64
import socket
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import sys
from _thread import *

ServerSocket = socket.socket()  # creating socket for the receiver using the port given by argument
port = int(sys.argv[3])
ThreadCount = 0
print(sys.argv)
try:
    ServerSocket.bind(("", port))   # waiting for bind of last server in the servers chain to the receiver
except socket.error as e:
    print(str(e))

print('Waiting for a Connection..')
ServerSocket.listen(5)


def threaded_client(connection):  # function to apply for each thread of server connected to the receiver
    while True:
        data = connection.recv(8192)  # getting the message from last server
        data = base64.b64decode(data)
        if data.decode() != "":         # decode the last message using the private key- k...
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=str.encode(sys.argv[2]), iterations=100000)
            k = base64.urlsafe_b64encode(kdf.derive(str.encode(sys.argv[1])))
            k = Fernet(k)
            received_message = k.decrypt(data)   # received message from sender after decoding

            if received_message.decode() != "":
                print(f"message received: {received_message.decode()}")
                if not data:
                    break
    connection.close()


while True:     # infinite loop receiver wait for connection of the servers and start new thread for each one
    Client, address = ServerSocket.accept()
    print('Connected to: ' + address[0] + ':' + str(address[1]))
    start_new_thread(threaded_client, (Client, ))
    ThreadCount += 1
    print('Thread Number: ' + str(ThreadCount))
ServerSocket.close()

