#!/usr/bin/env python3
"""
            COMP3334-Computer System Security
    Group 33 - Secure Text-based Intant Messenger
"""
"""
***This is the Python script for the server side***
***This application allows two or more users to chat instantly***
Principle:
1. Establish connections
2. Receive client's message
3. Unicasting ciphertext(with digital signature) to specific client
"""

# Import socket for establishing TCP connections.
# Import thread for handling multiple users at the same time.
from socket import socket, AF_INET, SOCK_STREAM
from threading import Thread
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import pickle

# Function for establishing connections with clients.
def establish_connections():
    global PublicKeys
    global clients
    while True:
        client, client_address = SERVER.accept()
        pubKey = client.recv(BUFSIZ)
        PublicKeys[str(client_address)] = pubKey   # Receive public key from new client
        clients[client] = str(client_address)
        print("%s:%s has connected." % client_address)
        broadcast(pickle.dumps(PublicKeys))
        Thread(target=handle_client, args=(client,)).start()
# Function establish_connections ends.

# Function for handling clients'request.
def handle_client(client):
    global PublicKeys
    global clients
    while True:
        msg = client.recv(BUFSIZ)
        if not msg:
            print("%s:%s has disconnected." % (clients[client][2:clients[client].find("'",2)], clients[client][clients[client].find("'",2) + 3:-1]))
            del PublicKeys[clients[client]]
            del clients[client]
            broadcast(pickle.dumps(PublicKeys))
            break;
        unicast(msg, client)
# Function handle_client ends.

# Function for broadcasting public keys to all connected users.
def broadcast(msg):  # msg should be in bytes
    global clients
    """Broadcasts a message to all the clients."""
    data = bytes("{PUBLICKEY}","utf8")+msg
    for sock in clients:
        sock.send(data)
# Function broadcast ends.

# Function for unicasting messages to a specific user according to receiver's address
def unicast(msg, client):
    global clients
    for sock in clients:
        if bytes(clients[sock],"utf8") in msg:
            destination = sock
        if sock == client:
            source = bytes(clients[sock],"utf8")
    """ remove receiver's address """
    msg = msg[:768]
    """ add sender's address """
    msg += source
    """ send the message (encrypted message + digital signature + sender's address) """
    destination.send(msg)
# Function unicast ends

# Main program begins.
clients = {}
PublicKeys = {}

HOST = input("Please input the server ip address: ")
PORT = 33000
BUFSIZ = 4096
ADDR = (HOST, PORT)

SERVER = socket(AF_INET, SOCK_STREAM)
SERVER.bind(ADDR)

SERVER.listen()
print("Server is up.")
ACCEPT_THREAD = Thread(target=establish_connections)
ACCEPT_THREAD.start()
ACCEPT_THREAD.join()
SERVER.close()
# Main program ends.
