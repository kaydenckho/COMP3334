    #!/usr/bin/env python3
"""
            COMP3334-Computer System Security
    Group 33 - Secure Text-based Intant Messenger
"""
"""
***This is the Python script for the client side***
***This application allows two or more users to chat instantly***
Principle:
1. Establish connection with server
2. User input the plaintext message
3. Client program encrypt the plaintext using RSA encryption
4. Send/receive ciphertext(with digital signature) between client and server
"""
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA
import pickle

global PublicKeys
global name

def receive():
    global PublicKeys
    global client_socket
    """Handles receiving of messages."""
    while True:
        msg = client_socket.recv(BUFSIZ)
        if not msg:
            break;
        if bytes("{PUBLICKEY}","utf8") in msg:
            msg = msg[11:]
            PublicKeys = pickle.loads(msg)
        else:
            message = msg[:384]
            signature = msg[384:768]
            sender = msg[768:]
            """ decrypt message """
            decryptor = PKCS1_OAEP.new(keyPair)
            decryptedMessage = decryptor.decrypt(message)
            
            """ decrypt signature """
            h = SHA.new()
            h.update(decryptedMessage)
            for ip in PublicKeys:
                if ip == sender.decode("utf8"):
                    verifier = PKCS1_PSS.new(RSA.import_key(PublicKeys[ip]))
            if verifier.verify(h, signature):
                print(decryptedMessage.decode("utf8"))
            else:
                print("Not Verified")

def inputHandling():
    global client_socket
    """Handles input."""
    while True:
        msg = input()
        if msg == "quit":
            client_socket.shutdown(2)
            client_socket.close()
            print("connection closed")
            break;
        else:
            data = bytes(name+": "+msg,"utf8")
            send(data)

def send(msg):
    global PublicKeys
    global client_socket
    """Handles sending of messages."""
    for ip in PublicKeys:
        """ add encrypted message """
        temp_key = RSA.importKey(PublicKeys[ip])
        encryptor = PKCS1_OAEP.new(temp_key)
        data = encryptor.encrypt(msg)
        """ add digital signature """
        h = SHA.new()
        h.update(msg)
        signer = PKCS1_PSS.new(keyPair)
        data += signer.sign(h)
        """ add receiver's address """
        data += bytes(ip,"utf8")
        client_socket.send(data)

# Main program begins here.
HOST = input("Please input the server ip address: ")
PORT = 33000

BUFSIZ = 4096
ADDR = (HOST, PORT)

client_socket = socket(AF_INET, SOCK_STREAM)
client_socket.connect(ADDR)

PublicKeys = {}
name = ""


# Generate RSA key pairs
keyPair = RSA.generate(3072)   # RSA Key size
pubKey = keyPair.publickey()
pubKey_send = pubKey.exportKey()
client_socket.send(pubKey_send)

receive_thread = Thread(target=receive)
receive_thread.start()

print("COMP3334 - Secure Instant Messenger")
print("Please type your name and press \"Enter\"!")

name = input("Name: ")
data = bytes(name+" has joined the chatroom.","utf8")
send(data)

inputHandling_thread = Thread(target=inputHandling)
inputHandling_thread.start()
# Main program ends.
