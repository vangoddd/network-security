import socket
import base64
from os import read
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64decode, b64encode

def encrypt(raw):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext = cipher.encrypt(raw)

    return nonce, ciphertext, key

def bintotext(msg):
    newMsg = b64encode(msg).decode()
    return newMsg

def texttobin(msg):
    newMsg = b64decode(msg.encode())
    return newMsg

host = "localhost"
port = 1060

socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.connect((host, port))
print('Client has been assigned socket name', socket.getsockname())

stringMsg = input("Message : ")

#encode the msg and print the key
nonce, ciphertext, key = encrypt(stringMsg.encode())

print("Key : ", bintotext(key))

message = f'{len(bintotext(nonce)):04d}{bintotext(nonce)}'
socket.sendall(message.encode())

message = f'{len(bintotext(ciphertext)):04d}{bintotext(ciphertext)}'
socket.sendall(message.encode())
