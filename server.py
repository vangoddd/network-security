import os
import socket
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64decode, b64encode

host = "localhost"
port = 1060

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind((host, port))
server_socket.listen(1)
print('Listening at', server_socket.getsockname())
socket, sockname = server_socket.accept()
print('We have accepted a connection from', sockname)
print('  Socket name:', socket.getsockname())
print('  Socket peer:', socket.getpeername())

def recvall(length):
    data = b''
    while len(data) < length:
      more = socket.recv(length - len(data))
      if not more:
        raise EOFError('was expecting %d bytes but only received'
                      ' %d bytes before the socket closed'
                      % (length, len(data)))
      data += more
    return data

def rcvmsg():
    length = recvall(4)
    message = recvall(int(length))
    return message.decode()

def decrypt(encrypted, nonce, key):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(encrypted)
    print("decrypted msg : ", plaintext.decode())

def bintotext(msg):
    newMsg = b64encode(msg).decode()
    return newMsg

def texttobin(msg):
    newMsg = b64decode(msg.encode())
    return newMsg

nonce = rcvmsg()
ciphertext = rcvmsg()

print("Encrypted message received")

key = input("Enter key : ")
decrypt(texttobin(ciphertext), texttobin(nonce), texttobin(key))