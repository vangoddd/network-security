import socket

import sys
sys.path.append("../")

import aes
import pyDH

#https://stackoverflow.com/questions/17667903/python-socket-receive-large-amount-of-data
def recvall(sock):
    BUFF_SIZE = 4096 # 4 KiB
    data = b''
    while True:
        part = sock.recv(BUFF_SIZE)
        data += part
        if len(part) < BUFF_SIZE:
            # either 0 or end of data
            break
    return data

def sendMsg(msg):
    socket.sendall(msg)

def intToBytes(integer):
    return str(integer).encode()

host = "localhost"
port = 1060

private_key_receiver = pyDH.DiffieHellman()
public_key_receiver = private_key_receiver.gen_public_key()

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind((host, port))
server_socket.listen(1)
print('Listening at', server_socket.getsockname())
socket, sockname = server_socket.accept()
print('We have accepted a connection from', sockname)
print('  Socket name:', socket.getsockname())
print('  Socket peer:', socket.getpeername())

# Doing key exchange with diffie hellman
data = recvall(socket)
public_key_sender = int(data.decode())

sendMsg(intToBytes(public_key_receiver))
shared_secret = private_key_receiver.gen_shared_key(public_key_sender)

# Get AES key from the 1st 16 bytes of the shared secret
encryptionKey = shared_secret[:16].encode()

#Receive the encrypted message
encryptedMsg = recvall(socket)
print("Received encrypted message :")

#Decrypt message using the shared secret as the key
plaintext = aes.decrypt(encryptedMsg, encryptionKey)

file_out = open("decrypted.png", "wb")
file_out.write(plaintext)

