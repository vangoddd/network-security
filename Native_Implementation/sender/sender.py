
import socket
import time
import sys
sys.path.append("../")

import aes
import pyDH

# msg is in byte
def sendMsg(msg):
    socket.sendall(msg)

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

def intToBytes(integer):
    return str(integer).encode()

host = "localhost"
port = 1060

private_key_sender = pyDH.DiffieHellman()
public_key_sender = private_key_sender.gen_public_key()

socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.connect((host, port))
print('Client has been assigned socket name', socket.getsockname())

# Doing key exchange with diffie hellman
print("Sending sender's public key")
sendMsg(intToBytes(public_key_sender))
data = recvall(socket)
print("Received Receiver's public key")

receiver_public_key = int(data.decode())
shared_secret = private_key_sender.gen_shared_key(receiver_public_key)
print("Shared secret generated")

# Get AES Key from the 1st 16 bytes of the shared secret
encryptionKey = shared_secret[:16].encode()

# Encrypt and send the message
file_name = input("Enter file name : ")

file_in = open(file_name, "rb")
msg = file_in.read()
file_in.close()

# Encrypt file name and send
print("Encrypting file name")
encName = aes.encrypt(file_name.encode(), encryptionKey)
sendMsg(encName)

print("File name sent, sleeping for 1 sec")
time.sleep(1)

# Encrypt file content and send
print("Encrypting file content")
encryptedMsg = aes.encrypt(msg, encryptionKey)
print("Encryption complete, sending file")
sendMsg(encryptedMsg)

print("File sent")

