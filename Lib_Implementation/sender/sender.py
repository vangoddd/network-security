import socket
import sys
import time
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad


sys.path.append("../../Native_Implementation/")
import pyDH

def encrypt(raw, key):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    ciphertext = cipher.encrypt(pad(raw, AES.block_size))
    return iv, ciphertext

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

socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.connect((host, port))
print('Client has been assigned socket name', socket.getsockname())

# Diffie hellman key exhange
private_key_sender = pyDH.DiffieHellman()
public_key_sender = private_key_sender.gen_public_key()

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
iv, cypherName = encrypt(file_name.encode(), encryptionKey)
sendMsg(iv+cypherName)

print("File name sent, sleeping for 1 sec")
time.sleep(1)

# Encrypt file content and send

#Counting time taken for decryption
startTime = time.time()

print("Encrypting file content")
msgIv, encryptedMsg = encrypt(msg, encryptionKey)
print("Encryption complete, sending file")
print("File Size : " + str(len(msg)) + "(in bytes)")
print("Encryption time : %s" % (time.time() - startTime))

sendMsg(msgIv + encryptedMsg)

print("File sent")

