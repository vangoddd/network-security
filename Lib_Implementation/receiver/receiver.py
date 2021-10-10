import socket
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import time

sys.path.append("../../Native_Implementation/")
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

def decrypt(encrypted, iv, key):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = cipher.decrypt(encrypted)
    return unpad(plaintext, AES.block_size)

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
print("Received Sender's public key")
public_key_sender = int(data.decode())
print("Sending public key to Sender")

sendMsg(intToBytes(public_key_receiver))

shared_secret = private_key_receiver.gen_shared_key(public_key_sender)
print("Shared secret generated")

# Get AES key from the 1st 16 bytes of the shared secret
encryptionKey = shared_secret[:16].encode()

#Receive file name
encryptedName = recvall(socket)
nameIv = encryptedName[:16]
encryptedName = encryptedName[16:]
print("Received filename :")
plainName = decrypt(encryptedName, nameIv, encryptionKey)

print(plainName)

#Receive the encrypted message
encryptedMsg = recvall(socket)
msgIv = encryptedMsg[:16]
encryptedMsg = encryptedMsg[16:]
print("Received encrypted file content")

#Decrypt message using the shared secret as the key

#Counting time taken for decryption
startTime = time.time()

print("Decrypting encrypted file content")
plaintext = decrypt(encryptedMsg, msgIv, encryptionKey)
print("Decryption complete")

print("File Size : " + str(len(plaintext)) + "(in bytes)")
print("Decryption time : %s" % (time.time() - startTime))

file_out = open(plainName.decode(), "wb")
file_out.write(plaintext)
file_out.close()



