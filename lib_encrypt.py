import base64
from os import read
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64decode, b64encode

def decrypt(encrypted, nonce, key):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(encrypted)
    print("decrypted msg : ", plaintext.decode())

def encrypt(raw):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext = cipher.encrypt(raw)

    file_out = open("encrypted.txt", "w")
    file_out.write(bintotext(nonce))
    file_out.write("\n")
    file_out.write(bintotext(ciphertext))
    file_out.close()

    file_key = open("key.txt", "w")
    file_key.write(bintotext(key))
    file_key.close()

def bintotext(msg):
    newMsg = b64encode(msg).decode()
    return newMsg

def texttobin(msg):
    newMsg = b64decode(msg.encode())
    return newMsg

msg = input("your msg: ")
#msg = "test message"
encrypt(msg.encode())

file_in = open("encrypted.txt", "r")
nonce = texttobin(file_in.readline())
ciphertext = texttobin(file_in.read())
file_key = open("key.txt", "r")
newkey = texttobin(file_key.read())

file_in.close()
file_key.close()

decrypt(ciphertext, nonce, newkey)
