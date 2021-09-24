from os import read
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode

def decrypt(encrypted, nonce, key):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(encrypted)
    print("decrypted msg : ", plaintext.decode())

def encrypt(raw):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext = cipher.encrypt(raw)

    file_out = open("encrypted.bin", "wb")
    file_out.write(nonce)
    file_out.write(ciphertext)
    file_out.close()

    file_key = open("key.bin", "wb")
    file_key.write(key)
    file_key.close()

#msg = input("your msg: ")
msg = "test message"
encrypt(msg.encode())

file_in = open("encrypted.bin", "rb")
nonce = file_in.read(16)
ciphertext = file_in.read()
file_key = open("key.bin", "rb")
newkey = file_key.read()

file_in.close()
file_key.close()

decrypt(ciphertext, nonce, newkey)
