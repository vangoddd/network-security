from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = get_random_bytes(16)

def decrypt(encrypted, nonce, key):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(encrypted)
    print(plaintext)

def encrypt(raw, key):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext = cipher.encrypt(raw)
    print(ciphertext, nonce)

    decrypt(ciphertext, nonce, key)



encrypt(b'secret message', key)
