# cryptography.py

import os
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

PRIME = 0xFFFFFFFB
GENERATOR = 5

def dh_generate_private_key():
    return int.from_bytes(os.urandom(32), 'big') % PRIME

def dh_generate_public_key(private_key, prime=PRIME, generator=GENERATOR):
    return pow(generator, private_key, prime)

def dh_compute_shared_secret(their_public, my_private, prime=PRIME):
    return pow(their_public, my_private, prime)

def derive_key(shared_secret):
    secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big')
    return SHA256.new(secret_bytes).digest()

def aes_encrypt(key, plaintext: bytes) -> bytes:
    nonce = os.urandom(8) 
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    ciphertext = cipher.encrypt(plaintext)
    return nonce + ciphertext

def aes_decrypt(key, ciphertext: bytes) -> bytes:
    nonce = ciphertext[:8]
    ciph = ciphertext[8:]
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(ciph)
