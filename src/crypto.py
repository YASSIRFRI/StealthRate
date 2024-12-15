# src/crypto.py
import os
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

# -----------------------------
# Diffie-Hellman Parameters
# -----------------------------
# These are small and insecure for demonstration only.
# Real DH would use large safe primes and strong parameters.
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

# -----------------------------
# Symmetric Encryption (AES)
# -----------------------------
def aes_encrypt(key, plaintext: bytes) -> bytes:
    # AES CTR mode with a random nonce
    nonce = os.urandom(8)  # 64-bit nonce
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    ciphertext = cipher.encrypt(plaintext)
    return nonce + ciphertext

def aes_decrypt(key, ciphertext: bytes) -> bytes:
    nonce = ciphertext[:8]
    ciph = ciphertext[8:]
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(ciph)
