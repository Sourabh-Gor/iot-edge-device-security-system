#crypto_utils.py
import hmac
import hashlib
import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SECRET_KEY = b'supersecurekey_here_is_32_byte_l'

def generate_nonce():
    return os.urandom(12)

def encrypt_puf(puf_key):
    aesgcm = AESGCM(SECRET_KEY)
    nonce = generate_nonce()
    encrypted = aesgcm.encrypt(nonce, puf_key.encode(), None)
    return base64.b64encode(nonce).decode(), base64.b64encode(encrypted).decode()

def decrypt_puf(nonce_b64, encrypted_b64):
    aesgcm = AESGCM(SECRET_KEY)
    nonce = base64.b64decode(nonce_b64)
    encrypted_puf = base64.b64decode(encrypted_b64)
    decrypted = aesgcm.decrypt(nonce, encrypted_puf, None)
    return decrypted.decode()

def generate_mac(data_bytes):
    return hmac.new(SECRET_KEY, data_bytes, hashlib.sha256).hexdigest()

def verify_mac(data_bytes, received_mac):
    expected_mac = generate_mac(data_bytes)
    return hmac.compare_digest(expected_mac, received_mac)

def hash_puf(puf_key):
    return hashlib.sha256(puf_key.encode()).hexdigest()
