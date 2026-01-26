import hashlib, base64, os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class Crypto:
    def __init__(self, key):
        self.key = hashlib.sha256(key.encode()).digest()
    
    def encrypt_aes(self, plaintext):
        return base64.urlsafe_b64encode(self.encrypt_bytes(plaintext.encode())).decode()

    def decrypt_aes(self, ciphertext):
        return self.decrypt_bytes(base64.urlsafe_b64decode(ciphertext)).decode()

    def encrypt_bytes(self, data):
        nonce = os.urandom(12)
        return nonce + AESGCM(self.key).encrypt(nonce, data, None)

    def decrypt_bytes(self, data):
        return AESGCM(self.key).decrypt(data[:12], data[12:], None)
