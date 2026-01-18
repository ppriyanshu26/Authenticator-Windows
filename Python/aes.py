import hashlib, base64, os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class Crypto:
    def __init__(self, key):
        self.key = key
    
    def encrypt_aes(self, plaintext):
        return base64.urlsafe_b64encode(self.encrypt_bytes(plaintext.encode())).decode()

    def decrypt_aes(self, ciphertext):
        return self.decrypt_bytes(base64.urlsafe_b64decode(ciphertext)).decode()

    def encrypt_bytes(self, data):
        key = hashlib.sha256(self.key.encode()).digest()
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        return nonce + aesgcm.encrypt(nonce, data, None)

    def decrypt_bytes(self, data):
        key = hashlib.sha256(self.key.encode()).digest()
        nonce = data[:12]
        encrypted_data = data[12:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, encrypted_data, None)
