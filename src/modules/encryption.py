import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class Encryption:
    """
    Handles AES payload encryption.
    """

    def encrypt(self, payload, key=None):
        """
        Encrypt payload using AES-256-GCM (or CBC for wider compatibility).
        Returns (ciphertext, key, iv).
        
        Using AES-CBC with PKCS7 padding for easier implementation in C/PS without complex GCM tag handling.
        """
        if key is None:
            key = os.urandom(32) # 256 bits
        
        iv = os.urandom(16)  # 128 bits
        
        # Pad payload to 16 bytes
        pad_len = 16 - (len(payload) % 16)
        padded_payload = payload + (chr(pad_len) * pad_len).encode()
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_payload) + encryptor.finalize()
        
        return ciphertext, key, iv
