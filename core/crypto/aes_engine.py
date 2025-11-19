from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64

class AESCipher:
    def __init__(self, key):
        self.key = key.encode('utf-8')  # Ensure key is bytes
        #Hash the key to get a secure length
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(self.key)
        self.key = digest.finalize()


    def encrypt(self, data):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CFB8(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data.encode('utf-8')) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(iv + ciphertext).decode('utf-8') #Return b64 for usability

    def decrypt(self, data):
        try:
            data = base64.b64decode(data)
            iv = data[:16]
            ciphertext = data[16:]
            cipher = Cipher(algorithms.AES(self.key), modes.CFB8(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            plaintext = unpadder.update(plaintext_padded) + unpadder.finalize()
            return plaintext.decode('utf-8')
        except Exception as e:
            print(f"Decryption Error: {e}") # Log the error, don't expose details to the user
            return None # Or raise an exception, depending on the desired behavior
