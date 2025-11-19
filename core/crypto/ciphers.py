from Crypto.Cipher import DES, ARC4, Blowfish
from Crypto.Util.Padding import pad, unpad
import hashlib
import os

class XORCipher:
    def __init__(self, key):
        self.key = key

    def encrypt(self, data):
        if isinstance(data, str):
            data = data.encode()
        key_bytes = self.key.encode() if isinstance(self.key, str) else self.key
        key_len = len(key_bytes)
        encrypted = bytearray()
        for i in range(len(data)):
            encrypted.append(data[i] ^ key_bytes[i % key_len])
        return bytes(encrypted)

    def decrypt(self, data):
        return self.encrypt(data)  # XOR is its own inverse

class DESCipher:
    def __init__(self, key):
        if isinstance(key, str):
            key = key.encode()
        self.key = key
        self.block_size = DES.block_size

    def encrypt(self, data):
        if isinstance(data, str):
            data = data.encode()
        cipher = DES.new(self.key, DES.MODE_ECB)
        padded_data = pad(data, self.block_size)
        return cipher.encrypt(padded_data)

    def decrypt(self, data):
        cipher = DES.new(self.key, DES.MODE_ECB)
        decrypted = cipher.decrypt(data)
        return unpad(decrypted, self.block_size)

class RC4Cipher:
    def __init__(self, key):
        if isinstance(key, str):
            key = key.encode()
        self.key = key

    def encrypt(self, data):
        if isinstance(data, str):
            data = data.encode()
        cipher = ARC4.new(self.key)
        return cipher.encrypt(data)

    def decrypt(self, data):
        cipher = ARC4.new(self.key)
        return cipher.decrypt(data)

class BlowfishCipher:
    def __init__(self, key):
        if isinstance(key, str):
            key = key.encode()
        self.key = key
        self.block_size = Blowfish.block_size

    def encrypt(self, data):
        if isinstance(data, str):
            data = data.encode()
        cipher = Blowfish.new(self.key, Blowfish.MODE_ECB)
        padded_data = pad(data, self.block_size)
        return cipher.encrypt(padded_data)

    def decrypt(self, data):
        cipher = Blowfish.new(self.key, Blowfish.MODE_ECB)
        decrypted = cipher.decrypt(data)
        return unpad(decrypted, self.block_size)

class HashFunction:
    @staticmethod
    def hash(data, algorithm='sha256'):
        if isinstance(data, str):
            data = data.encode()
        
        if algorithm.lower() == 'md5':
            return hashlib.md5(data).hexdigest()
        elif algorithm.lower() == 'sha256':
            return hashlib.sha256(data).hexdigest()
        elif algorithm.lower() == 'sha512':
            return hashlib.sha512(data).hexdigest()
        else:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")

    @staticmethod
    def verify(data, hash_value, algorithm='sha256'):
        return HashFunction.hash(data, algorithm) == hash_value 