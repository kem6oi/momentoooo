import base64
from core.crypto.aes_engine import AESCipher
from core.crypto.vigenere import VigenereCipher
import random

class ChallengeLayer:
    def __init__(self):
        self.aes_cipher = AESCipher("defaultkey") #Default key, overwritten in layer
        self.vigenere_cipher = VigenereCipher("defaultkey") #Default key, overwritten in layer

    def apply_layers(self, data, num_layers=2): #Number of layers to create
        """Applies multiple layers of encryption to the data."""
        encrypted_data = data

        for _ in range(num_layers):
            layer_type = random.choice(["aes", "vigenere"])
            if layer_type == "aes":
                key = self.generate_key() #Generate secure key for AES
                aes_cipher = AESCipher(key) #Local cipher instance
                encrypted_data = aes_cipher.encrypt(encrypted_data)
                encrypted_data = f"AES:{key}:{encrypted_data}" #Add layer information
            elif layer_type == "vigenere":
                key = self.generate_key(vigenere=True) #Generate secure key for Vigenere
                vigenere_cipher = VigenereCipher(key) #Local cipher instance
                encrypted_data = vigenere_cipher.encrypt(encrypted_data)
                encrypted_data = f"VIGENERE:{key}:{encrypted_data}" #Add layer information
        return encrypted_data

    def remove_layers(self, data):
      """Removes layers from the encrypted data"""
      decrypted_data = data

      while ":" in decrypted_data: #Layers are splitted by :
          try:
              layer_type, key, encrypted_data = decrypted_data.split(":", 2) #split by 2 to preserve encrypted data if its have the same char
              if layer_type == "AES":
                    aes_cipher = AESCipher(key) #Init cypher with key
                    decrypted_data = aes_cipher.decrypt(encrypted_data)
              elif layer_type == "VIGENERE":
                    vigenere_cipher = VigenereCipher(key) #Init cypher with key
                    decrypted_data = vigenere_cipher.decrypt(encrypted_data)
          except Exception as e:
              print(f"Error removing layer: {e}") # Log the error
              return None  # Or raise an exception, depending on the desired behavior

      return decrypted_data

    def generate_key(self, key_length=16, vigenere = False): #default AES key, increase if needed
        """Generates a secure random key for use by algorithms."""
        if vigenere:
            return ''.join(random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(key_length)) #Vigenere key is case sensitive, token_hex not valid
        return self.generator_hex(key_length // 2)

    def generator_hex(self, length = 8):
        from secrets import token_hex
        return token_hex(length) #Hex key, default to not expose the length

    @property
    def generator(self):
        from core.challenges.generator import ChallengeGenerator
        return ChallengeGenerator() #Challenge generator to use generate flag