class VigenereCipher:
    def __init__(self, key):
        self.key = key.upper()

    def encrypt(self, plaintext):
        plaintext = plaintext.upper()
        key_len = len(self.key)
        ciphertext = ''
        key_index = 0
        for i in range(len(plaintext)):
            char = plaintext[i]
            if 'A' <= char <= 'Z':
                key_char = self.key[key_index % key_len]
                key_shift = ord(key_char) - ord('A')
                encrypted_char = chr(((ord(char) - ord('A') + key_shift) % 26) + ord('A'))
                ciphertext += encrypted_char
                key_index += 1
            else:
                ciphertext += char  # Non-alphabetic characters remain unchanged
        return ciphertext

    def decrypt(self, ciphertext):
        ciphertext = ciphertext.upper()
        key_len = len(self.key)
        plaintext = ''
        key_index = 0
        for i in range(len(ciphertext)):
            char = ciphertext[i]
            if 'A' <= char <= 'Z':
                key_char = self.key[key_index % key_len]
                key_shift = ord(key_char) - ord('A')
                decrypted_char = chr(((ord(char) - ord('A') - key_shift + 26) % 26) + ord('A'))
                plaintext += decrypted_char
                key_index += 1
            else:
                plaintext += char
        return plaintext