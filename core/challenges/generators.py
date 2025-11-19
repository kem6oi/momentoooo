import os
import random
import string
from core.crypto.ciphers import XORCipher, DESCipher, RC4Cipher, BlowfishCipher, HashFunction
from typing import Tuple, Dict, Any
import yara
import volatility3
import scapy.all as scapy

class ChallengeGenerator:
    @staticmethod
    def generate_random_string(length: int) -> str:
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    @staticmethod
    def generate_xor_challenge(difficulty: str) -> Tuple[str, str, Dict[str, Any]]:
        key_lengths = {'easy': 4, 'medium': 8, 'hard': 16}
        key = os.urandom(key_lengths[difficulty])
        flag = f"FLAG{{XOR-{ChallengeGenerator.generate_random_string(16)}}}"
        cipher = XORCipher(key)
        encrypted_flag = cipher.encrypt(flag.encode())
        
        return encrypted_flag.hex(), flag, {
            'type': 'xor',
            'difficulty': difficulty,
            'key_length': len(key),
            'hints': [
                f"The key length is {len(key)} bytes",
                "XOR encryption is its own inverse",
                "Try frequency analysis on the ciphertext"
            ]
        }

    @staticmethod
    def generate_des_challenge(difficulty: str) -> Tuple[str, str, Dict[str, Any]]:
        key = os.urandom(8)  # DES uses 64-bit (8-byte) keys
        flag = f"FLAG{{DES-{ChallengeGenerator.generate_random_string(16)}}}"
        cipher = DESCipher(key)
        encrypted_flag = cipher.encrypt(flag.encode())
        
        hints = {
            'easy': ["The key might be weak", "Check for weak key patterns"],
            'medium': ["Try known-plaintext attack", "The flag format is known"],
            'hard': ["Consider meet-in-the-middle attack", "Multiple encryptions used"]
        }
        
        return encrypted_flag.hex(), flag, {
            'type': 'des',
            'difficulty': difficulty,
            'hints': hints[difficulty]
        }

    @staticmethod
    def generate_rc4_challenge(difficulty: str) -> Tuple[str, str, Dict[str, Any]]:
        key_lengths = {'easy': 8, 'medium': 16, 'hard': 32}
        key = os.urandom(key_lengths[difficulty])
        flag = f"FLAG{{RC4-{ChallengeGenerator.generate_random_string(16)}}}"
        cipher = RC4Cipher(key)
        encrypted_flag = cipher.encrypt(flag.encode())
        
        return encrypted_flag.hex(), flag, {
            'type': 'rc4',
            'difficulty': difficulty,
            'key_length': len(key),
            'hints': [
                "RC4 is vulnerable to statistical attacks",
                "The first few bytes of the keystream might be weak",
                "Consider bias in the output stream"
            ]
        }

    @staticmethod
    def generate_blowfish_challenge(difficulty: str) -> Tuple[str, str, Dict[str, Any]]:
        key_lengths = {'easy': 8, 'medium': 16, 'hard': 32}
        key = os.urandom(key_lengths[difficulty])
        flag = f"FLAG{{BF-{ChallengeGenerator.generate_random_string(16)}}}"
        cipher = BlowfishCipher(key)
        encrypted_flag = cipher.encrypt(flag.encode())
        
        return encrypted_flag.hex(), flag, {
            'type': 'blowfish',
            'difficulty': difficulty,
            'key_length': len(key),
            'hints': [
                f"The key length is {len(key)} bytes",
                "Blowfish uses a 64-bit block size",
                "Check for weak keys in the key schedule"
            ]
        }

    @staticmethod
    def generate_hash_challenge(difficulty: str) -> Tuple[str, str, Dict[str, Any]]:
        flag = f"FLAG{{HASH-{ChallengeGenerator.generate_random_string(16)}}}"
        hash_types = {
            'easy': 'md5',
            'medium': 'sha256',
            'hard': 'sha512'
        }
        hash_type = hash_types[difficulty]
        hashed_flag = getattr(HashFunction, hash_type)(flag.encode()).hex()
        
        return hashed_flag, flag, {
            'type': 'hash',
            'difficulty': difficulty,
            'hash_type': hash_type,
            'hints': [
                f"This is a {hash_type.upper()} hash",
                "Consider rainbow table attacks",
                "The flag format is known"
            ]
        }

    @staticmethod
    def generate_web_challenge(difficulty: str) -> Tuple[str, Dict[str, Any]]:
        vulnerabilities = {
            'easy': ['xss', 'sqli', 'idor'],
            'medium': ['csrf', 'xxe', 'ssrf'],
            'hard': ['rce', 'deserialization', 'jwt']
        }
        vuln_type = random.choice(vulnerabilities[difficulty])
        flag = f"FLAG{{WEB-{vuln_type.upper()}-{ChallengeGenerator.generate_random_string(8)}}}"
        
        return flag, {
            'type': 'web',
            'difficulty': difficulty,
            'vulnerability': vuln_type,
            'hints': [
                f"Look for {vuln_type.upper()} vulnerabilities",
                "Check the request/response headers",
                "Consider using automated scanning tools"
            ]
        }

    @staticmethod
    def generate_binary_challenge(difficulty: str) -> Tuple[str, Dict[str, Any]]:
        techniques = {
            'easy': ['buffer-overflow', 'format-string'],
            'medium': ['rop', 'heap-overflow'],
            'hard': ['kernel-exploit', 'race-condition']
        }
        technique = random.choice(techniques[difficulty])
        flag = f"FLAG{{BIN-{technique.upper()}-{ChallengeGenerator.generate_random_string(8)}}}"
        
        return flag, {
            'type': 'binary',
            'difficulty': difficulty,
            'technique': technique,
            'hints': [
                f"This challenge involves {technique} exploitation",
                "Check for memory corruption",
                "Use a debugger to analyze the binary"
            ]
        }

    @staticmethod
    def generate_forensics_challenge(difficulty: str) -> Tuple[str, Dict[str, Any]]:
        types = {
            'easy': ['file-carving', 'metadata'],
            'medium': ['memory-dump', 'network-capture'],
            'hard': ['disk-image', 'malware-analysis']
        }
        forensic_type = random.choice(types[difficulty])
        flag = f"FLAG{{FOR-{forensic_type.upper()}-{ChallengeGenerator.generate_random_string(8)}}}"
        
        return flag, {
            'type': 'forensics',
            'difficulty': difficulty,
            'forensic_type': forensic_type,
            'hints': [
                f"This is a {forensic_type} analysis challenge",
                "Consider using specialized forensics tools",
                "Look for hidden data or deleted files"
            ]
        } 