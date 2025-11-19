from core.crypto.challenge_layer import ChallengeLayer
from config.security import HINT_POINTS_DEDUCTION

class EncryptionManager:
    def __init__(self):
        self.challenge_layer = ChallengeLayer()

    def encrypt_message(self, message, encryption_type, difficulty="easy"):
        encrypted_data, layers = self.challenge_layer.apply_layers(message, encryption_type, difficulty)
        return {
            "original_message": message,
            "encryption_type": encryption_type,
            "difficulty": difficulty,
            "layers": layers,
            "final_encrypted": encrypted_data,
            "total_layers": len(layers)
        }

    def generate_hints(self, encryption_info):
        hints = []
        layers = encryption_info["layers"]
        difficulty = encryption_info["difficulty"]

        hints.append(f"This is a {encryption_info['encryption_type'].upper()} challenge.")
        hints.append(f"Total layers: {encryption_info['total_layers']}.")

        for i, layer in enumerate(layers):
            if layer["type"] == "aes":
                hints.append(f"Layer {i+1}: AES with IV {layer['iv']}.")
            elif layer["type"] == "vigenere":
                hints.append(f"Layer {i+1}: Vigenère with a {len(layer['key'])}-letter key.")
            elif layer["type"] == "rsa":
                hints.append(f"Layer {i+1}: RSA with public key provided.")

        if difficulty == "easy":
            hints.append("Start with the basics of the encryption type.")
        elif difficulty == "medium":
            hints.append("Multiple steps required; check layer order.")
        else:
            hints.append("Advanced techniques needed for multiple layers.")

        # Assign costs to hints (incremental)
        return [{"text": hint, "cost": HINT_POINTS_DEDUCTION * (i + 1)} for i, hint in enumerate(hints)]

    def get_decryption_steps(self, encryption_info):
        steps = []
        for i, layer in enumerate(reversed(encryption_info["layers"])):
            step = {
                "layer_number": i + 1,
                "type": layer["type"],
                "description": f"Decrypt layer {i+1} using {layer['type'].upper()}"
            }
            if layer["type"] == "aes":
                step["details"] = {"key": layer["key"], "iv": layer["iv"]}
            elif layer["type"] == "vigenere":
                step["details"] = {"key": layer["key"]}
            elif layer["type"] == "rsa":
                step["details"] = {"public_key": layer["public_key"], "private_key": "hidden"}
            steps.append(step)
        return steps