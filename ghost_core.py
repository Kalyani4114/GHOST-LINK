import os
import math
import random
import secrets
import struct
import hashlib
import numpy as np
from PIL import Image, ImageEnhance
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class GhostEngine:
    def __init__(self):
        self.marker = b"$$GHOST$$" 

    # --- CRYPTOGRAPHY ---
    def derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=salt,
            iterations=100000, backend=default_backend()
        )
        return kdf.derive(password.encode())

    def encrypt_payload(self, message: str, password: str) -> bytes:
        salt = secrets.token_bytes(16)
        key = self.derive_key(password, salt)
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)
        data = message.encode() + self.marker
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return salt + nonce + ciphertext

    def decrypt_payload(self, encrypted_package: bytes, password: str) -> str:
        try:
            salt = encrypted_package[:16]
            nonce = encrypted_package[16:28]
            ciphertext = encrypted_package[28:]
            key = self.derive_key(password, salt)
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            if self.marker not in plaintext:
                raise ValueError("Invalid Marker")
            return plaintext.replace(self.marker, b"").decode()
        except Exception:
            return None

    # --- CHAOS & STEGANOGRAPHY ---
    def generate_chaos_path(self, password: str, total_pixels: int):
        hash_obj = hashlib.sha256(password.encode())
        seed_val = int(hash_obj.hexdigest(), 16) % (2**32)
        random.seed(seed_val)
        path = list(range(total_pixels))
        random.shuffle(path)
        return path

    def calculate_entropy(self, img: Image) -> float:
        histogram = img.histogram()
        total_pixels = sum(histogram)
        entropy = 0
        for count in histogram:
            if count == 0: continue
            p = count / total_pixels
            entropy -= p * math.log2(p)
        return entropy

    def embed_data(self, img_path: str, message: str, password: str, output_path: str):
        try:
            img = Image.open(img_path).convert("RGB")
            pixels = np.array(img, dtype=np.uint8)
            shape = pixels.shape
            flat_pixels = pixels.reshape(-1, 3)
            
            encrypted_data = self.encrypt_payload(message, password)
            data_len = len(encrypted_data)
            len_bytes = struct.pack('>I', data_len) 
            full_payload = len_bytes + encrypted_data
            
            binary_data = ''.join(f'{byte:08b}' for byte in full_payload)
            
            if len(binary_data) > len(flat_pixels):
                return False, "Data too large for image."

            chaos_indices = self.generate_chaos_path(password, len(flat_pixels))
            
            for i, bit in enumerate(binary_data):
                idx = chaos_indices[i]
                val = flat_pixels[idx][2]
                flat_pixels[idx][2] = (val & 254) | int(bit)

            new_pixels = flat_pixels.reshape(shape)
            stego_img = Image.fromarray(new_pixels, 'RGB')
            stego_img.save(output_path, "PNG")
            return True, "Success"
        except Exception as e:
            return False, str(e)

    def extract_data(self, img_path: str, password: str):
        try:
            img = Image.open(img_path).convert("RGB")
            pixels = np.array(img, dtype=np.uint8)
            flat_pixels = pixels.reshape(-1, 3)
            chaos_indices = self.generate_chaos_path(password, len(flat_pixels))
            
            header_bits = []
            for i in range(32):
                idx = chaos_indices[i]
                header_bits.append(str(flat_pixels[idx][2] & 1))
            
            header_bytes = int("".join(header_bits), 2).to_bytes(4, byteorder='big')
            data_len = struct.unpack('>I', header_bytes)[0]
            
            if data_len > len(flat_pixels) or data_len == 0:
                return False, "Decryption Failed."

            total_bits_needed = data_len * 8
            payload_bits = []
            for i in range(total_bits_needed):
                idx = chaos_indices[i + 32] 
                payload_bits.append(str(flat_pixels[idx][2] & 1))
                
            payload_str = "".join(payload_bits)
            byte_array = bytearray()
            for i in range(0, len(payload_str), 8):
                byte_array.append(int(payload_str[i:i+8], 2))
                
            result = self.decrypt_payload(bytes(byte_array), password)
            if result: return True, result
            else: return False, "Decryption Failed."
        except Exception as e:
            return False, str(e)

    def generate_heatmap(self, img_path: str, password: str, output_path: str):
        """
        Generates a cleaner, sharper Difference Map.
        """
        img = Image.open(img_path).convert("RGB")
        width, height = img.size
        total_pixels = width * height
        
        chaos_indices = self.generate_chaos_path(password, total_pixels)
        pixels = img.load()
        
        # REDUCE CLUTTER: Only show 5,000 bits (instead of 15,000)
        limit = min(5000, total_pixels)
        
        for i in range(limit):
            idx = chaos_indices[i]
            x = idx % width
            y = idx // width
            
            # MAKE IT SHARPER: 2x2 Block (Small but visible)
            # This prevents the "Big Blob" effect
            for dx in range(2):
                for dy in range(2):
                    nx, ny = x + dx, y + dy
                    if 0 <= nx < width and 0 <= ny < height:
                        pixels[nx, ny] = (255, 0, 0) # RED
            
        img.save(output_path)
        return output_path