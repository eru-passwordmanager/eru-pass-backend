import os
import base64
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def b64e(b: bytes): # -> str
    return base64.urlsafe_b64encode(b).decode("utf-8")

def b64d(s:str): # -> bytes
    return base64.urlsafe_b64decode(s.encode("utf-8"))

@dataclass(frozen=True)
class KdfParams:
    # Scrypt parameters
    n: int = 2**14
    r: int = 8
    p: int = 1
    length: int = 32 # AES-256 key => 32 byte

class CryptoService:
    """
    Docstring for CryptoService
    1) master_password + salt -> key(derive_key)
    2) plaintext -> "v1:nonce_b64:cipher_b64" (encrpt_to_string)
    3) string format -> plaintext (decrypt_from_string)
    """

    VERSION = "v1"

    @staticmethod
    def generate_salt(size: int = 16): # -> bytes
        return os.urandom(size)
    
    @staticmethod
    def derive_key(master_password: str, salt:bytes, params: KdfParams):
        pw_bytes = master_password.encode("utf-8")

        kdf = Scrypt(
            salt=salt,
            length=params.length,
            n=params.n,
            r=params.r,
            p=params.p
        )

        return kdf.derive(pw_bytes) # -> 32 byte key
    
    @staticmethod
    def encrypt_to_string(key: bytes, plaintext: bytes, aad: bytes | None = None): # -> str
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

        return f"{CryptoService.VERSION}:{b64e(nonce)}:{b64e(ciphertext)}"

    @staticmethod
    def decrypt_from_string(key: bytes, blob:str, aad: bytes | None = None): # -> bytes
        # format: v1:nonce_b64:cipher_b64
        parts = blob.split(":")
        if len(parts) != 3:
            raise ValueError("Invalid encrypted blob format")
        
        version, nonce_b64, cipher_b64 = parts
        if version != CryptoService.VERSION:
            raise ValueError(f"Unsupported version: {version}")
        
        nonce = b64d(nonce_b64)
        ciphertext = b64d(cipher_b64)

        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, aad)

    @staticmethod
    def make_verify_blob(key: bytes): # -> str
        return CryptoService.encrypt_to_string(key, b"vault-check", aad=b"meta")
    
    @staticmethod
    def check_verify_blob(key:bytes, verify_blob: str): # -> bool
        try:
            pt = CryptoService.decrypt_from_string(key, verify_blob, aad=b"meta")
            return pt == b"vault-check"
        except Exception:
            return False
    