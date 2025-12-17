import secrets
import time
from typing import Optional

_UNLOCKED = {} # token -> {key: bytes, last_used: int}

IDLE_TIMEOUT = 60 # seconds

def _zeroize(buf: bytearray):
        """
        Docstring for _zeroize
        
        :param buf: Description
        :type buf: bytearray

        Best-effort memory wipe
        """
        for i in range(len(buf)):
            buf[i] = 0

class VaultService:

    @staticmethod
    def create_unlock_session(key: bytes): #-> str
        token = secrets.token_urlsafe(32)

        # bytes -> bytearray (mutable)
        key_buf = bytearray(key)

        _UNLOCKED[token] = {
            "key":key_buf,
            "last_used": int(time.time()),
        }
        return token
    
    @staticmethod
    def get_key_by_token(token: str): #-> Optional[bytes]
        entry = _UNLOCKED.get(token)
        if not entry:
            return None
        
        now = int(time.time())

        # auto lock control
        if now - entry["last_used"] > IDLE_TIMEOUT:
            VaultService._revoke_entry(token, entry)
            return None
        
        entry["last_used"] = now
        # bytes for AESGCM
        return bytes(entry["key"])
    
    @staticmethod
    def revoke_token(token: str): # -> None
        entry = _UNLOCKED.get(token)
        if entry:
            VaultService._revoke_entry(token, entry)

    @staticmethod
    def revoke_all(): # -> None:
        for token, entry in list(_UNLOCKED.items()):
            VaultService._revoke_entry(token, entry)

    @staticmethod
    def _revoke_entry(token:str, entry:dict):
        key_buf = entry.get("key")
        if isinstance(key_buf, bytearray):
            _zeroize(key_buf)

        _UNLOCKED.pop(token, None)


