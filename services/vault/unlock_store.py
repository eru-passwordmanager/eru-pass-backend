import secrets
import time
from typing import Optional

_UNLOCKED = {} # token -> {key: bytes, last_used: int}

IDLE_TIMEOUT = 60 # seconds

class VaultService:

    @staticmethod
    def create_unlock_session(key: bytes): #-> str
        token = secrets.token_urlsafe(32)
        _UNLOCKED[token] = {
            "key":key,
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
            _UNLOCKED.pop(token, None)
            return None
        
        entry["last_used"] = now
        return entry["key"]
    
    @staticmethod
    def revoke_token(token: str): # -> None
        _UNLOCKED.pop(token, None)

    @staticmethod
    def revoke_all(): # -> None:
        _UNLOCKED.clear()


