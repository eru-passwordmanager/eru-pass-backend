import secrets
from typing import Optional



class VaultService:

    _UNLOCKED = {}
    
    @staticmethod
    def create_unlock_session(key: bytes): #-> str
        token = secrets.token_urlsafe(32)
        VaultService._UNLOCKED[token] = key
        return token
    
    @staticmethod
    def get_key_by_token(token: str): #-> Optional[bytes]
        return VaultService._UNLOCKED.get(token)
    
    @staticmethod
    def revoke_token(token: str): # -> None
        VaultService._UNLOCKED.pop(token, None)

    @staticmethod
    def revoke_all(): # -> None:
        VaultService._UNLOCKED.clear()


