from flask import request
from services.vault.unlock_store import VaultService

def get_unlocked_key_or_401():
    auth =  request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer"):
        return None, ("Missing Authorization header", 401)
    
    token = auth.removeprefix("Bearer ").strip()
    key = VaultService.get_key_by_token(token)

    if key is None:
        return None, ("Vault locked or invalid token", 401)
    
    return key, None

def get_bearer_token():
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        return None
    return auth.removeprefix("Bearer ").strip()