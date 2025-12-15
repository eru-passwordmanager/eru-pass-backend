from flask import Blueprint, request, jsonify, current_app
import time

from db.connection import get_conn
from db.vault_meta_repo import meta_get, meta_set
from services.crypto.crypto_service import CryptoService, KdfParams, b64e

vault_bp = Blueprint("vault_bp", __name__, url_prefix="/api/vault")

@vault_bp.route("/status", methods=["GET"])
def status():
    conn = get_conn(current_app.config["VAULT_DB_PATH"])
    try:
        initialized = meta_get(conn, "kdf_salt") is not None
        return jsonify({"initialized": initialized})
    except ValueError as err:
        return jsonify({"message":str(err)}), 400
    finally:
        conn.close()

@vault_bp.route("/init", methods=["POST"])
def init_vault():
    """
    Docstring for init_vault
    - produce salt
    - master_password + salt -> key
    - produce verify blob to check if master is correct or not
    - write into vault_meta
    """

    body = request.get_json(silent=True) or {}
    master = body.get("master_password")

    if not master or not isinstance(master, str) or len(master) < 4:
        return jsonify({"error": "master_password required (min 4 chars)"}), 400
    
    conn = get_conn(current_app.config["VAULT_DB_PATH"])
    try:
        if meta_get(conn, "kdf_salt") is not None:
            return jsonify({"error": "Vault already initialized"}), 409
        
        params = KdfParams()
        salt = CryptoService.generate_salt(16)
        key = CryptoService.derive_key(master, salt, params)

        verify_blob = CryptoService.make_verify_blob(key)

        meta_set(conn, "vault_version", "1")
        meta_set(conn, "kdf_salt", b64e(salt))
        meta_set(conn, "kdf_n", str(params.n))
        meta_set(conn, "kdf_r", str(params.r))
        meta_set(conn, "kdf_p", str(params.p))
        meta_set(conn, "kdf_len", str(params.length))
        meta_set(conn, "verify_blob", verify_blob)
        meta_set(conn, "created_at", str(int(time.time())))

        conn.commit()
        return jsonify({"ok":True, "initialized":True})
    except ValueError as err:
        return jsonify({"message":str(err)}), 400
    finally:
        conn.close()
