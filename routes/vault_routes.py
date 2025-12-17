from flask import Blueprint, request, jsonify, current_app
import time

from db.connection import get_conn
from db.vault_meta_repo import meta_get, meta_set
from services.crypto.crypto_service import CryptoService, KdfParams, b64e, b64d
from services.vault.unlock_store import VaultService
from services.vault.auth import get_unlocked_key_or_401, get_bearer_token
from services.security.rate_limit import check_rate_limit
from services.security.password_strength import check_master_password_strength
from services.security.progressive_backoff import record_failure_and_delay, reset_failures

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

    strength = check_master_password_strength(master)
    if not strength["ok"]:
        return jsonify({
            "error":"Master password to weak",
            "score": strength["score"],
            "feedback": strength["feedback"]
        }), 400

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

@vault_bp.route("lock", methods=["POST"])
def lock_vault():
    token = get_bearer_token()

    # idempotent: return locked even token does not exist
    if not token:
        return jsonify({"ok": True, "locked": True})
    
    VaultService.revoke_token(token)
    reset_failures() # reset fail counter
    return jsonify({"ok": True, "locked":True})

@vault_bp.route("/unlock", methods=["POST"])
def unlock_vault():
    if not check_rate_limit("vault_unlock"):
        return jsonify({
            "error":"Too many attempts. Try again later."
        })

    body = request.get_json(silent=True) or {}
    master = body.get("master_password")

    if not master or not isinstance(master, str):
        return jsonify({"error":"master_password required"}), 400
    
    conn = get_conn(current_app.config["VAULT_DB_PATH"])
    try:
        # Is vault initalized ?
        salt_b64 = meta_get(conn, "kdf_salt")
        if salt_b64 is None:
            return jsonify({"error":"Vault not initialized"}), 400

        salt = b64d(salt_b64)
        params = KdfParams(
            n=int(meta_get(conn, "kdf_n")),
            r=int(meta_get(conn, "kdf_r")),
            p=int(meta_get(conn, "kdf_p")),
            length = int(meta_get(conn, "kdf_len"))
        )
        verify_blob = meta_get(conn, "verify_blob")

        key = CryptoService.derive_key(master, salt, params)

        if not CryptoService.check_verify_blob(key, verify_blob):
            record_failure_and_delay() # progressive backoff
            return jsonify({"error":"Invalid master password"}), 401
        
        token = VaultService.create_unlock_session(key)
        reset_failures() # fail counter reset
        return jsonify({
            "ok":True,
            "unlocked":True,
            "token": token
        })

    except ValueError as err:
        return jsonify({"message":str(err)}), 400
    finally:
        conn.close()

@vault_bp.route("/change-master", methods=["POST"])
def change_master_password():
    # Vault locker or unlocked ? 
    _, err = get_unlocked_key_or_401()
    if err:
        msg, code = err
        return jsonify({"error": msg}), code
    
    body = request.get_json(silent=True) or {}
    current_master_password = body.get("current_master_password")
    new_master_password = body.get("new_master_password")

    strength = check_master_password_strength(new_master_password)
    if not strength["ok"]:
        return jsonify({
            "error":"New master password too weak",
            "score": strength["score"],
            "feedback": strength["feedback"]
        }), 400

    if not current_master_password or not isinstance(current_master_password, str):
        return jsonify({"error": "current_master_password required"}), 400
    
    if not new_master_password or not isinstance(new_master_password, str) or len(new_master_password) < 6:
        return jsonify({"error": "new_master_password required (min 6 character)"}), 400
    
    conn = get_conn(current_app.config["VAULT_DB_PATH"])

    try:
        # read meta
        salt_b64 = meta_get(conn, "kdf_salt")
        if salt_b64 is None:
            return jsonify({"error":"Vault not initialized"}), 400

        params = KdfParams(
            n = int(meta_get(conn, "kdf_n")),
            r = int(meta_get(conn, "kdf_r")),
            p = int(meta_get(conn, "kdf_p")),
            length = int(meta_get(conn, "kdf_len")),
        )

        old_salt = b64d(salt_b64)
        verify_blob = meta_get(conn, "verify_blob")

        # Is current master password correct ?
        old_key = CryptoService.derive_key(current_master_password, old_salt, params)
        if not CryptoService.check_verify_blob(old_key, verify_blob):
            return jsonify({"error": "Invalid current master password"}), 401
        
        # new key 
        new_salt = CryptoService.generate_salt(16)
        new_key = CryptoService.derive_key(new_master_password, new_salt, params)
        new_verify_blob = CryptoService.make_verify_blob(new_key)

        # start a transaction
        conn.execute("BEGIN")

        # re-encrypt all items
        cursor = conn.cursor()
        cursor.execute("SELECT id, type, encrypted_data FROM vault_items")
        rows = cursor.fetchall()

        for row in rows:
            item_id = row["id"]
            item_type = row["type"]
            enc = row["encrypted_data"]

            aad = f"item:{item_type}".encode("utf-8")

            # decrypt with old key
            plaintext = CryptoService.decrypt_from_string(old_key, enc, aad=aad)

            # encrypt with new key
            new_enc = CryptoService.encrypt_to_string(new_key, plaintext, aad=aad)

            cursor.execute(
                "UPDATE vault_items SET encrypted_data = ?, updated_at = ? WHERE id = ?",
                (new_enc, int(time.time()), item_id),
            )

        # update meta
        meta_set(conn, "kdf_salt", b64e(new_salt))
        meta_set(conn, "verify_blob", new_verify_blob)
        meta_set(conn, "master_changed_at", str(int(time.time())))

        conn.commit()

        VaultService.revoke_all()

        return jsonify({"ok":True})

    except Exception as e:
        # if any wrong thing happens in the middle of this, rollback all process
        try:
            conn.rollback()
        except Exception:
            pass
        return jsonify({"error":"Master password change failed","detail": str(e)}), 500
    finally:
        conn.close()