import json
import time
import uuid

from flask import Blueprint, request, jsonify, current_app

from db.connection import get_conn
from services.crypto.crypto_service import CryptoService
from services.vault.auth import get_unlocked_key_or_401

items_bp = Blueprint("items_bp", __name__, url_prefix="/api/items")

@items_bp.route("/create", methods=["POST"])
def create_item():
    # Vault locked or unlocked ?
    key , err = get_unlocked_key_or_401()
    if err:
        msg, code = err
        return jsonify({"error": msg}), code
    
    body = request.get_json(silent=True) or {}

    item_type = body.get("type")
    title = body.get("title")
    payload = body.get("payload")

    if not item_type or not title or not isinstance(payload, dict):
        return jsonify({"error": "type, title, payload required"}), 400
    
    # payload to bytes
    plaintext = json.dumps(payload).encode("utf-8")

    encrypted_data = CryptoService.encrypt_to_string(
        key,
        plaintext,
        aad=f"item:{item_type}".encode("utf-8")
    )

    # db insert
    now = int(time.time())
    item_id = str(uuid.uuid4())

    conn = get_conn(current_app.config["VAULT_DB_PATH"])

    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO vault_items
            (id, type, title, encrypted_data, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (item_id, item_type, title, encrypted_data, now, now),
        )
        conn.commit()

        return jsonify({
            "ok":True,
            "id":item_id
        })
    except ValueError as err:
        return jsonify({"message":str(err)}), 400
    finally:
        conn.close()

@items_bp.route("/", methods=["GET"])
def list_items():
    # Vault locked or unlocked ?
    key, err = get_unlocked_key_or_401()
    if err:
        msg, code = err
        return jsonify({"error": msg}), code
    
    conn = get_conn(current_app.config["VAULT_DB_PATH"])

    try:
        cursor = conn.cursor()
        cursor.execute(
            """
                SELECT id, type, title, encrypted_data, created_at, updated_at
                FROM vault_items
                ORDER BY updated_at DESC
            """
        )
        rows = cursor.fetchall()

        items = []

        for row in rows:
            try:
                # decrypt
                plaintext = CryptoService.decrypt_from_string(
                    key,
                    row["encrypted_data"],
                    aad=f"item:{row['type']}".encode("utf-8") # integrity guard
                )

                payload = json.loads(plaintext.decode("utf-8"))

                items.append({
                    "id":row["id"],
                    "type":row["type"],
                    "title":row["title"],
                    "payload":payload,
                    "created_at": row["created_at"],
                    "updated_at": row["updated_at"],
                })

            except Exception:
                items.append({
                    "id":row["id"],
                    "type": row["type"],
                    "title": row["title"],
                    "error": "decrypt_failed"
                })

        return jsonify(items)

    finally:
        conn.close()

@items_bp.route("/<item_id>", methods=["GET"])
def get_item(item_id):
    key, err = get_unlocked_key_or_401()
    if err:
        msg, code = err
        return jsonify({"error": msg}), code
    
    conn = get_conn(current_app.config["VAULT_DB_PATH"])

    try:
        cursor = conn.cursor()
        cursor.execute(
            """
                SELECT id,type, title, encrypted_data, created_at, updated_at
                FROM vault_items
                WHERE id = ?
            """,
            (item_id,),
        )

        row = cursor.fetchone()

        if row is None:
            return jsonify({"error": "Item not found"}), 404
        
        plaintext = CryptoService.decrypt_from_string(
            key,
            row["encrypted_data"],
            aad=f"item:{row['type']}".encode("utf-8") # integrity
        )

        payload = json.loads(plaintext.decode("utf-8"))

        return jsonify({
            "id":row["id"],
            "type":row["type"],
            "title":row["title"],
            "payload":payload,
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        })

    except Exception:
        return jsonify({"error":"Failed to decrypt item"}), 500
    finally:
        conn.close()