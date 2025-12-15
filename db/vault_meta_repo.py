import sqlite3
from typing import Optional

def meta_get(conn: sqlite3.Connection, key:str): # Optional[str]
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM vault_meta WHERE key= ?",(key,))
    row = cursor.fetchone()
    return row[0] if row else None

def meta_set(conn: sqlite3.Connection, key:str, value:str): # -> None
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO vault_meta(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value),
    )