import sqlite3
import os

def init_db(db_path:str):
    os.makedirs(os.path.dirname(db_path), exist_ok=True)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS vault_items(
        id TEXT PRIMARY KEY,
        type TEXT NOT NULL,
        title TEXT NOT NULL,
        encrypted_data TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL           
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS vault_types(
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        display_name TEXT NOT NULL             
    );
    """)

    cursor.execute("""
    INSERT OR IGNORE INTO vault_types (id, name, display_name) VALUES
        ('web', 'web', 'Internet'),
        ('email', 'email', 'Email'),
        ('ssh', 'ssh', 'SSH Keys'),
        ('note', 'note', 'Secure Notes');
    """)


    conn.commit()
    conn.close()