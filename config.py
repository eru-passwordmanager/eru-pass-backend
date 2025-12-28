import os
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config():
    SECRET_KEY = os.getenv("SECRET_KEY", "fallback-secret")
    # INSTANCE_PATH = os.path.join(BASE_DIR, "instance")
    VAULT_DB_PATH = os.getenv(
        "VAULT_DB_PATH",
        os.path.join(os.path.dirname(__file__), "instance","passman.db")
    )