from flask import Flask
from config import Config
from flask_cors import CORS
import os
from db.db_init import init_db

def create_app():
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(Config)

    CORS(
        app,
        resources={r"/*": {"origins": "http://localhost:5173"}},
        supports_credentials=True,
    )

    os.makedirs(app.instance_path, exist_ok=True)
    
    #if not os.path.exists(app.config["VAULT_DB_PATH"]):
    init_db(app.config["VAULT_DB_PATH"])

    #print("VAULT DB PATH:", app.config["VAULT_DB_PATH"])

    from routes.health import health_bp
    from routes.vault_routes import vault_bp
    from routes.items.items_route import items_bp
    app.register_blueprint(health_bp)
    app.register_blueprint(vault_bp)
    app.register_blueprint(items_bp)

    return app