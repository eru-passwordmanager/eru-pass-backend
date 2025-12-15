from flask import Flask
from config import Config


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    from route import deneme_bp
    app.register_blueprint(deneme_bp)

    return app