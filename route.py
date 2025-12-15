from flask import Blueprint, request, jsonify
deneme_bp = Blueprint("deneme_bp", __name__, url_prefix="/")

@deneme_bp.get("/")
def hello_world():
    return jsonify({"helllo":"hellooo"})