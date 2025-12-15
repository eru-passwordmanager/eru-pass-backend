from flask import Blueprint, request, jsonify

health_bp = Blueprint("health_bp",__name__,url_prefix="/api")

@health_bp.route("/health",methods=["GET"])
def health():
    return jsonify({
        "status":"ok",
        "service":"erupass-backend"
    })