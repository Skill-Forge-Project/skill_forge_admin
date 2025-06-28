import os, requests
from flask import Blueprint, request, jsonify
from flask_jwt_extended import get_jwt_identity
from extensions import db
from services import token_required
from sqlalchemy import text
from dotenv import load_dotenv
import app

load_dotenv()

AUTH_SERVICE_URL = os.getenv("AUTH_SERVICE_URL")
INTERNAL_SECRET = os.getenv("INTERNAL_SECRET")
GENERIC_ERROR_MESSAGE = "An internal error has occurred."

admin_bp = Blueprint('admin', __name__)

# Check if admin service is running
@admin_bp.route('/admin/health', methods=['GET'])
@token_required
def health_check():
    """
    Health check endpoint to verify the service is running.
    """
    return jsonify({"status": "ok"}), 200

# Download logs endpoint
@admin_bp.route('/admin/metrics', methods=['GET'])
@token_required
def get_metrics():
    """
    Endpoint to retrieve application metrics.
    """
    try:
        metrics = app.get_metrics()
        return jsonify(metrics), 200
    except Exception as e:
        app.logger.error(f"Error retrieving metrics: {e}")
        return jsonify({"error": GENERIC_ERROR_MESSAGE}), 500

# Clear cache endpoint
@admin_bp.route('/admin/clear_cache', methods=['POST'])
@token_required
def clear_cache():
    """
    Endpoint to clear the cache.
    """
    try:
        app.clear_cache()
        return jsonify({"message": "Cache cleared successfully"}), 200
    except Exception as e:
        app.logger.error(f"Error clearing cache: {e}")
        return jsonify({"error": GENERIC_ERROR_MESSAGE}), 500

# Check if user is admin
@admin_bp.route('/admin/check', methods=['GET'])
@token_required
def check_admin():
    """
    Endpoint to check if the user has an 'Admin' role by querying the database.
    """
    try:
        user_id = get_jwt_identity()
        if not user_id:
            return jsonify({"error": "User ID not found in token"}), 400

        user = db.session.execute(
            text("SELECT * FROM users WHERE id = :user_id"),
            {"user_id": user_id}
        ).fetchone()

        if not user:
            return jsonify({"error": "User not found"}), 404

        if user.user_role == "Admin":
            return jsonify({"message": "User is an admin"}), 200
        else:
            return jsonify({"error": "Forbidden", "message": "Admin access required"}), 403

    except Exception as e:
        app.logger.error(f"Error checking admin status: {e}")
        return jsonify({
            "error": "Internal Server Error",
            "message": GENERIC_ERROR_MESSAGE
        }), 500
