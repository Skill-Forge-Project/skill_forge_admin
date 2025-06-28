import requests, os
from flask_jwt_extended import JWTManager, verify_jwt_in_request, get_jwt_identity
from functools import wraps
from flask import request, jsonify
from dotenv import load_dotenv
import logging
import app

logging.basicConfig(level=logging.ERROR)


def token_required(f):
    """Decorator to check if the request has a valid JWT token.

    Args:
        f (object): function to be decorated

    Returns:
        function object: function
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            verify_jwt_in_request()
        except Exception as e:
            app.logger.error(f"JWT verification failed: {e}")
            return jsonify({"error": "Unauthorized", "message": "Invalid token"}), 401
        return f(*args, **kwargs)
    return decorated
