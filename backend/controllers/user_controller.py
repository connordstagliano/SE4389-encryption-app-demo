from flask import request, jsonify, Blueprint, current_app, g
from datetime import datetime, timedelta, timezone
import uuid
import jwt
from services.user_service import create_user, verify_user_and_get_root, rotate_user_password
from decorators.auth_guard import auth_guard

user_bp = Blueprint('user', __name__)

@user_bp.route('/signup', methods=['POST'])
def signup():
    if not request.is_json:
        return jsonify(error="Expected application/json"), 400

    data = request.get_json(silent=True)
    if not data or 'username' not in data or 'password' not in data:
        return jsonify(error="Missing username/password"), 400

    if not isinstance(data['username'], str) or not isinstance(data['password'], str):
        return jsonify(error="Invalid types"), 400

    if len(data['username']) == 0 or len(data['username']) > 128:
        return jsonify(error="username length invalid"), 400

    if len(data['password']) == 0 or len(data['password']) > 1024:
        return jsonify(error="password length invalid"), 400

    try:
        user = create_user(current_app.config['storage'], data['username'], data['password'])

        return jsonify(message="User created", username=user.username), 201
    except ValueError as e:
        return jsonify(error=str(e)), 400

@user_bp.route('/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify(error="Expected application/json"), 400

    data = request.get_json(silent=True)
    if not data or 'username' not in data or 'password' not in data:
        return jsonify(error="Invalid credentials"), 400

    try:
        root_key = verify_user_and_get_root(current_app.config['storage'], data['username'], data['password'])

        session_store = current_app.config.get('session_store')
        if session_store is None:
            return jsonify(error="Server misconfiguration"), 500

        sid = session_store.create(data['username'], root_key, ttl_seconds=3600)

        now = datetime.now(timezone.utc)
        claims = {
            'iss': 'taco-backend',
            'sub': data['username'],
            'sid': sid,
            'iat': int(now.timestamp()),
            'nbf': int(now.timestamp()),
            'exp': int((now + timedelta(hours=1)).timestamp()),
            'jti': str(uuid.uuid4()),
        }
        token = jwt.encode(
            claims,
            current_app.config['SECRET_KEY'],
            algorithm='HS256'
        )

        return jsonify(message="Login successful", token=token), 200
    except ValueError as e:
        return jsonify(error=str(e)), 401

@user_bp.route('/rotate', methods=['PUT'])
@auth_guard
def rotate():
    if not request.is_json:
        return jsonify(error="Expected application/json"), 400

    data = request.get_json(silent=True)

    if not data or 'new_password' not in data or 'current_password' not in data:
        return jsonify(error="Missing current_password/new_password"), 400

    if not isinstance(data['new_password'], str) or not isinstance(data['current_password'], str):
        return jsonify(error="Invalid types"), 400

    if len(data['new_password']) == 0 or len(data['new_password']) > 1024:
        return jsonify(error="new_password length invalid"), 400

    try:
        rotate_user_password(
            current_app.config['storage'],
            g.username,
            data['current_password'],
            data['new_password']
        )

        return jsonify(message="Password rotated"), 200
    except ValueError as e:
        return jsonify(error=str(e)), 400