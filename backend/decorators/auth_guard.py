from flask import request, jsonify, current_app, g
from functools import wraps
import jwt
from typing import Callable

def auth_guard(f: Callable) -> Callable:
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify(error="Missing or invalid Authorization header"), 401

        try:
            token = auth_header.split(' ')[1]
            payload = jwt.decode(
                token,
                current_app.config['SECRET_KEY'],
                algorithms=['HS256'],
                options={
                    'require': ['exp', 'iat', 'nbf', 'jti'],
                    'verify_signature': True,
                    'verify_exp': True,
                    'verify_iat': True,
                    'verify_nbf': True,
                },
                audience=None,
                issuer='taco-backend',
            )

            sid = payload.get('sid')
            if not sid:
                return jsonify(error="Invalid token"), 401

            session_store = current_app.config.get('session_store')
            if session_store is None:
                return jsonify(error="Server misconfiguration"), 500

            try:
                username, root_key = session_store.get(sid)
            except KeyError:
                return jsonify(error="Session expired or invalid"), 401

            g.username = username
            g.root_key = root_key

        except jwt.ExpiredSignatureError:
            return jsonify(error="Token expired"), 401
        except jwt.InvalidTokenError:
            return jsonify(error="Invalid token"), 401

        return f(*args, **kwargs)

    return decorated