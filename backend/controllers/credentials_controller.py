from flask import request, jsonify, Blueprint, current_app, g
from decorators.auth_guard import auth_guard
from services.credential_service import add_credential, check_credential_dup, get_credentials

credentials_bp = Blueprint('credentials', __name__)

@credentials_bp.route('/', methods=['POST'])
@auth_guard
def add_cred():
    if not request.is_json:
        return jsonify(error="Expected application/json"), 400
    data = request.get_json(silent=True)
    required = ['site', 'account', 'site_password']
    if not data or any(k not in data for k in required):
        return jsonify(error="Missing fields"), 400
    if not all(isinstance(data[k], str) for k in required):
        return jsonify(error="Invalid types"), 400
    if any(len(data[k]) == 0 for k in required):
        return jsonify(error="Empty fields not allowed"), 400
    if len(data['site']) > 512 or len(data['account']) > 512:
        return jsonify(error="Field length too large"), 400
    if len(data['site_password']) > 4096:
        return jsonify(error="Password too long"), 400

    try:
        cred = add_credential(
            current_app.config['storage'], g.username, g.root_key,
            data['site'], data['account'], data['site_password']
        )

        return jsonify(message="Credential added", site=cred.site, account=cred.account), 201
    except ValueError as e:
        return jsonify(error=str(e)), 400

@credentials_bp.route('/', methods=['GET'])
@auth_guard
def get_creds():
    # get all credentials
    try:
        creds = get_credentials(current_app.config['storage'], g.username, g.root_key)
        return jsonify(credentials=creds), 200
    except ValueError as e:
        return jsonify(error=str(e)), 400
    

@credentials_bp.route('/check', methods=['POST'])
@auth_guard
def check_dup():
    if not request.is_json:
        return jsonify(error="Expected application/json"), 400
    data = request.get_json(silent=True)
    required = ['site', 'account', 'site_password']
    if not data or any(k not in data for k in required):
        return jsonify(error="Missing fields"), 400
    if not all(isinstance(data[k], str) for k in required):
        return jsonify(error="Invalid types"), 400
    if any(len(data[k]) == 0 for k in required):
        return jsonify(error="Empty fields not allowed"), 400
    if len(data['site']) > 512 or len(data['account']) > 512:
        return jsonify(error="Field length too large"), 400
    if len(data['site_password']) > 4096:
        return jsonify(error="Password too long"), 400
    
    msg, warning = check_credential_dup(current_app.config['storage'], g.username, g.root_key, data['site_password'])

    return jsonify(message=msg, warning=warning), 200