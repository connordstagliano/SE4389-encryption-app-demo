import os
from flask import Flask
from dotenv import load_dotenv
from controllers.user_controller import user_bp
from controllers.credentials_controller import credentials_bp
from storage.json_storage import JsonStorage
from storage.file_session_store import FileSessionStore

load_dotenv('./.env')

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['storage'] = JsonStorage()
app.config['session_store'] = FileSessionStore()
app.config['MAX_CONTENT_LENGTH'] = 1024 * 32


@app.after_request
def set_security_headers(resp):
    resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
    resp.headers.setdefault('X-Frame-Options', 'DENY')
    resp.headers.setdefault('X-XSS-Protection', '0')
    resp.headers.setdefault('Referrer-Policy', 'no-referrer')
    resp.headers.setdefault('Cache-Control', 'no-store')
    return resp

app.register_blueprint(user_bp, url_prefix='/auth')
app.register_blueprint(credentials_bp, url_prefix='/credentials')

if __name__ == '__main__':
    app.run(debug=True)