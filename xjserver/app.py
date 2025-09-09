import os
import sys
from flask import Flask, session, request, redirect, url_for

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'your-secret-key-change-this')

import admin_routes
import api_endpoints

sys.stdout.reconfigure(line_buffering=True)

PUBLIC_ROUTES = [
    'login', 'register', 'api_ping', 'static',
    'pending_adoption', 'api_adoption_status'
]

@app.before_request
def check_authentication():
    if request.endpoint in PUBLIC_ROUTES:
        return None
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    from database import get_db
    conn = get_db()
    c = conn.cursor()
    username = session.get('username')
    if not username:
        session.clear()
        return redirect(url_for('login'))
    c.execute('SELECT 1 FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    conn.close()
    if not user:
        session.clear()
        return redirect(url_for('login'))

@app.route('/')
def index():
    return redirect(url_for('admin'))

def initialize_app():
    print("🚀 Initializing HTTP server...")
    admin_routes.create_admin_routes(app)
    api_endpoints.create_api_routes(app, None)
    print("✅ server apps initialization complete")

initialize_app()