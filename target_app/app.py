#!/usr/bin/env python3
"""
Secure Web Application for CTI Pipeline Testing
This app is secure but uses vulnerable dependencies for testing.
"""

from flask import Flask, request, render_template_string, redirect, url_for, session, flash
import sqlite3
import hashlib
import secrets
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Secure database setup
def setup_db():
    """Create a secure database."""
    conn = sqlite3.connect('secure_app.db')
    cursor = conn.cursor()
    
    # Create users table with secure practices
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')
    
    # Insert some test data with secure password hashes
    cursor.execute("INSERT OR IGNORE INTO users (username, password_hash, role) VALUES (?, ?, ?)", 
                 ("admin", hashlib.sha256(b"secure_password_123!").hexdigest(), "admin"))
    cursor.execute("INSERT OR IGNORE INTO users (username, password_hash, role) VALUES (?, ?, ?)", 
                 ("user1", hashlib.sha256(b"user_password_456!").hexdigest(), "user"))
    
    conn.commit()
    conn.close()
    return True

def get_db_connection():
    """Get database connection with proper error handling."""
    try:
        conn = sqlite3.connect('secure_app.db')
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return None

def hash_password(password):
    """Secure password hashing."""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, hashed):
    """Verify password against hash."""
    return hash_password(password) == hashed

# Secure login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Username and password are required', 'error')
            return render_login_page()
        
        # Secure database query with parameterization
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, username, password_hash, role FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()
            conn.close()
            
            if user and verify_password(password, user['password_hash']):
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']
                
                # Update last login
                conn = get_db_connection()
                if conn:
                    cursor = conn.cursor()
                    cursor.execute("UPDATE users SET last_login = ? WHERE id = ?", 
                                 (datetime.now(), user['id']))
                    conn.commit()
                    conn.close()
                
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid username or password', 'error')
        
        return render_login_page()
    
    return render_login_page()

def render_login_page():
    """Render secure login page."""
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Secure App - Login</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 50px; background: #f5f5f5; }
        .container { max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h2 { text-align: center; color: #333; margin-bottom: 30px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 5px; color: #555; }
        input[type="text"], input[type="password"] { width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        button { width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
        button:hover { background: #0056b3; }
        .alert { padding: 10px; margin-bottom: 20px; border-radius: 4px; }
        .alert-error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .alert-success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Secure Application Login</h2>
        
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        <form method="POST">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
    ''')

# Secure dashboard route
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Secure App - Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; color: #333; }
        .info { background: #e7f3ff; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .nav { margin-bottom: 30px; }
        .nav a { margin-right: 20px; text-decoration: none; color: #007bff; }
        .nav a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Secure Dashboard</h1>
            <p>Welcome, {{ session.username }}!</p>
        </div>
        
        <div class="info">
            <h3>Application Information</h3>
            <p><strong>Status:</strong> ✅ Secure</p>
            <p><strong>Dependencies:</strong> Multiple vulnerable packages for testing</p>
            <p><strong>Database:</strong> SQLite with secure practices</p>
            <p><strong>Session:</strong> Secure token-based authentication</p>
        </div>
        
        <div class="nav">
            <a href="{{ url_for('packages') }}">📦 View Packages</a>
            <a href="{{ url_for('logout') }}">🚪 Logout</a>
        </div>
    </div>
</body>
</html>
    ''')

# Packages display route
@app.route('/packages')
def packages():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Simulate vulnerable packages info
    packages = [
        {
            'name': 'Flask',
            'version': '2.3.3',
            'cve': 'CVE-2023-30861',
            'severity': 'HIGH',
            'description': 'Possible XSS in Jinja2 templating'
        },
        {
            'name': 'requests',
            'version': '2.25.0',
            'cve': 'CVE-2023-32681',
            'severity': 'HIGH',
            'description': 'Potential cookie leakage in redirect handling'
        },
        {
            'name': 'urllib3',
            'version': '1.26.0',
            'cve': 'CVE-2023-27827',
            'severity': 'CRITICAL',
            'description': 'Certification bypass vulnerability'
        },
        {
            'name': 'Pillow',
            'version': '9.5.0',
            'cve': 'CVE-2022-22817',
            'severity': 'HIGH',
            'description': 'Buffer overflow in image processing'
        },
        {
            'name': 'setuptools',
            'version': '65.5.0',
            'cve': 'CVE-2022-40897',
            'severity': 'HIGH',
            'description': 'Remote code execution in package installation'
        }
    ]
    
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Secure App - Vulnerable Packages</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; color: #333; }
        .package { border: 1px solid #ddd; padding: 20px; margin-bottom: 20px; border-radius: 8px; }
        .package-critical { border-left: 5px solid #dc3545; }
        .package-high { border-left: 5px solid #ffc107; }
        .package-medium { border-left: 5px solid #28a745; }
        .package-name { font-size: 18px; font-weight: bold; color: #333; }
        .package-details { margin-top: 10px; color: #666; }
        .severity { display: inline-block; padding: 4px 8px; border-radius: 4px; color: white; font-size: 12px; margin-left: 10px; }
        .severity-critical { background: #dc3545; }
        .severity-high { background: #ffc107; }
        .severity-medium { background: #28a745; }
        .nav { margin-bottom: 20px; }
        .nav a { margin-right: 20px; text-decoration: none; color: #007bff; }
        .nav a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📦 Vulnerable Packages</h1>
            <p>These packages have known vulnerabilities for testing the CTI pipeline</p>
        </div>
        
        <div class="nav">
            <a href="{{ url_for('dashboard') }}">🏠 Dashboard</a>
            <a href="{{ url_for('logout') }}">🚪 Logout</a>
        </div>
        
        {% for package in packages %}
            <div class="package package-{{ package.severity.lower() }}">
                <div class="package-name">{{ package.name }} v{{ package.version }}</div>
                <div class="package-details">
                    <p><strong>CVE:</strong> {{ package.cve }}</p>
                    <p><strong>Severity:</strong> 
                        <span class="severity severity-{{ package.severity.lower() }}">{{ package.severity }}</span>
                    </p>
                    <p><strong>Description:</strong> {{ package.description }}</p>
                </div>
            </div>
        {% endfor %}
    </div>
</body>
</html>
    ''', packages=packages)

# Logout route
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

# Home route redirects to login
@app.route('/')
def home():
    return redirect(url_for('login'))

if __name__ == '__main__':
    setup_db()
    app.run(debug=False, host='0.0.0.0', port=5000)
