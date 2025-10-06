#!/usr/bin/env python3
"""
Demo Vulnerable Website for Password Toolkit Testing
Educational Cybersecurity Toolkit - For authorized educational use only

This is an intentionally vulnerable web application designed for 
educational purposes to demonstrate brute force attacks.

Author: Aniket886
GitHub: https://github.com/Aniket886
Project: Educational Cybersecurity Toolkit
Created: 2025

WARNING: This application is intentionally vulnerable and should NEVER
be deployed in a production environment or on public networks.
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
import hashlib
import sqlite3
import os
import time
import json
from datetime import datetime
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Database setup
DATABASE = 'demo_users.db'

def init_db():
    """Initialize the database with demo users."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create login attempts table for monitoring
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password_attempt TEXT,
            ip_address TEXT,
            success BOOLEAN,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Insert demo users with weak passwords
    demo_users = [
        ('admin', 'admin@demo.com', 'admin'),
        ('user', 'user@demo.com', 'password'),
        ('test', 'test@demo.com', '123456'),
        ('demo', 'demo@demo.com', 'demo'),
        ('guest', 'guest@demo.com', 'guest'),
        ('john', 'john@demo.com', 'john123'),
        ('alice', 'alice@demo.com', 'alice'),
        ('bob', 'bob@demo.com', 'qwerty'),
        ('manager', 'manager@demo.com', 'manager'),
        ('root', 'root@demo.com', 'root')
    ]
    
    for username, email, password in demo_users:
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        try:
            cursor.execute(
                'INSERT OR IGNORE INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                (username, email, password_hash)
            )
        except sqlite3.IntegrityError:
            pass  # User already exists
    
    conn.commit()
    conn.close()
    print("✓ Database initialized with demo users")

@app.route('/')
def index():
    """Main page with login form."""
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    """Handle login attempts - intentionally vulnerable."""
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    ip_address = request.remote_addr
    
    # Intentionally add a small delay to simulate real authentication
    time.sleep(0.1)
    
    if not username or not password:
        return jsonify({
            'success': False,
            'message': 'Username and password are required'
        })
    
    # Hash the provided password
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    # Check against database
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute(
        'SELECT id, username, email FROM users WHERE username = ? AND password_hash = ?',
        (username, password_hash)
    )
    user = cursor.fetchone()
    
    # Log the attempt
    cursor.execute(
        'INSERT INTO login_attempts (username, password_attempt, ip_address, success) VALUES (?, ?, ?, ?)',
        (username, password, ip_address, user is not None)
    )
    conn.commit()
    conn.close()
    
    if user:
        session['user_id'] = user[0]
        session['username'] = user[1]
        return jsonify({
            'success': True,
            'message': f'Welcome, {user[1]}!',
            'redirect': '/dashboard'
        })
    else:
        return jsonify({
            'success': False,
            'message': 'Invalid username or password'
        })

@app.route('/dashboard')
def dashboard():
    """User dashboard - requires login."""
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    return render_template('dashboard.html', username=session['username'])

@app.route('/logout')
def logout():
    """Logout user."""
    session.clear()
    return redirect(url_for('index'))

@app.route('/api/users')
def api_users():
    """API endpoint to list users - intentionally exposed for demo."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT username, email FROM users')
    users = [{'username': row[0], 'email': row[1]} for row in cursor.fetchall()]
    conn.close()
    
    return jsonify({
        'users': users,
        'total': len(users)
    })

@app.route('/api/login-attempts')
def api_login_attempts():
    """API endpoint to view recent login attempts."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT username, password_attempt, ip_address, success, timestamp 
        FROM login_attempts 
        ORDER BY timestamp DESC 
        LIMIT 100
    ''')
    attempts = []
    for row in cursor.fetchall():
        attempts.append({
            'username': row[0],
            'password_attempt': row[1],
            'ip_address': row[2],
            'success': bool(row[3]),
            'timestamp': row[4]
        })
    conn.close()
    
    return jsonify({
        'attempts': attempts,
        'total': len(attempts)
    })

@app.route('/admin')
def admin():
    """Admin panel - shows login attempts."""
    if 'user_id' not in session or session['username'] != 'admin':
        return redirect(url_for('index'))
    
    return render_template('admin.html')

@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

if __name__ == '__main__':
    print("\n" + "=" * 60)
    print("DEMO VULNERABLE WEBSITE")
    print("Educational Cybersecurity Toolkit")
    print("=" * 60)
    print("WARNING: This is an intentionally vulnerable application!")
    print("Only use for educational purposes in controlled environments.")
    print("=" * 60)
    
    # Initialize database
    init_db()
    
    print("\nDemo Users Available:")
    print("Username: admin    | Password: admin")
    print("Username: user     | Password: password")
    print("Username: test     | Password: 123456")
    print("Username: demo     | Password: demo")
    print("Username: guest    | Password: guest")
    print("And more...")
    
    print(f"\nStarting server on http://localhost:5000")
    print("Press Ctrl+C to stop the server")
    
    app.run(debug=True, host='0.0.0.0', port=5000)