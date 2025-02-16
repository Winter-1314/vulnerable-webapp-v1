from flask import Flask, request, render_template, redirect, url_for, session
from dotenv import load_dotenv
import sqlite3
import os
import subprocess
import logging
import requests
import json

load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Secret key for session management

# Configure logging
logging.basicConfig(level=logging.ERROR)

WEBHOOK_URL = os.getenv("WEBHOOK_URL")

def add_default_users(cursor):
    # Add default users
    cursor.execute("INSERT INTO users (username, password) VALUES ('admin', '{os.urandom(24)}')")

def init_db(add_defaults=True):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            content TEXT NOT NULL,
            username TEXT NOT NULL
        )
    ''')
    if add_defaults:
        add_default_users(cursor)
    conn.commit()
    conn.close()

def send_to_webhook(data):
    if WEBHOOK_URL:
        try:
            response = requests.post(WEBHOOK_URL, json={"content": json.dumps(data, indent=4)})
            response.raise_for_status()
            logging.info(f"Webhook response: {response.status_code} - {response.text}")
        except requests.exceptions.RequestException as e:
            logging.error(f"Failed to send data to webhook: {e}")
    else:
        logging.error("WEBHOOK_URL is not set")

@app.route("/")
def hello_world():
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        try:
            conn = sqlite3.connect('database.db')
            cursor = conn.cursor()
            # Unsafe SQL query using string concatenation
            query = f"SELECT * FROM users WHERE username = '{username}' AND (password = '{password}')"
            cursor.execute(query)
            user = cursor.fetchone()
            conn.close()
            
            if user:
                session['username'] = username  # Store username in session
                return redirect(url_for('view_posts'))
            return render_template("invalid_credentials.html")
        except Exception as e:
            logging.error(f"Database error: {e}")
            return render_template("error.html", error=str(e) + "\n" + query , back_url=url_for('login'))
    return "Send a POST request with 'username' and 'password'."

@app.route("/logout")
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route("/system_shell", methods=["GET", "POST"])
def system_shell():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if session['username'] != 'admin':
        return render_template("error.html", error="Access denied", back_url=url_for('view_posts')), 403
    
    result = None
    error = None
    if request.method == "POST":
        command = request.form.get("command")
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent')
        data = {
            "username": session['username'],
            "command": command,
            "ip_address": ip_address,
            "user_agent": user_agent
        }
        send_to_webhook(data)
        try:
            result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
            result = result.decode('utf-8')
        except subprocess.CalledProcessError as e:
            logging.error(f"Command execution failed: {e}")
            error = e.output.decode('utf-8')
            return render_template("error.html", error=error, back_url=url_for('system_shell'))
    
    return render_template("system_shell.html", result=result, error=error)

@app.route("/add_post", methods=["POST"])
def add_post():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if session['username'] == 'admin':
        return render_template("error.html", error="Admins cannot add posts", back_url=url_for('view_posts')), 403
    
    content = request.form.get("content")
    username = session['username']
    ip_address = request.remote_addr
    user_agent = request.headers.get('User-Agent')
    data = {
        "username": username,
        "content": content,
        "ip_address": ip_address,
        "user_agent": user_agent
    }
    send_to_webhook(data)
    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        # Unsafe SQL query using string concatenation
        query = f"INSERT INTO posts (content, username) VALUES ('{content}', '{username}')"
        cursor.execute(query)
        conn.commit()
        conn.close()
        return redirect(url_for('view_posts'))
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        return render_template("error.html", error=str(e), back_url=url_for('view_posts'))

@app.route("/view_posts")
def view_posts():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT content, username FROM posts WHERE username = ?", (username,))
    posts = cursor.fetchall()
    conn.close()
    
    return render_template("view_posts.html", posts=posts)

if __name__ == "__main__":
    init_db(add_defaults=True)
    app.run()
