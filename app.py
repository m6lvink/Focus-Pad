''' 
Main Application - FocusPad
'''
import mimetypes
# Ensure CSS is served with correct MIME type
mimetypes.add_type('text/css', '.css')

from flask import Flask, render_template, request, redirect, session, url_for, g
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import CSRFProtect
import secrets

# Init Flask app
app = Flask(__name__)

# Security config
secretKey = os.environ.get('SECRET_KEY', 'placeholderSecret')
app.secret_key = secretKey

# Boolean flag config for cookies
isCookieSecure = (os.environ.get('SESSION_COOKIE_SECURE', '0') == '1')

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Strict',
    SESSION_COOKIE_SECURE=isCookieSecure,
)

# Implemented CSRF protection
csrfProtection = CSRFProtect(app)

def getDbConnection():
    # Function to return a new DB connection
    dbConnection = sqlite3.connect('notes.db')
    return dbConnection

def initDatabase():
    # Function to create tables if they do not exist
    connection = getDbConnection()
    with connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
    connection.close()

@app.before_request
def beforeRequest():
    # Setup DB and Nonce before every request
    initDatabase()
    g.cspNonce = secrets.token_urlsafe(16)

@app.context_processor
def injectCspNonce():
    # Function to push nonce to templates
    currentNonce = getattr(g, 'cspNonce', '')
    return {'csp_nonce': currentNonce}

@app.after_request
def setSecurityHeaders(responseObject):
    # Function to apply strict security headers
    currentNonce = getattr(g, 'cspNonce', '')
    
    cspString = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{currentNonce}'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    
    responseObject.headers['Content-Security-Policy'] = cspString
    responseObject.headers['X-Content-Type-Options'] = 'nosniff'
    responseObject.headers['X-Frame-Options'] = 'DENY'
    responseObject.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    responseObject.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    
    isHstsEnabled = (os.environ.get('ENABLE_HSTS', '0') == '1')
    if isHstsEnabled:
        responseObject.headers['Strict-Transport-Security'] = 'max-age=15552000; includeSubDomains; preload'
        
    return responseObject

# Routes

@app.route('/')
def index():
    isUserLoggedIn = ('userId' in session)
    
    if isUserLoggedIn:
        return redirect(url_for('dashboard'))
        
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    isPostRequest = (request.method == 'POST')
    
    if isPostRequest:
        inputUsername = request.form.get('username', '').strip()
        inputPassword = request.form.get('password', '')
        
        hasValidCredentials = (inputUsername != "" and inputPassword != "")
        
        if not hasValidCredentials:
            return render_template('register.html', error='Username and password are required')
            
        passwordHash = generate_password_hash(inputPassword)
        
        connection = None
        try:
            connection = getDbConnection()
            with connection:
                connection.execute(
                    "INSERT INTO users (username, password) VALUES (?, ?)", 
                    (inputUsername, passwordHash)
                )
            return redirect(url_for('login'))
            
        except sqlite3.IntegrityError:
            return render_template('register.html', error='Username already exists')
        finally:
            if connection is not None:
                connection.close()
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    isPostRequest = (request.method == 'POST')
    
    if isPostRequest:
        inputUsername = request.form.get('username', '').strip()
        inputPassword = request.form.get('password', '')
        
        connection = getDbConnection()
        cursor = connection.execute(
            "SELECT id, password FROM users WHERE username = ?", 
            (inputUsername,)
        )
        userData = cursor.fetchone()
        connection.close()
        
        isValidUser = False
        if userData is not None:
            storedHash = userData[1]
            if check_password_hash(storedHash, inputPassword):
                isValidUser = True
                
        if not isValidUser:
            return render_template('login.html', error='Invalid username or password')
            
        session.clear()
        session['userId'] = userData[0]
        return redirect(url_for('dashboard'))
        
    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    isUserLoggedIn = ('userId' in session)
    if not isUserLoggedIn:
        return redirect(url_for('login'))
        
    isPostRequest = (request.method == 'POST')
    
    if isPostRequest:
        noteTitle = request.form.get('title', '').strip()
        noteContent = request.form.get('content', '').strip()
        
        hasContent = (noteTitle != "" and noteContent != "")
        
        if hasContent:
            currentUserId = session['userId']
            connection = getDbConnection()
            with connection:
                connection.execute(
                    "INSERT INTO notes (title, content, user_id) VALUES (?, ?, ?)", 
                    (noteTitle, noteContent, currentUserId)
                )
            connection.close()
            
        return redirect(url_for('dashboard'))
        
    currentUserId = session['userId']
    connection = getDbConnection()
    cursor = connection.execute(
        "SELECT id, title, content FROM notes WHERE user_id = ?", 
        (currentUserId,)
    )
    userNotes = cursor.fetchall()
    connection.close()
    
    return render_template('dashboard.html', notes=userNotes)

@app.route('/logout', methods=['POST'])
def logout():
    # Function to clear session
    session.clear()
    return redirect(url_for('login'))

@app.route('/delete/<int:noteId>', methods=['POST'])
def delete(noteId):
    isUserLoggedIn = ('userId' in session)
    if not isUserLoggedIn:
        return redirect(url_for('login'))
        
    currentUserId = session['userId']
    connection = getDbConnection()
    with connection:
        connection.execute(
            "DELETE FROM notes WHERE id = ? AND user_id = ?", 
            (noteId, currentUserId)
        )
    connection.close()
    
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    serverPort = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=serverPort)