from flask import Flask, request, render_template, redirect, url_for, session, jsonify, make_response
import sqlite3
import uuid
import hashlib
import bleach
import re
import time
from urllib.parse import unquote

app = Flask(__name__)
app.secret_key = "xss-master-key-2023"
app.config['DATABASE'] = 'xsslab.db'

# Initialize database
def init_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    
    # Create tables
    c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        email TEXT NOT NULL,
        role TEXT DEFAULT 'student',
        token TEXT
    )
    ''')
    
    c.execute('''
    CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        content TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    c.execute('''
    CREATE TABLE IF NOT EXISTS progress (
        user_id INTEGER PRIMARY KEY,
        level INTEGER DEFAULT 1,
        completed INTEGER DEFAULT 0
    )
    ''')
    
    # Add sample users
    users = [
        ('admin', hash_pass('Admin@123'), 'admin@xsslab.com', 'admin', str(uuid.uuid4())),
        ('student', hash_pass('Student@123'), 'student@xsslab.com', 'student', str(uuid.uuid4()))
    ]
    
    c.executemany('''
    INSERT OR IGNORE INTO users (username, password, email, role, token)
    VALUES (?, ?, ?, ?, ?)
    ''', users)
    
    conn.commit()
    conn.close()

def hash_pass(password):
    return hashlib.sha256(password.encode()).hexdigest()

def get_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

# XSS Challenge Engine
class XSSEngine:
    def __init__(self):
        self.levels = {
            1: {"name": "Basic Alert", "filter": "none", "hint": "Try <script>alert('XSS')</script>"},
            2: {"name": "HTML Escape", "filter": "escape", "hint": "Bypass with <img src=x onerror=alert(1)>"},
            3: {"name": "Attribute Escape", "filter": "attr", "hint": "Use event handlers: 'onload' or 'onerror'"},
            4: {"name": "DOM Injection", "filter": "dom", "hint": "Manipulate DOM with #<img src=x onerror=alert(1)>"},
            5: {"name": "SVG Payloads", "filter": "svg", "hint": "Use SVG with embedded JavaScript"},
            6: {"name": "Template Literals", "filter": "template", "hint": "Exploit ${} syntax in JavaScript"},
            7: {"name": "WAF Bypass", "filter": "waf", "hint": "Bypass filters with case manipulation and encoding"},
            8: {"name": "Service Workers", "filter": "service", "hint": "Persist XSS through service worker cache"},
            9: {"name": "AngularJS Sandbox", "filter": "angular", "hint": "Escape AngularJS sandbox with prototype pollution"},
            10: {"name": "WebSocket XSS", "filter": "websocket", "hint": "Inject through WebSocket messages"}
        }
    
    def filter_input(self, level, input_str):
        if level == 1:
            return input_str  # No filtering
        elif level == 2:
            return bleach.clean(input_str, tags=[], attributes={})  # Strip all tags
        elif level == 3:
            # Allow some tags but sanitize attributes
            return bleach.clean(input_str, tags=['b', 'i', 'u'], attributes={})
        elif level == 4:
            # Simulate DOM-based injection
            return input_str.replace('<script>', '').replace('</script>', '')
        elif level == 5:
            # Allow SVG but sanitize
            return bleach.clean(input_str, tags=['svg', 'path'], attributes={'svg': ['onload']})
        elif level == 6:
            # Template literal injection
            return input_str.replace('${', '').replace('}', '')
        elif level == 7:
            # WAF-style filtering
            filtered = re.sub(r'<script|javascript:', '', input_str, flags=re.IGNORECASE)
            return re.sub(r'on\w+=', '', filtered)
        elif level == 8:
            # Service worker context
            return input_str
        elif level == 9:
            # AngularJS context
            return input_str.replace('{{', '').replace('}}', '')
        elif level == 10:
            # WebSocket context
            return input_str
        return input_str

engine = XSSEngine()

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed = hash_pass(password)
        
        conn = get_db()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ? AND password = ?',
            (username, hashed)
        ).fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['level'] = 1
            return redirect(url_for('dashboard'))
        
        return render_template('login.html', error="Invalid credentials")
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    conn = get_db()
    progress = conn.execute(
        'SELECT level, completed FROM progress WHERE user_id = ?',
        (user_id,)
    ).fetchone()
    conn.close()
    
    level = progress['level'] if progress else 1
    completed = progress['completed'] if progress else 0
    
    return render_template('dashboard.html', 
                          username=session['username'],
                          level=level,
                          completed=completed,
                          levels=engine.levels)

@app.route('/level/<int:level_id>', methods=['GET', 'POST'])
def xss_level(level_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if level_id < 1 or level_id > 10:
        return redirect(url_for('dashboard'))
    
    user_input = ""
    result = ""
    success = False
    
    if request.method == 'POST':
        user_input = request.form.get('payload', '')
        filtered = engine.filter_input(level_id, user_input)
        
        # Store for reflected XSS
        session['last_payload'] = filtered
        
        # Check if payload is successful
        if level_id == 1:
            success = '<script>' in user_input
        elif level_id == 2:
            success = 'onerror' in user_input.lower() or 'onload' in user_input.lower()
        elif level_id == 3:
            success = 'javascript:' in user_input.lower()
        elif level_id == 4:
            success = 'onerror' in user_input.lower() and '#' in request.referrer
        elif level_id == 5:
            success = '<svg' in user_input.lower() and 'onload' in user_input.lower()
        elif level_id == 6:
            success = '${' in user_input and '}' in user_input
        elif level_id == 7:
            success = 'alert' in user_input.lower() and ('<' in user_input or '(' in user_input)
        elif level_id == 8:
            success = 'serviceworker' in user_input.lower()
        elif level_id == 9:
            success = 'constructor' in user_input.lower()
        elif level_id == 10:
            success = 'websocket' in user_input.lower()
        
        if success:
            # Update progress
            conn = get_db()
            conn.execute('''
            INSERT OR REPLACE INTO progress (user_id, level, completed)
            VALUES (?, ?, ?)
            ''', (session['user_id'], level_id + 1, session.get('completed', 0) + 1))
            conn.commit()
            conn.close()
            session['completed'] = session.get('completed', 0) + 1
            session['level'] = level_id + 1
    
    level_info = engine.levels.get(level_id, {})
    return render_template('level.html',
                          level=level_id,
                          level_info=level_info,
                          user_input=user_input,
                          result=result,
                          success=success)

@app.route('/comment', methods=['GET', 'POST'])
def comment_system():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    
    if request.method == 'POST':
        content = request.form['comment']
        conn.execute(
            'INSERT INTO comments (user_id, content) VALUES (?, ?)',
            (session['user_id'], content)
        )
        conn.commit()
    
    comments = conn.execute('''
    SELECT users.username, comments.content, comments.timestamp 
    FROM comments JOIN users ON comments.user_id = users.id
    ORDER BY comments.timestamp DESC
    ''').fetchall()
    
    conn.close()
    return render_template('comments.html', comments=comments)

@app.route('/dom')
def dom_xss():
    return render_template('dom.html')

@app.route('/websocket')
def websocket_demo():
    return render_template('websocket.html')

@app.route('/playground')
def xss_playground():
    return render_template('playground.html')

@app.route('/cheatsheet')
def cheatsheet():
    payloads = {
        "Basic": ["<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>"],
        "DOM-based": ["#<img src=x onerror=alert(1)>", "<svg onload=alert(1)>"],
        "Advanced": ["javascript:eval('ale'+'rt(1)')", "{{constructor.constructor('alert(1)')()}}"]
    }
    return render_template('cheatsheet.html', payloads=payloads)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
