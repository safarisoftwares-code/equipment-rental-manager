import sqlite3
import bcrypt
import jwt
import datetime
import os
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

app = Flask(__name__, static_folder='static')
CORS(app)
SECRET_KEY = os.environ.get('JWT_SECRET', 'your-secret-key-change-this')

# ------------------------------
# Database: use PostgreSQL if DATABASE_URL exists, else SQLite
# ------------------------------
DATABASE_URL = os.environ.get('DATABASE_URL')
if DATABASE_URL:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    def get_db():
        return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
else:
    DATABASE = 'data/rental.db'
    os.makedirs('data', exist_ok=True)
    def get_db():
        conn = sqlite3.connect(DATABASE)
        conn.row_factory = sqlite3.Row
        return conn

def init_db():
    conn = get_db()
    if DATABASE_URL:
        with conn.cursor() as cur:
            cur.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    name TEXT,
                    role TEXT DEFAULT 'user',
                    is_active INTEGER DEFAULT 1,
                    company_name TEXT DEFAULT 'Equipment Rental Manager Pro',
                    company_phone TEXT DEFAULT 'Tel: [Your Phone Number]',
                    company_address TEXT DEFAULT 'P. O. Box [Your Address]',
                    company_email TEXT DEFAULT '[Your Email Address]',
                    signature_name TEXT,
                    tax_rate REAL DEFAULT 0.0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS clients (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    client_name TEXT NOT NULL,
                    client_phone TEXT DEFAULT '',
                    client_email TEXT DEFAULT '',
                    client_pob TEXT DEFAULT '',
                    client_comment TEXT DEFAULT '',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS rental_items (
                    id SERIAL PRIMARY KEY,
                    client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
                    description TEXT DEFAULT '',
                    date_issued TEXT DEFAULT '',
                    cost_per_day REAL DEFAULT 0,
                    days_issued INTEGER DEFAULT 1,
                    amount_paid REAL DEFAULT 0,
                    tax_rate REAL DEFAULT 0,
                    tax_amount REAL DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            ''')
            conn.commit()
    else:
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                name TEXT,
                role TEXT DEFAULT 'user',
                is_active INTEGER DEFAULT 1,
                company_name TEXT DEFAULT 'Equipment Rental Manager Pro',
                company_phone TEXT DEFAULT 'Tel: [Your Phone Number]',
                company_address TEXT DEFAULT 'P. O. Box [Your Address]',
                company_email TEXT DEFAULT '[Your Email Address]',
                signature_name TEXT,
                tax_rate REAL DEFAULT 0.0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS clients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                client_name TEXT NOT NULL,
                client_phone TEXT DEFAULT '',
                client_email TEXT DEFAULT '',
                client_pob TEXT DEFAULT '',
                client_comment TEXT DEFAULT '',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS rental_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id INTEGER NOT NULL,
                description TEXT DEFAULT '',
                date_issued TEXT DEFAULT '',
                cost_per_day REAL DEFAULT 0,
                days_issued INTEGER DEFAULT 1,
                amount_paid REAL DEFAULT 0,
                tax_rate REAL DEFAULT 0,
                tax_amount REAL DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
            );
        ''')
    conn.close()

def create_default_admin():
    admin_email = os.environ.get('ADMIN_EMAIL')
    admin_password = os.environ.get('ADMIN_PASSWORD')
    if not admin_email or not admin_password:
        return
    conn = get_db()
    try:
        if DATABASE_URL:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM users")
                count = cur.fetchone()['count']
                if count == 0:
                    hashed = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt())
                    cur.execute(
                        "INSERT INTO users (email, password_hash, name, role, is_active) VALUES (%s, %s, %s, %s, %s)",
                        (admin_email, hashed.decode('utf-8'), 'System Admin', 'admin', 1)
                    )
                    conn.commit()
                else:
                    cur.execute("UPDATE users SET role = 'admin' WHERE email = %s AND role != 'admin'", (admin_email,))
                    conn.commit()
        else:
            cur = conn.execute("SELECT COUNT(*) FROM users")
            count = cur.fetchone()[0]
            if count == 0:
                hashed = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt())
                conn.execute(
                    "INSERT INTO users (email, password_hash, name, role, is_active) VALUES (?, ?, ?, ?, ?)",
                    (admin_email, hashed.decode('utf-8'), 'System Admin', 'admin', 1)
                )
                conn.commit()
            else:
                conn.execute("UPDATE users SET role = 'admin' WHERE email = ? AND role != 'admin'", (admin_email,))
                conn.commit()
    except Exception as e:
        print(f"Admin creation error: {e}")
    finally:
        conn.close()

init_db()
create_default_admin()

# ------------------------------
# Helper functions (token, admin)
# ------------------------------
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token or not token.startswith('Bearer '):
            return jsonify({'error': 'Missing token'}), 401
        token = token.split(' ')[1]
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            current_user_id = data['userId']
        except:
            return jsonify({'error': 'Invalid token'}), 401
        conn = get_db()
        if DATABASE_URL:
            with conn.cursor() as cur:
                cur.execute("SELECT id, is_active, role FROM users WHERE id = %s", (current_user_id,))
                user = cur.fetchone()
        else:
            cur = conn.execute("SELECT id, is_active, role FROM users WHERE id = ?", (current_user_id,))
            user = cur.fetchone()
        conn.close()
        if not user:
            return jsonify({'error': 'User not found'}), 401
        if user['is_active'] == 0:
            return jsonify({'error': 'Account suspended. Contact admin at safarisoftwares@gmail.com'}), 403
        return f(current_user_id, *args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(current_user_id, *args, **kwargs):
        conn = get_db()
        if DATABASE_URL:
            with conn.cursor() as cur:
                cur.execute("SELECT role FROM users WHERE id = %s", (current_user_id,))
                user = cur.fetchone()
        else:
            cur = conn.execute("SELECT role FROM users WHERE id = ?", (current_user_id,))
            user = cur.fetchone()
        conn.close()
        if not user or user['role'] != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(current_user_id, *args, **kwargs)
    return decorated

# ------------------------------
# Health check
# ------------------------------
@app.route('/health', methods=['GET'])
def health():
    try:
        conn = get_db()
        if DATABASE_URL:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
        else:
            conn.execute("SELECT 1")
        conn.close()
        return jsonify({'status': 'ok', 'database': 'PostgreSQL' if DATABASE_URL else 'SQLite'})
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 500

# ------------------------------
# (All remaining endpoints – identical to your previous working app.py)
# To save space, I will indicate that you should copy the rest of your working endpoints from the last successful deployment.
# However, since you already have them, I assume you will keep them unchanged.
# ------------------------------

# ... (your existing routes for auth, clients, items, export, etc.) ...

# ------------------------------
# Run
# ------------------------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3443, debug=False)