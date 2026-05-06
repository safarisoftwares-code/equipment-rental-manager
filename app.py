import os
import sys
import sqlite3
import bcrypt
import jwt
import datetime
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

# ------------------------------------------------------------------
# Database setup: PostgreSQL on Render, SQLite locally
# ------------------------------------------------------------------
DATABASE_URL = os.environ.get('DATABASE_URL')
IS_RENDER = bool(DATABASE_URL)

if IS_RENDER:
    import psycopg2
    from psycopg2.extras import RealDictCursor
else:
    # local SQLite
    DATABASE = 'data/rental.db'
    os.makedirs('data', exist_ok=True)

def get_db():
    if IS_RENDER:
        conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
        return conn
    else:
        conn = sqlite3.connect(DATABASE)
        conn.row_factory = sqlite3.Row
        return conn

def init_db():
    conn = get_db()
    if IS_RENDER:
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
        print("ADMIN_EMAIL or ADMIN_PASSWORD not set, skipping default admin creation", file=sys.stderr)
        return
    conn = get_db()
    try:
        if IS_RENDER:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) as cnt FROM users")
                count = cur.fetchone()['cnt']
                if count == 0:
                    hashed = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt())
                    cur.execute(
                        "INSERT INTO users (email, password_hash, name, role, is_active) VALUES (%s, %s, %s, %s, %s)",
                        (admin_email, hashed.decode('utf-8'), 'System Admin', 'admin', 1)
                    )
                    conn.commit()
                    print(f"Default admin account created for {admin_email}", file=sys.stderr)
                else:
                    cur.execute("UPDATE users SET role = 'admin' WHERE email = %s AND role != 'admin'", (admin_email,))
                    conn.commit()
        else:
            cur = conn.execute("SELECT COUNT(*) as cnt FROM users")
            count = cur.fetchone()['cnt']
            if count == 0:
                hashed = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt())
                conn.execute(
                    "INSERT INTO users (email, password_hash, name, role, is_active) VALUES (?, ?, ?, ?, ?)",
                    (admin_email, hashed.decode('utf-8'), 'System Admin', 'admin', 1)
                )
                conn.commit()
                print(f"Default admin account created for {admin_email}", file=sys.stderr)
            else:
                conn.execute("UPDATE users SET role = 'admin' WHERE email = ? AND role != 'admin'", (admin_email,))
                conn.commit()
    except Exception as e:
        print(f"Error creating default admin: {e}", file=sys.stderr)
    finally:
        conn.close()

# ------------------------------------------------------------------
# Flask app setup
# ------------------------------------------------------------------
app = Flask(__name__, static_folder='static')
CORS(app)
SECRET_KEY = os.environ.get('JWT_SECRET', 'your-secret-key-change-this')

init_db()
create_default_admin()

# ------------------------------------------------------------------
# Helper functions: token_required, admin_required
# ------------------------------------------------------------------
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
        if IS_RENDER:
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
        if IS_RENDER:
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

# ------------------------------------------------------------------
# Health check
# ------------------------------------------------------------------
@app.route('/health', methods=['GET'])
def health():
    try:
        conn = get_db()
        if IS_RENDER:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
        else:
            conn.execute("SELECT 1")
        conn.close()
        return jsonify({'status': 'ok', 'database': 'PostgreSQL' if IS_RENDER else 'SQLite'})
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 500

# ------------------------------------------------------------------
# Authentication endpoints
# ------------------------------------------------------------------
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    name = data.get('name', '')
    if not email or not password:
        return jsonify({'error': 'Email and password required'}), 400
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    conn = get_db()
    try:
        if IS_RENDER:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO users (email, password_hash, name, role, is_active) VALUES (%s, %s, %s, %s, %s) RETURNING id",
                    (email, hashed.decode('utf-8'), name, 'user', 1)
                )
                user_id = cur.fetchone()['id']
                conn.commit()
        else:
            cur = conn.execute(
                "INSERT INTO users (email, password_hash, name, role, is_active) VALUES (?, ?, ?, ?, ?)",
                (email, hashed.decode('utf-8'), name, 'user', 1)
            )
            user_id = cur.lastrowid
            conn.commit()
        token = jwt.encode({'userId': user_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)}, SECRET_KEY)
        return jsonify({'token': token, 'user': {'id': user_id, 'email': email, 'name': name, 'role': 'user'}})
    except Exception as e:
        if 'unique' in str(e).lower() or 'duplicate' in str(e).lower():
            return jsonify({'error': 'Email already exists'}), 400
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    conn = get_db()
    try:
        if IS_RENDER:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM users WHERE email = %s", (email,))
                user = cur.fetchone()
        else:
            cur = conn.execute("SELECT * FROM users WHERE email = ?", (email,))
            user = cur.fetchone()
        if not user:
            return jsonify({'error': 'Invalid credentials'}), 401
        if user['is_active'] == 0:
            return jsonify({'error': 'Account suspended. Contact admin at safarisoftwares@gmail.com'}), 403
        if not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            return jsonify({'error': 'Invalid credentials'}), 401
        token = jwt.encode({'userId': user['id'], 'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)}, SECRET_KEY)
        return jsonify({
            'token': token,
            'user': {
                'id': user['id'],
                'email': user['email'],
                'name': user['name'],
                'role': user['role'],
                'company_name': user['company_name'],
                'company_phone': user['company_phone'],
                'company_address': user['company_address'],
                'company_email': user['company_email'],
                'signature_name': user['signature_name'],
                'tax_rate': user['tax_rate']
            }
        })
    finally:
        conn.close()

@app.route('/api/auth/verify', methods=['GET'])
@token_required
def verify(current_user_id):
    conn = get_db()
    try:
        if IS_RENDER:
            with conn.cursor() as cur:
                cur.execute("SELECT id, email, name, role, company_name, company_phone, company_address, company_email, signature_name, tax_rate FROM users WHERE id = %s", (current_user_id,))
                user = cur.fetchone()
        else:
            cur = conn.execute("SELECT id, email, name, role, company_name, company_phone, company_address, company_email, signature_name, tax_rate FROM users WHERE id = ?", (current_user_id,))
            user = cur.fetchone()
        return jsonify({'user': dict(user)})
    finally:
        conn.close()

@app.route('/api/auth/change-password', methods=['POST'])
@token_required
def change_password(current_user_id):
    data = request.json
    old = data.get('old_password')
    new = data.get('new_password')
    if not old or not new:
        return jsonify({'error': 'Old and new password required'}), 400
    conn = get_db()
    try:
        if IS_RENDER:
            with conn.cursor() as cur:
                cur.execute("SELECT password_hash FROM users WHERE id = %s", (current_user_id,))
                user = cur.fetchone()
        else:
            cur = conn.execute("SELECT password_hash FROM users WHERE id = ?", (current_user_id,))
            user = cur.fetchone()
        if not bcrypt.checkpw(old.encode('utf-8'), user['password_hash'].encode('utf-8')):
            return jsonify({'error': 'Old password incorrect'}), 401
        new_hash = bcrypt.hashpw(new.encode('utf-8'), bcrypt.gensalt())
        if IS_RENDER:
            with conn.cursor() as cur:
                cur.execute("UPDATE users SET password_hash = %s WHERE id = %s", (new_hash.decode('utf-8'), current_user_id))
                conn.commit()
        else:
            conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash.decode('utf-8'), current_user_id))
            conn.commit()
        return jsonify({'success': True})
    finally:
        conn.close()

# ------------------------------------------------------------------
# Admin user management
# ------------------------------------------------------------------
@app.route('/api/admin/users', methods=['GET'])
@token_required
@admin_required
def get_users(current_user_id):
    conn = get_db()
    try:
        if IS_RENDER:
            with conn.cursor() as cur:
                cur.execute("SELECT id, email, name, role, is_active FROM users")
                users = cur.fetchall()
        else:
            cur = conn.execute("SELECT id, email, name, role, is_active FROM users")
            users = cur.fetchall()
        return jsonify({'users': [dict(u) for u in users]})
    finally:
        conn.close()

@app.route('/api/admin/users/<int:user_id>/reset-password', methods=['POST'])
@token_required
@admin_required
def reset_password(current_user_id, user_id):
    data = request.json
    new_password = data.get('new_password')
    if not new_password:
        return jsonify({'error': 'New password required'}), 400
    hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    conn = get_db()
    try:
        if IS_RENDER:
            with conn.cursor() as cur:
                cur.execute("UPDATE users SET password_hash = %s WHERE id = %s", (hashed.decode('utf-8'), user_id))
                conn.commit()
        else:
            conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hashed.decode('utf-8'), user_id))
            conn.commit()
        return jsonify({'success': True})
    finally:
        conn.close()

@app.route('/api/admin/users/<int:user_id>/suspend', methods=['POST'])
@token_required
@admin_required
def suspend_user(current_user_id, user_id):
    if user_id == current_user_id:
        return jsonify({'error': 'Cannot suspend yourself'}), 400
    conn = get_db()
    try:
        if IS_RENDER:
            with conn.cursor() as cur:
                cur.execute("UPDATE users SET is_active = 0 WHERE id = %s", (user_id,))
                conn.commit()
        else:
            conn.execute("UPDATE users SET is_active = 0 WHERE id = ?", (user_id,))
            conn.commit()
        return jsonify({'success': True})
    finally:
        conn.close()

@app.route('/api/admin/users/<int:user_id>/activate', methods=['POST'])
@token_required
@admin_required
def activate_user(current_user_id, user_id):
    conn = get_db()
    try:
        if IS_RENDER:
            with conn.cursor() as cur:
                cur.execute("UPDATE users SET is_active = 1 WHERE id = %s", (user_id,))
                conn.commit()
        else:
            conn.execute("UPDATE users SET is_active = 1 WHERE id = ?", (user_id,))
            conn.commit()
        return jsonify({'success': True})
    finally:
        conn.close()

# ------------------------------------------------------------------
# Company settings
# ------------------------------------------------------------------
@app.route('/api/company', methods=['PUT'])
@token_required
def update_company(current_user_id):
    data = request.json
    conn = get_db()
    try:
        if IS_RENDER:
            with conn.cursor() as cur:
                cur.execute('''
                    UPDATE users SET
                        company_name = COALESCE(%s, company_name),
                        company_phone = COALESCE(%s, company_phone),
                        company_address = COALESCE(%s, company_address),
                        company_email = COALESCE(%s, company_email),
                        signature_name = COALESCE(%s, signature_name),
                        tax_rate = COALESCE(%s, tax_rate)
                    WHERE id = %s
                ''', (
                    data.get('company_name'),
                    data.get('company_phone'),
                    data.get('company_address'),
                    data.get('company_email'),
                    data.get('signature_name'),
                    data.get('tax_rate'),
                    current_user_id
                ))
                conn.commit()
        else:
            conn.execute('''
                UPDATE users SET
                    company_name = COALESCE(?, company_name),
                    company_phone = COALESCE(?, company_phone),
                    company_address = COALESCE(?, company_address),
                    company_email = COALESCE(?, company_email),
                    signature_name = COALESCE(?, signature_name),
                    tax_rate = COALESCE(?, tax_rate)
                WHERE id = ?
            ''', (
                data.get('company_name'),
                data.get('company_phone'),
                data.get('company_address'),
                data.get('company_email'),
                data.get('signature_name'),
                data.get('tax_rate'),
                current_user_id
            ))
            conn.commit()
        return jsonify({'success': True})
    finally:
        conn.close()

# ------------------------------------------------------------------
# Clients CRUD
# ------------------------------------------------------------------
@app.route('/api/clients', methods=['GET'])
@token_required
def get_clients(current_user_id):
    conn = get_db()
    try:
        if IS_RENDER:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM clients WHERE user_id = %s ORDER BY created_at DESC", (current_user_id,))
                clients = cur.fetchall()
        else:
            cur = conn.execute("SELECT * FROM clients WHERE user_id = ? ORDER BY created_at DESC", (current_user_id,))
            clients = cur.fetchall()
        return jsonify({'clients': [dict(c) for c in clients]})
    finally:
        conn.close()

@app.route('/api/clients', methods=['POST'])
@token_required
def create_client(current_user_id):
    data = request.json
    if not data.get('client_name'):
        return jsonify({'error': 'Client name required'}), 400
    conn = get_db()
    try:
        if IS_RENDER:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO clients (user_id, client_name, client_phone, client_email, client_pob, client_comment) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
                    (current_user_id, data['client_name'], data.get('client_phone', ''), data.get('client_email', ''),
                     data.get('client_pob', ''), data.get('client_comment', ''))
                )
                client_id = cur.fetchone()['id']
                conn.commit()
        else:
            cur = conn.execute(
                "INSERT INTO clients (user_id, client_name, client_phone, client_email, client_pob, client_comment) VALUES (?, ?, ?, ?, ?, ?)",
                (current_user_id, data['client_name'], data.get('client_phone', ''), data.get('client_email', ''),
                 data.get('client_pob', ''), data.get('client_comment', ''))
            )
            client_id = cur.lastrowid
            conn.commit()
        return jsonify({'id': client_id, 'client_name': data['client_name']})
    finally:
        conn.close()

@app.route('/api/clients/<int:client_id>', methods=['PUT'])
@token_required
def update_client(current_user_id, client_id):
    data = request.json
    conn = get_db()
    try:
        if IS_RENDER:
            with conn.cursor() as cur:
                cur.execute('''
                    UPDATE clients SET
                        client_name = COALESCE(%s, client_name),
                        client_phone = COALESCE(%s, client_phone),
                        client_email = COALESCE(%s, client_email),
                        client_pob = COALESCE(%s, client_pob),
                        client_comment = COALESCE(%s, client_comment),
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = %s AND user_id = %s
                ''', (
                    data.get('client_name'), data.get('client_phone'), data.get('client_email'),
                    data.get('client_pob'), data.get('client_comment'), client_id, current_user_id
                ))
                if cur.rowcount == 0:
                    return jsonify({'error': 'Client not found'}), 404
                conn.commit()
        else:
            result = conn.execute('''
                UPDATE clients SET
                    client_name = COALESCE(?, client_name),
                    client_phone = COALESCE(?, client_phone),
                    client_email = COALESCE(?, client_email),
                    client_pob = COALESCE(?, client_pob),
                    client_comment = COALESCE(?, client_comment),
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ? AND user_id = ?
            ''', (
                data.get('client_name'), data.get('client_phone'), data.get('client_email'),
                data.get('client_pob'), data.get('client_comment'), client_id, current_user_id
            ))
            if result.rowcount == 0:
                return jsonify({'error': 'Client not found'}), 404
            conn.commit()
        return jsonify({'success': True})
    finally:
        conn.close()

@app.route('/api/clients/<int:client_id>', methods=['DELETE'])
@token_required
def delete_client(current_user_id, client_id):
    conn = get_db()
    try:
        if IS_RENDER:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM clients WHERE id = %s AND user_id = %s", (client_id, current_user_id))
                if cur.rowcount == 0:
                    return jsonify({'error': 'Client not found'}), 404
                conn.commit()
        else:
            result = conn.execute("DELETE FROM clients WHERE id = ? AND user_id = ?", (client_id, current_user_id))
            if result.rowcount == 0:
                return jsonify({'error': 'Client not found'}), 404
            conn.commit()
        return jsonify({'success': True})
    finally:
        conn.close()

# ------------------------------------------------------------------
# Rental items
# ------------------------------------------------------------------
@app.route('/api/clients/<int:client_id>/items', methods=['GET'])
@token_required
def get_items(current_user_id, client_id):
    conn = get_db()
    try:
        if IS_RENDER:
            with conn.cursor() as cur:
                cur.execute("SELECT id FROM clients WHERE id = %s AND user_id = %s", (client_id, current_user_id))
                client = cur.fetchone()
                if not client:
                    return jsonify({'error': 'Client not found'}), 404
                cur.execute("SELECT * FROM rental_items WHERE client_id = %s ORDER BY id", (client_id,))
                items = cur.fetchall()
        else:
            client = conn.execute("SELECT id FROM clients WHERE id = ? AND user_id = ?", (client_id, current_user_id)).fetchone()
            if not client:
                return jsonify({'error': 'Client not found'}), 404
            items = conn.execute("SELECT * FROM rental_items WHERE client_id = ? ORDER BY id", (client_id,)).fetchall()
        return jsonify({'items': [dict(i) for i in items]})
    finally:
        conn.close()

@app.route('/api/clients/<int:client_id>/items/bulk', methods=['PUT'])
@token_required
def bulk_update_items(current_user_id, client_id):
    data = request.json
    items = data.get('items', [])
    conn = get_db()
    try:
        # get current tax rate
        if IS_RENDER:
            with conn.cursor() as cur:
                cur.execute("SELECT tax_rate FROM users WHERE id = %s", (current_user_id,))
                user = cur.fetchone()
                current_tax_rate = user['tax_rate'] if user else 0.0
                cur.execute("SELECT id FROM clients WHERE id = %s AND user_id = %s", (client_id, current_user_id))
                client = cur.fetchone()
                if not client:
                    return jsonify({'error': 'Client not found'}), 404
                cur.execute("DELETE FROM rental_items WHERE client_id = %s", (client_id,))
                for item in items:
                    cost_per_day = item.get('cost_per_day', 0)
                    days = item.get('days_issued', 1)
                    total_cost = cost_per_day * days
                    tax_amount = total_cost * current_tax_rate / 100
                    cur.execute('''
                        INSERT INTO rental_items (client_id, description, date_issued, cost_per_day, days_issued, amount_paid, tax_rate, tax_amount)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ''', (client_id, item.get('description', ''), item.get('date_issued', ''),
                          cost_per_day, days, item.get('amount_paid', 0), current_tax_rate, tax_amount))
                conn.commit()
        else:
            user = conn.execute("SELECT tax_rate FROM users WHERE id = ?", (current_user_id,)).fetchone()
            current_tax_rate = user['tax_rate'] if user else 0.0
            client = conn.execute("SELECT id FROM clients WHERE id = ? AND user_id = ?", (client_id, current_user_id)).fetchone()
            if not client:
                return jsonify({'error': 'Client not found'}), 404
            conn.execute("DELETE FROM rental_items WHERE client_id = ?", (client_id,))
            for item in items:
                cost_per_day = item.get('cost_per_day', 0)
                days = item.get('days_issued', 1)
                total_cost = cost_per_day * days
                tax_amount = total_cost * current_tax_rate / 100
                conn.execute('''
                    INSERT INTO rental_items (client_id, description, date_issued, cost_per_day, days_issued, amount_paid, tax_rate, tax_amount)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (client_id, item.get('description', ''), item.get('date_issued', ''),
                      cost_per_day, days, item.get('amount_paid', 0), current_tax_rate, tax_amount))
            conn.commit()
        return jsonify({'success': True, 'count': len(items)})
    finally:
        conn.close()

# ------------------------------------------------------------------
# Tax history and reset
# ------------------------------------------------------------------
@app.route('/api/tax-history', methods=['GET'])
@token_required
def tax_history(current_user_id):
    conn = get_db()
    try:
        if IS_RENDER:
            with conn.cursor() as cur:
                cur.execute('''
                    SELECT ri.*, c.client_name FROM rental_items ri
                    JOIN clients c ON ri.client_id = c.id
                    WHERE c.user_id = %s
                    ORDER BY ri.created_at DESC
                ''', (current_user_id,))
                items = cur.fetchall()
        else:
            items = conn.execute('''
                SELECT ri.*, c.client_name FROM rental_items ri
                JOIN clients c ON ri.client_id = c.id
                WHERE c.user_id = ?
                ORDER BY ri.created_at DESC
            ''', (current_user_id,)).fetchall()
        return jsonify({'history': [dict(i) for i in items]})
    finally:
        conn.close()

@app.route('/api/reset-testing-data', methods=['POST'])
@token_required
def reset_testing_data(current_user_id):
    conn = get_db()
    try:
        if IS_RENDER:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM clients WHERE user_id = %s", (current_user_id,))
                conn.commit()
        else:
            conn.execute("DELETE FROM clients WHERE user_id = ?", (current_user_id,))
            conn.commit()
        return jsonify({'success': True})
    finally:
        conn.close()

# ------------------------------------------------------------------
# Export / Import data
# ------------------------------------------------------------------
@app.route('/api/export-data', methods=['GET'])
@token_required
def export_data(current_user_id):
    conn = get_db()
    try:
        if IS_RENDER:
            with conn.cursor() as cur:
                cur.execute("SELECT id, email, name, company_name, company_phone, company_address, company_email, signature_name, tax_rate FROM users WHERE id = %s", (current_user_id,))
                user = cur.fetchone()
                cur.execute("SELECT * FROM clients WHERE user_id = %s", (current_user_id,))
                clients = cur.fetchall()
                export = {'user': dict(user), 'clients': []}
                for client in clients:
                    cur.execute("SELECT * FROM rental_items WHERE client_id = %s", (client['id'],))
                    items = cur.fetchall()
                    export['clients'].append({**dict(client), 'items': [dict(i) for i in items]})
        else:
            user = conn.execute("SELECT id, email, name, company_name, company_phone, company_address, company_email, signature_name, tax_rate FROM users WHERE id = ?", (current_user_id,)).fetchone()
            clients = conn.execute("SELECT * FROM clients WHERE user_id = ?", (current_user_id,)).fetchall()
            export = {'user': dict(user), 'clients': []}
            for client in clients:
                items = conn.execute("SELECT * FROM rental_items WHERE client_id = ?", (client['id'],)).fetchall()
                export['clients'].append({**dict(client), 'items': [dict(i) for i in items]})
        return jsonify(export)
    finally:
        conn.close()

@app.route('/api/import-data', methods=['POST'])
@token_required
def import_data(current_user_id):
    data = request.json
    imported_clients = data.get('clients', [])
    conn = get_db()
    try:
        for client in imported_clients:
            if IS_RENDER:
                with conn.cursor() as cur:
                    cur.execute('''
                        INSERT INTO clients (user_id, client_name, client_phone, client_email, client_pob, client_comment)
                        VALUES (%s, %s, %s, %s, %s, %s) RETURNING id
                    ''', (current_user_id, client.get('client_name'), client.get('client_phone'), client.get('client_email'),
                          client.get('client_pob'), client.get('client_comment')))
                    new_client_id = cur.fetchone()['id']
                    for item in client.get('items', []):
                        cur.execute('''
                            INSERT INTO rental_items (client_id, description, date_issued, cost_per_day, days_issued, amount_paid, tax_rate, tax_amount)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        ''', (new_client_id, item.get('description'), item.get('date_issued'),
                              item.get('cost_per_day'), item.get('days_issued'), item.get('amount_paid'),
                              item.get('tax_rate', 0), item.get('tax_amount', 0)))
                    conn.commit()
            else:
                cur = conn.execute('''
                    INSERT INTO clients (user_id, client_name, client_phone, client_email, client_pob, client_comment)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (current_user_id, client.get('client_name'), client.get('client_phone'), client.get('client_email'),
                      client.get('client_pob'), client.get('client_comment')))
                new_client_id = cur.lastrowid
                for item in client.get('items', []):
                    conn.execute('''
                        INSERT INTO rental_items (client_id, description, date_issued, cost_per_day, days_issued, amount_paid, tax_rate, tax_amount)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (new_client_id, item.get('description'), item.get('date_issued'),
                          item.get('cost_per_day'), item.get('days_issued'), item.get('amount_paid'),
                          item.get('tax_rate', 0), item.get('tax_amount', 0)))
                conn.commit()
        return jsonify({'success': True})
    finally:
        conn.close()

# ------------------------------------------------------------------
# Serve static frontend
# ------------------------------------------------------------------
@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/<path:path>')
def static_files(path):
    return send_from_directory('static', path)

# ------------------------------------------------------------------
# Run locally
# ------------------------------------------------------------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3443, debug=False)