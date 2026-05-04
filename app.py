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
SECRET_KEY = "your-secret-key-change-this"
DATABASE = "data/rental.db"

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
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
            tax_rate REAL DEFAULT 16.0,
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
        user = conn.execute('SELECT id, is_active, role FROM users WHERE id = ?', (current_user_id,)).fetchone()
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
        user = conn.execute('SELECT role FROM users WHERE id = ?', (current_user_id,)).fetchone()
        conn.close()
        if not user or user['role'] != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(current_user_id, *args, **kwargs)
    return decorated

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
        count = conn.execute('SELECT COUNT(*) as cnt FROM users').fetchone()['cnt']
        role = 'admin' if count == 0 else 'user'
        cursor = conn.execute(
            'INSERT INTO users (email, password_hash, name, role, is_active) VALUES (?, ?, ?, ?, ?)',
            (email, hashed.decode('utf-8'), name, role, 1)
        )
        conn.commit()
        user_id = cursor.lastrowid
        token = jwt.encode({'userId': user_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)}, SECRET_KEY)
        return jsonify({'token': token, 'user': {'id': user_id, 'email': email, 'name': name, 'role': role}})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Email already exists'}), 400
    finally:
        conn.close()

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    conn.close()
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

@app.route('/api/auth/verify', methods=['GET'])
@token_required
def verify(current_user_id):
    conn = get_db()
    user = conn.execute('SELECT id, email, name, role, company_name, company_phone, company_address, company_email, signature_name, tax_rate FROM users WHERE id = ?', (current_user_id,)).fetchone()
    conn.close()
    return jsonify({'user': dict(user)})

@app.route('/api/auth/change-password', methods=['POST'])
@token_required
def change_password(current_user_id):
    data = request.json
    old = data.get('old_password')
    new = data.get('new_password')
    if not old or not new:
        return jsonify({'error': 'Old and new password required'}), 400
    conn = get_db()
    user = conn.execute('SELECT password_hash FROM users WHERE id = ?', (current_user_id,)).fetchone()
    if not bcrypt.checkpw(old.encode('utf-8'), user['password_hash'].encode('utf-8')):
        conn.close()
        return jsonify({'error': 'Old password incorrect'}), 401
    new_hash = bcrypt.hashpw(new.encode('utf-8'), bcrypt.gensalt())
    conn.execute('UPDATE users SET password_hash = ? WHERE id = ?', (new_hash.decode('utf-8'), current_user_id))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/api/admin/users', methods=['GET'])
@token_required
@admin_required
def get_users(current_user_id):
    conn = get_db()
    users = conn.execute('SELECT id, email, name, role, is_active FROM users').fetchall()
    conn.close()
    return jsonify({'users': [dict(u) for u in users]})

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
    conn.execute('UPDATE users SET password_hash = ? WHERE id = ?', (hashed.decode('utf-8'), user_id))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/api/admin/users/<int:user_id>/suspend', methods=['POST'])
@token_required
@admin_required
def suspend_user(current_user_id, user_id):
    if user_id == current_user_id:
        return jsonify({'error': 'Cannot suspend yourself'}), 400
    conn = get_db()
    conn.execute('UPDATE users SET is_active = 0 WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/api/admin/users/<int:user_id>/activate', methods=['POST'])
@token_required
@admin_required
def activate_user(current_user_id, user_id):
    conn = get_db()
    conn.execute('UPDATE users SET is_active = 1 WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/api/company', methods=['PUT'])
@token_required
def update_company(current_user_id):
    data = request.json
    conn = get_db()
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
    conn.close()
    return jsonify({'success': True})

@app.route('/api/clients', methods=['GET'])
@token_required
def get_clients(current_user_id):
    conn = get_db()
    clients = conn.execute('SELECT * FROM clients WHERE user_id = ? ORDER BY created_at DESC', (current_user_id,)).fetchall()
    conn.close()
    return jsonify({'clients': [dict(c) for c in clients]})

@app.route('/api/clients', methods=['POST'])
@token_required
def create_client(current_user_id):
    data = request.json
    if not data.get('client_name'):
        return jsonify({'error': 'Client name required'}), 400
    conn = get_db()
    cursor = conn.execute('''
        INSERT INTO clients (user_id, client_name, client_phone, client_email, client_pob, client_comment)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (current_user_id, data['client_name'], data.get('client_phone', ''), data.get('client_email', ''),
          data.get('client_pob', ''), data.get('client_comment', '')))
    conn.commit()
    client_id = cursor.lastrowid
    conn.close()
    return jsonify({'id': client_id, 'client_name': data['client_name']})

@app.route('/api/clients/<int:client_id>', methods=['PUT'])
@token_required
def update_client(current_user_id, client_id):
    data = request.json
    conn = get_db()
    result = conn.execute('''
        UPDATE clients SET
            client_name = COALESCE(?, client_name),
            client_phone = COALESCE(?, client_phone),
            client_email = COALESCE(?, client_email),
            client_pob = COALESCE(?, client_pob),
            client_comment = COALESCE(?, client_comment),
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ? AND user_id = ?
    ''', (data.get('client_name'), data.get('client_phone'), data.get('client_email'),
          data.get('client_pob'), data.get('client_comment'), client_id, current_user_id))
    conn.commit()
    conn.close()
    if result.rowcount == 0:
        return jsonify({'error': 'Client not found'}), 404
    return jsonify({'success': True})

@app.route('/api/clients/<int:client_id>', methods=['DELETE'])
@token_required
def delete_client(current_user_id, client_id):
    conn = get_db()
    result = conn.execute('DELETE FROM clients WHERE id = ? AND user_id = ?', (client_id, current_user_id))
    conn.commit()
    conn.close()
    if result.rowcount == 0:
        return jsonify({'error': 'Client not found'}), 404
    return jsonify({'success': True})

@app.route('/api/clients/<int:client_id>/items', methods=['GET'])
@token_required
def get_items(current_user_id, client_id):
    conn = get_db()
    client = conn.execute('SELECT id FROM clients WHERE id = ? AND user_id = ?', (client_id, current_user_id)).fetchone()
    if not client:
        conn.close()
        return jsonify({'error': 'Client not found'}), 404
    items = conn.execute('SELECT * FROM rental_items WHERE client_id = ? ORDER BY id', (client_id,)).fetchall()
    conn.close()
    return jsonify({'items': [dict(i) for i in items]})

@app.route('/api/clients/<int:client_id>/items/bulk', methods=['PUT'])
@token_required
def bulk_update_items(current_user_id, client_id):
    data = request.json
    items = data.get('items', [])
    conn = get_db()
    user = conn.execute('SELECT tax_rate FROM users WHERE id = ?', (current_user_id,)).fetchone()
    current_tax_rate = user['tax_rate'] if user else 16.0
    client = conn.execute('SELECT id FROM clients WHERE id = ? AND user_id = ?', (client_id, current_user_id)).fetchone()
    if not client:
        conn.close()
        return jsonify({'error': 'Client not found'}), 404
    conn.execute('DELETE FROM rental_items WHERE client_id = ?', (client_id,))
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
    conn.close()
    return jsonify({'success': True, 'count': len(items)})

@app.route('/api/tax-history', methods=['GET'])
@token_required
def tax_history(current_user_id):
    conn = get_db()
    items = conn.execute('''
        SELECT ri.*, c.client_name FROM rental_items ri
        JOIN clients c ON ri.client_id = c.id
        WHERE c.user_id = ?
        ORDER BY ri.created_at DESC
    ''', (current_user_id,)).fetchall()
    conn.close()
    return jsonify({'history': [dict(i) for i in items]})

@app.route('/api/reset-testing-data', methods=['POST'])
@token_required
def reset_testing_data(current_user_id):
    conn = get_db()
    conn.execute('DELETE FROM clients WHERE user_id = ?', (current_user_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/api/export-data', methods=['GET'])
@token_required
def export_data(current_user_id):
    conn = get_db()
    user = conn.execute('SELECT id, email, name, company_name, company_phone, company_address, company_email, signature_name, tax_rate FROM users WHERE id = ?', (current_user_id,)).fetchone()
    clients = conn.execute('SELECT * FROM clients WHERE user_id = ?', (current_user_id,)).fetchall()
    export = {'user': dict(user), 'clients': []}
    for client in clients:
        items = conn.execute('SELECT * FROM rental_items WHERE client_id = ?', (client['id'],)).fetchall()
        export['clients'].append({**dict(client), 'items': [dict(i) for i in items]})
    conn.close()
    return jsonify(export)

@app.route('/api/import-data', methods=['POST'])
@token_required
def import_data(current_user_id):
    data = request.json
    imported_clients = data.get('clients', [])
    conn = get_db()
    for client in imported_clients:
        cursor = conn.execute('''
            INSERT INTO clients (user_id, client_name, client_phone, client_email, client_pob, client_comment)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (current_user_id, client.get('client_name'), client.get('client_phone'), client.get('client_email'),
              client.get('client_pob'), client.get('client_comment')))
        new_client_id = cursor.lastrowid
        for item in client.get('items', []):
            conn.execute('''
                INSERT INTO rental_items (client_id, description, date_issued, cost_per_day, days_issued, amount_paid, tax_rate, tax_amount)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (new_client_id, item.get('description'), item.get('date_issued'),
                  item.get('cost_per_day'), item.get('days_issued'), item.get('amount_paid'),
                  item.get('tax_rate', 0), item.get('tax_amount', 0)))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/<path:path>')
def static_files(path):
    return send_from_directory('static', path)

if __name__ == '__main__':
    os.makedirs('data', exist_ok=True)
    init_db()
    app.run(host='0.0.0.0', port=3443, debug=False)