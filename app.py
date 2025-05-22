from flask import Flask, render_template, request, redirect, url_for, session, flash, Response
import sqlite3
from functools import wraps
from datetime import datetime, timedelta
from azure.storage.blob import generate_blob_sas, BlobSasPermissions, BlobServiceClient
from azure.storage.blob import BlobServiceClient
import requests
from urllib.parse import quote
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Replace with a strong secret key

DATABASE = 'users.db'

# === Azure Storage Config ===
AZURE_STORAGE_ACCOUNT = 'offerletterstorage'
AZURE_STORAGE_KEY = os.environ.get("AZURE_STORAGE_KEY")
AZURE_CONTAINER_NAME = 'offer-letters'

# === DB Connection ===
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# === Login Decorator ===
def login_required(role=None):
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            if role and session.get('role') != role:
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function
    return wrapper

# === SAS Generator ===
def generate_blob_sas_url(blob_name):
    sas_token = generate_blob_sas(
        account_name=AZURE_STORAGE_ACCOUNT,
        container_name=AZURE_CONTAINER_NAME,
        blob_name=blob_name,
        account_key=AZURE_STORAGE_KEY,
        permission=BlobSasPermissions(read=True),
        expiry=datetime.utcnow() + timedelta(hours=1)
    )
    blob_url = f"https://{AZURE_STORAGE_ACCOUNT}.blob.core.windows.net/{AZURE_CONTAINER_NAME}/{blob_name}?{sas_token}"
    print("\u2705 Generated SAS URL:", blob_url)
    return blob_url

def generate_sas_url(blob_name):
    sas_token = generate_blob_sas(
        account_name=AZURE_STORAGE_ACCOUNT,
        container_name=AZURE_CONTAINER_NAME,
        blob_name=blob_name,
        account_key=AZURE_STORAGE_KEY,
        permission=BlobSasPermissions(read=True),
        expiry=datetime.utcnow() + timedelta(hours=1)
    )
    return f"https://{AZURE_STORAGE_ACCOUNT}.blob.core.windows.net/{AZURE_CONTAINER_NAME}/{blob_name}?{sas_token}"


# === Routes ===

@app.route('/pdf')
@login_required(role='candidate')
def serve_offer_pdf():
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()

    sas_url = generate_blob_sas_url(user['offer_filename'])

    response = requests.get(sas_url)
    if response.status_code == 200:
        return Response(response.content, mimetype='application/pdf')
    else:
        return "Failed to load PDF", 500

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ? AND password = ?',
            (username, password)
        ).fetchone()
        conn.close()

        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('candidate_dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/upload_offer_letter', methods=['POST'])
@login_required(role='admin')
def upload_offer_letter():
    user_id = request.form['user_id']
    file = request.files['offer_pdf']

    if file and file.filename.endswith('.pdf'):
        filename = f"offer_{user_id}.pdf"
        
        # Upload to Azure Blob
        blob_service_client = BlobServiceClient(account_url=f"https://{AZURE_STORAGE_ACCOUNT}.blob.core.windows.net", credential=AZURE_STORAGE_KEY)
        container_client = blob_service_client.get_container_client(AZURE_CONTAINER_NAME)
        container_client.upload_blob(name=filename, data=file, overwrite=True)
         
        # Save filename in DB
        conn = get_db_connection()
        conn.execute('UPDATE users SET offer_filename = ? WHERE id = ?', (filename, user_id))
        conn.commit()
        conn.close()

        flash('Offer letter uploaded and assigned successfully.', 'success')
    else:
        flash('Invalid file type. Please upload a PDF.', 'danger')
        print(f"✅ Uploaded {filename} to Azure for user ID {user_id}") 
    return redirect(url_for('admin_dashboard'))


@app.route('/candidate')
@login_required(role='candidate')
def candidate_dashboard():
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()

    if not user or not user['offer_filename']:
        return "Offer letter not assigned.", 404

    # Generate SAS URL for this user's assigned PDF
    sas_url = generate_sas_url(user['offer_filename'])
    encoded_sas_url = quote(sas_url, safe='')

    print("🔗 Final Encoded URL for Viewer:", encoded_sas_url)

    return render_template(
        'candidate.html',
        username=user['username'],
        offer_file=user['offer_filename'],
        sas_url=encoded_sas_url
    )

@app.route('/admin')
@login_required(role='admin')
def admin_dashboard():
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users WHERE role = ?', ('candidate',)).fetchall()
    conn.close()
    return render_template('admin.html', username=session['username'], users=users)

@app.route('/add_user', methods=['POST'])
@login_required(role='admin')
def add_user():
    username = request.form['username'].strip()
    password = request.form['password'].strip()
    offer_filename = request.form['offer_filename'].strip()

    if not username or not password or not offer_filename:
        flash('All fields are required.', 'danger')
        return redirect(url_for('admin_dashboard'))

    conn = get_db_connection()
    try:
        conn.execute(
            'INSERT INTO users (username, password, role, offer_filename) VALUES (?, ?, ?, ?)',
            (username, password, 'candidate', offer_filename)
        )
        conn.commit()
        flash(f'User {username} added successfully.', 'success')
    except sqlite3.IntegrityError:
        flash(f'Username "{username}" already exists.', 'danger')
    finally:
        conn.close()

    return redirect(url_for('admin_dashboard'))

@app.route('/delete_user', methods=['POST'])
@login_required(role='admin')
def delete_user():
    user_id = request.form['user_id']

    conn = get_db_connection()
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

    flash('User deleted successfully.', 'success')
    return redirect(url_for('admin_dashboard'))

# === Main App Runner ===
if __name__ == '__main__':
    app.run(debug=True)
