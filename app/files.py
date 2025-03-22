# app/files.py

import os
import io
import uuid
import secrets
from datetime import datetime, timedelta
from flask import (
    Blueprint, render_template, request, redirect,
    url_for, flash, session, current_app, send_file
)
from werkzeug.utils import secure_filename
from sqlalchemy import or_
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from . import db
from .models import File, User, SharingLink, AuditLog

files_bp = Blueprint('files', __name__)

def aes_encrypt_cbc(data, key, iv):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()

def aes_decrypt_cbc(ciphertext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()

@files_bp.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if 'user_id' not in session:
        flash("Please log in first.")
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        if 'file' not in request.files:
            flash("No file part in the request.")
            return redirect(request.url)

        file = request.files['file']
        if file.filename == '':
            flash("No file selected.")
            return redirect(request.url)

        original_name = secure_filename(file.filename)
        file_data = file.read()

        # Generate a random per-file secret (32 bytes)
        file_secret = os.urandom(32)
        # Generate a random salt (16 bytes) for key derivation
        salt = os.urandom(16)
        # Derive an AES key using PBKDF2HMAC with SHA-512
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        aes_key = kdf.derive(file_secret)
        # Generate a random IV for AES-CBC
        iv = os.urandom(16)
        # Encrypt the file data using AES-CBC
        encrypted_data = aes_encrypt_cbc(file_data, aes_key, iv)

        # Encrypt the per-file secret using AES-GCM with the master key
        master_key = current_app.config['MASTER_ENCRYPTION_KEY']
        aesgcm = AESGCM(master_key)
        nonce = os.urandom(12)
        encrypted_file_secret = aesgcm.encrypt(nonce, file_secret, None)
        # Store the encrypted_file_secret, nonce, salt, iv as hex
        encryption_key_str = (
            encrypted_file_secret.hex() + ":" +
            nonce.hex() + ":" +
            salt.hex() + ":" +
            iv.hex()
        )

        # Save the encrypted file to disk
        random_name = f"{uuid.uuid4().hex}.enc"
        stored_path = os.path.join('uploads', random_name)
        with open(stored_path, 'wb') as f:
            f.write(encrypted_data)

        new_file = File(
            owner_id=session['user_id'],
            original_name=original_name,
            stored_name=random_name,
            encryption_key=encryption_key_str
        )
        db.session.add(new_file)
        db.session.commit()

        # Log the upload event
        new_log = AuditLog(user_id=session['user_id'], action='UPLOAD', file_id=new_file.id)
        db.session.add(new_log)
        db.session.commit()

        flash("File uploaded successfully.")
        return redirect(url_for('main.dashboard'))  # Go back to the dashboard

    return render_template('upload.html')

@files_bp.route('/download/<int:file_id>')
def download_file(file_id):
    if 'user_id' not in session:
        flash("Please log in first.")
        return redirect(url_for('auth.login'))

    file_record = File.query.get(file_id)
    if not file_record:
        flash("File not found.")
        return redirect(url_for('main.dashboard'))

    current_user_id = session['user_id']
    user_has_access = (
        file_record.owner_id == current_user_id or
        any(u.id == current_user_id for u in file_record.permitted_users)
    )
    if not user_has_access:
        flash("You do not have permission to download this file.")
        return redirect(url_for('main.dashboard'))

    encrypted_path = os.path.join('uploads', file_record.stored_name)
    if not os.path.exists(encrypted_path):
        flash("File not found on server.")
        return redirect(url_for('main.dashboard'))

    with open(encrypted_path, 'rb') as f:
        encrypted_data = f.read()

    # Decrypt the per-file secret
    encryption_key_str = file_record.encryption_key
    try:
        encrypted_file_secret_hex, nonce_hex, salt_hex, iv_hex = encryption_key_str.split(":")
    except Exception:
        flash("Encryption key data malformed.")
        return redirect(url_for('main.dashboard'))

    encrypted_file_secret = bytes.fromhex(encrypted_file_secret_hex)
    nonce = bytes.fromhex(nonce_hex)
    salt = bytes.fromhex(salt_hex)
    iv = bytes.fromhex(iv_hex)

    master_key = current_app.config['MASTER_ENCRYPTION_KEY']
    aesgcm = AESGCM(master_key)
    try:
        file_secret = aesgcm.decrypt(nonce, encrypted_file_secret, None)
    except Exception:
        flash("Error decrypting file secret.")
        return redirect(url_for('main.dashboard'))

    # Re-derive the AES key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    aes_key = kdf.derive(file_secret)

    try:
        decrypted_data = aes_decrypt_cbc(encrypted_data, aes_key, iv)
    except Exception:
        flash("Error decrypting file.")
        return redirect(url_for('main.dashboard'))

    # Log the download
    new_log = AuditLog(user_id=current_user_id, action='DOWNLOAD', file_id=file_record.id)
    db.session.add(new_log)
    db.session.commit()

    return send_file(
        io.BytesIO(decrypted_data),
        as_attachment=True,
        download_name=file_record.original_name
    )

@files_bp.route('/download_raw/<int:file_id>')
def download_raw(file_id):
    """
    Returns the raw encrypted file (ciphertext) without decryption.
    """
    if 'user_id' not in session:
        flash("Please log in first.")
        return redirect(url_for('auth.login'))

    file_record = File.query.get(file_id)
    if not file_record:
        flash("File not found.")
        return redirect(url_for('main.dashboard'))

    current_user_id = session['user_id']
    user_has_access = (
        file_record.owner_id == current_user_id or
        any(u.id == current_user_id for u in file_record.permitted_users)
    )
    if not user_has_access:
        flash("You do not have permission to download this file.")
        return redirect(url_for('main.dashboard'))

    encrypted_path = os.path.join('uploads', file_record.stored_name)
    if not os.path.exists(encrypted_path):
        flash("File not found on server.")
        return redirect(url_for('main.dashboard'))

    with open(encrypted_path, 'rb') as f:
        encrypted_data = f.read()

    return send_file(
        io.BytesIO(encrypted_data),
        as_attachment=True,
        download_name=file_record.original_name + ".enc"
    )

@files_bp.route('/grant_access/<int:file_id>', methods=['POST'])
def grant_access(file_id):
    if 'user_id' not in session:
        flash("Please log in first.")
        return redirect(url_for('auth.login'))

    file_record = File.query.get(file_id)
    if not file_record or file_record.owner_id != session['user_id']:
        flash("File not found or permission denied.")
        return redirect(url_for('main.dashboard'))

    username = request.form.get('username')
    if not username:
        flash("Username is required to grant access.")
        return redirect(url_for('main.dashboard'))

    user_to_share = User.query.filter_by(username=username).first()
    if not user_to_share:
        flash(f"User '{username}' does not exist.")
        return redirect(url_for('main.dashboard'))

    if user_to_share not in file_record.permitted_users:
        file_record.permitted_users.append(user_to_share)
        db.session.commit()
        flash(f"Access granted to user '{username}'.")
    else:
        flash(f"User '{username}' already has access.")

    return redirect(url_for('main.dashboard'))

@files_bp.route('/revoke_access/<int:file_id>', methods=['POST'])
def revoke_access(file_id):
    if 'user_id' not in session:
        flash("Please log in first.")
        return redirect(url_for('auth.login'))

    file_record = File.query.get(file_id)
    if not file_record or file_record.owner_id != session['user_id']:
        flash("File not found or permission denied.")
        return redirect(url_for('main.dashboard'))

    username = request.form.get('username')
    if not username:
        flash("Username is required to revoke access.")
        return redirect(url_for('main.dashboard'))

    user_to_revoke = User.query.filter_by(username=username).first()
    if not user_to_revoke:
        flash(f"User '{username}' does not exist.")
        return redirect(url_for('main.dashboard'))

    if user_to_revoke in file_record.permitted_users:
        file_record.permitted_users.remove(user_to_revoke)
        db.session.commit()
        flash(f"Access revoked from user '{username}'.")
    else:
        flash(f"User '{username}' does not have access to revoke.")

    return redirect(url_for('main.dashboard'))

@files_bp.route('/generate_share/<int:file_id>', methods=['POST'])
def generate_share(file_id):
    if 'user_id' not in session:
        flash("Please log in first.")
        return redirect(url_for('auth.login'))

    file_record = File.query.get(file_id)
    current_user_id = session['user_id']

    if not file_record:
        flash("File not found.")
        return redirect(url_for('main.dashboard'))

    # Allow both the owner and permitted users to generate a sharing link
    is_owner = file_record.owner_id == current_user_id
    has_access = any(user.id == current_user_id for user in file_record.permitted_users)

    if not (is_owner or has_access):
        flash("You do not have permission to share this file.")
        return redirect(url_for('main.dashboard'))

    token = secrets.token_hex(32)
    expires_at = datetime.utcnow() + timedelta(hours=24)
    sharing_link = SharingLink(file_id=file_id, token=token, expires_at=expires_at)
    db.session.add(sharing_link)
    db.session.commit()

    share_url = url_for('files.shared_download', token=token, _external=True)
    flash(f"Public share link generated: {share_url}")
    return redirect(url_for('main.dashboard'))



@files_bp.route('/s/<token>')
def shared_download(token):
    sharing_link = SharingLink.query.filter_by(token=token).first()
    if not sharing_link:
        flash("Invalid share token.")
        return redirect(url_for('auth.login'))

    if sharing_link.is_expired():
        flash("Share link has expired.")
        return redirect(url_for('auth.login'))

    file_record = sharing_link.file
    encrypted_path = os.path.join('uploads', file_record.stored_name)
    if not os.path.exists(encrypted_path):
        flash("File not found on server.")
        return redirect(url_for('auth.login'))

    with open(encrypted_path, 'rb') as f:
        encrypted_data = f.read()

    encryption_key_str = file_record.encryption_key
    try:
        encrypted_file_secret_hex, nonce_hex, salt_hex, iv_hex = encryption_key_str.split(":")
    except Exception:
        flash("Encryption key data malformed.")
        return redirect(url_for('auth.login'))

    encrypted_file_secret = bytes.fromhex(encrypted_file_secret_hex)
    nonce = bytes.fromhex(nonce_hex)
    salt = bytes.fromhex(salt_hex)
    iv = bytes.fromhex(iv_hex)

    master_key = current_app.config['MASTER_ENCRYPTION_KEY']
    aesgcm = AESGCM(master_key)
    try:
        file_secret = aesgcm.decrypt(nonce, encrypted_file_secret, None)
    except Exception:
        flash("Error decrypting file secret.")
        return redirect(url_for('auth.login'))

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    aes_key = kdf.derive(file_secret)

    try:
        decrypted_data = aes_decrypt_cbc(encrypted_data, aes_key, iv)
    except Exception:
        flash("Error decrypting file.")
        return redirect(url_for('auth.login'))

    new_log = AuditLog(user_id=None, action='PUBLIC_DOWNLOAD', file_id=file_record.id)
    db.session.add(new_log)
    db.session.commit()

    return send_file(
        io.BytesIO(decrypted_data),
        as_attachment=True,
        download_name=file_record.original_name
    )
