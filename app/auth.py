from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from .models import User, AuditLog
from . import db

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password_hash, password):
            flash("Invalid credentials. Please try again.")
            return redirect(url_for('auth.login'))
        session['user_id'] = user.id
        flash("Logged in successfully.")
        new_log = AuditLog(user_id=user.id, action='LOGIN')
        db.session.add(new_log)
        db.session.commit()
        return redirect(url_for('main.dashboard'))
    return render_template('login.html')

@auth.route('/logout')
def logout():
    user_id = session.get('user_id')
    session.pop('user_id', None)
    flash("You have been logged out.")
    if user_id:
        new_log = AuditLog(user_id=user_id, action='LOGOUT')
        db.session.add(new_log)
        db.session.commit()
    return redirect(url_for('auth.login'))

@auth.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            flash("Username and password are required.")
            return redirect(url_for('auth.register'))
        if User.query.filter_by(username=username).first():
            flash("Username already exists.")
            return redirect(url_for('auth.register'))
        new_user = User(username=username, password_hash=generate_password_hash(password))
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful. Please log in.")
        return redirect(url_for('auth.login'))
    return render_template('register.html')
