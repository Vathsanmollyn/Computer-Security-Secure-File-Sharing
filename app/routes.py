from flask import Blueprint, session, redirect, url_for, flash, render_template
from .models import File, User, file_access
from . import db

main = Blueprint('main', __name__)

@main.route('/')
def index():
    return redirect(url_for('auth.login'))

@main.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash("Please log in first.")
        return redirect(url_for('auth.login'))
    
    user_id = session['user_id']
    user = User.query.get(user_id)

    user_files = File.query.filter_by(owner_id=user_id).all()
    shared_files = (
        db.session.query(File, User.username.label("owner_name"))
        .join(file_access, File.id == file_access.c.file_id)
        .join(User, File.owner_id == User.id)
        .filter(file_access.c.user_id == user_id)
        .all()
    )

    return render_template('dashboard.html', files=user_files, shared_files=shared_files)
