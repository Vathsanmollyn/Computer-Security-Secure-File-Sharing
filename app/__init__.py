# app/__init__.py
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate  # (not used if you don't want migrations)
from .config import Config

db = SQLAlchemy()
# If you're not using migrations, you don't need to initialize Migrate
# migrate = Migrate()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Debugging: Print if key is set
    print("🔑 MASTER_ENCRYPTION_KEY Loaded:", 'Yes' if 'MASTER_ENCRYPTION_KEY' in app.config else 'No')

    db.init_app(app)
    
    with app.app_context():

        # Import models so that they're registered with SQLAlchemy
        from .models import User, File, SharingLink, AuditLog

        # This will create all tables if they don't exist
        db.create_all()

        # Register your blueprints
        from .auth import auth as auth_blueprint
        app.register_blueprint(auth_blueprint)

        from .routes import main
        app.register_blueprint(main)

        from .files import files_bp
        app.register_blueprint(files_bp)

    return app
