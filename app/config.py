import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your_default_secret_key'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'mysql+pymysql://root:2048@localhost/secure_file_sharing'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Expect MASTER_ENCRYPTION_KEY as a 64-character hex string
    master_key_hex = os.environ.get('MASTER_ENCRYPTION_KEY')

    if master_key_hex:
        MASTER_ENCRYPTION_KEY = bytes.fromhex(master_key_hex)
    else:
        print("⚠️ Warning: MASTER_ENCRYPTION_KEY is missing! Generating a temporary key.")
        MASTER_ENCRYPTION_KEY = os.urandom(32)  # Only for development
