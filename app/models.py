from datetime import datetime
from app import db

# Association table for user-to-user sharing
file_access = db.Table(
    'file_access',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('file_id', db.Integer, db.ForeignKey('files.id'), primary_key=True)
)

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    files = db.relationship('File', backref='owner', lazy=True)
    
    def __repr__(self):
        return f"<User {self.username}>"

class File(db.Model):
    __tablename__ = 'files'
    
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    original_name = db.Column(db.String(255), nullable=False)
    stored_name = db.Column(db.String(255), nullable=False)
    # encryption_key stores: encrypted_file_secret_hex:nonce_hex:salt_hex:iv_hex
    encryption_key = db.Column(db.String(1024), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    permitted_users = db.relationship('User', secondary=file_access, backref='shared_files', lazy='subquery')
    sharing_links = db.relationship('SharingLink', backref='file', lazy=True)
    
    def __repr__(self):
        return f"<File {self.original_name} owned by {self.owner_id}>"

class SharingLink(db.Model):
    __tablename__ = 'sharing_links'
    
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('files.id'), nullable=False)
    token = db.Column(db.String(64), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def is_expired(self):
        from datetime import datetime
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at
    
    def __repr__(self):
        return f"<SharingLink token={self.token} for file {self.file_id}>"

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action = db.Column(db.String(50), nullable=False)
    file_id = db.Column(db.Integer, db.ForeignKey('files.id'), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref='audit_logs')
    file = db.relationship('File', backref='audit_logs')
    
    def __repr__(self):
        return f"<AuditLog {self.action} by {self.user_id} on {self.file_id} at {self.timestamp}>"
