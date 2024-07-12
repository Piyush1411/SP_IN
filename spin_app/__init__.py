from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from werkzeug.security import generate_password_hash
import os

app = Flask(__name__)

# Load configuration from config.py
from spin_app import config

# Initialize extensions
db = SQLAlchemy(app)
app.app_context().push()
login_manager = LoginManager(app)
login_manager.login_view = "login"


from spin_app.models import User

with app.app_context():
    if not os.path.exists("db.sqlite3"):
        db.create_all()
        admin = User.query.filter_by(is_admin=True).first()
        if not admin:
            password_hash = generate_password_hash('admin')
            admin = User(username='admin', email='admin@example.com', password=password_hash, role='admin', is_admin=True)
            db.session.add(admin)
            db.session.commit()
        print("Database created and admin user added")

# Import routes at the end to avoid circular imports
from spin_app import routes
