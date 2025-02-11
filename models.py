from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from flask_bcrypt import Bcrypt
from datetime import datetime
from config import Config
import os

db = SQLAlchemy()
bcrypt = Bcrypt()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class Board(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    location_url = db.Column(db.String(300), nullable=False)
    renewal_date = db.Column(db.Date, nullable=False)
    renewal_amount = db.Column(db.Float, nullable=False)
    image = db.Column(db.String(300), nullable=True)
    updated_by = db.Column(db.String(150), nullable=True)  # Tracks who updated the board
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)  # Timestamp for updates

def create_tables():
    """Creates database tables if they don't exist"""
    if not os.path.exists("boards.db"):  # Prevents recreation of DB every time app runs
        db.create_all()

