import os

class Config:
    SECRET_KEY = 'your_secret_key_here'  # Use a strong, secure secret key
    SQLALCHEMY_DATABASE_URI = 'sqlite:///boards.db'  # Use your desired database path
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = os.path.join(os.getcwd(), 'static/uploads')  # Ensure this directory exists
