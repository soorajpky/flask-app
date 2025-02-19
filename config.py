import os

class Config:
    SECRET_KEY = 'your_secret_key_here'  # Use a strong, secure secret key
    SQLALCHEMY_DATABASE_URI = 'sqlite:///boards.db'  # Database path
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = os.path.join(os.getcwd(), 'static/uploads')  # Image upload path

# Ensure the folder exists
if not os.path.exists(Config.UPLOAD_FOLDER):
    os.makedirs(Config.UPLOAD_FOLDER)
