import os

# Get the absolute path of the folder where config.py is
BASEDIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    
    # Absolute path to SQLite DB
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{os.path.join(BASEDIR, 'instance', 'goldshop.db')}"
    )
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Absolute path to uploads folder
    UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", os.path.join(BASEDIR, "uploads"))
    
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5MB
    ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}
