import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")
DATABASE_PATH = os.getenv("DATABASE_PATH", str(BASE_DIR / "data" / "cheker.db"))
MAX_CONCURRENT_CHECKS = int(os.getenv("MAX_CONCURRENT_CHECKS", "5"))
CHECK_TIMEOUT = int(os.getenv("CHECK_TIMEOUT", "30"))
CLIENT_HELLO_DIR = str(BASE_DIR / "app" / "client_hello")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_HOURS = 24
