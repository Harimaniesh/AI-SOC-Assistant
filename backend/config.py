import os
import secrets
import logging
from pathlib import Path
from pydantic_settings import BaseSettings

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("AI_SOC_Assistant")

BASE_DIR = Path(__file__).resolve().parent.parent

class Settings(BaseSettings):
    # Security
    JWT_SECRET_KEY: str = ""
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 120

    # Database
    DATABASE_URL: str = ""

    # AI Integration
    OPENAI_API_KEY: str = ""

    # Directory Paths (Absolute paths inside workspace)
    UPLOAD_DIR: str = str(BASE_DIR / "uploads")
    REPORTS_DIR: str = str(BASE_DIR / "reports")

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()

# Post-processing configurations for security compliance
if not settings.JWT_SECRET_KEY:
    # Look for a local jwt_secret.txt file to persist between runs
    secret_file = BASE_DIR / "backend" / "jwt_secret.txt"
    if secret_file.exists():
        settings.JWT_SECRET_KEY = secret_file.read_text().strip()
    else:
        logger.warning(
            "JWT_SECRET_KEY is empty. Generating ephemeral secret key for session management! "
            "Note: Sessions will invalidate on server restart."
        )
        settings.JWT_SECRET_KEY = secrets.token_hex(32)
        try:
            # Try to persist the secret locally for ease of development/testing consistency
            secret_file.parent.mkdir(parents=True, exist_ok=True)
            secret_file.write_text(settings.JWT_SECRET_KEY)
        except Exception as e:
            logger.error(f"Could not persist JWT secret locally: {e}")

if not settings.DATABASE_URL:
    # Default to SQLite local database in the database/ folder
    db_dir = BASE_DIR / "database"
    db_dir.mkdir(parents=True, exist_ok=True)
    settings.DATABASE_URL = f"sqlite:///{db_dir}/soc_assistant.db"
    logger.info(f"DATABASE_URL not set. Falling back to local SQLite database at {settings.DATABASE_URL}")

# Create uploads and reports folders
Path(settings.UPLOAD_DIR).mkdir(parents=True, exist_ok=True)
Path(settings.REPORTS_DIR).mkdir(parents=True, exist_ok=True)
