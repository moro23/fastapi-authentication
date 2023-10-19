## core/config.py
## import libraries
from fastapi.templating import Jinja2Templates
from datetime import time, date



class Settings:
    PROJECT_NAME:str = ""
    PROJECT_VERSION: str = "1.0.0"

    # POSTGRES_USER: str = os.getenv("POSTGRES_USER")
    # POSTGRES_PASSWORD: str = os.getenv("POSTGRES_PASSWORD")
    # POSTGRES_SERVER: str = os.getenv("POSTGRES_SERVER", "localhost")
    # POSTGRES_PORT: str = os.getenv("POSTGRES_PORT", 5432)
    # POSTGRES_DB: str = os.getenv("POSTGRES_DB", "")

    # DATABASE_URL = f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_SERVER}:{POSTGRES_PORT}/{POSTGRES_DB}"


    ## lets define var for creating the access token
    SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
    ALGORITHM = "HS256"
    # JWT_SECRET_KEY : str = secrets.token_urlsafe(32)
    # ACCESS_TOKEN_EXPIRE_MINUTES = 30
    # EMAIL_CODE_DURATION_IN_MINUTES= 15
    # EMAIL_CODE_DURATION_IN_MINUTES: int = 15
    # ACCESS_TOKEN_DURATION_IN_MINUTES: int = 60
    # REFRESH_TOKEN_DURATION_IN_MINUTES: int = 600
    # PASSWORD_RESET_TOKEN_DURATION_IN_MINUTES: int = 15
    # ACCOUNT_VERIFICATION_TOKEN_DURATION_IN_MINUTES: int = 15






settings = Settings()