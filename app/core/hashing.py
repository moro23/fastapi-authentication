from passlib.context import CryptContext
from datetime import datetime, time, timedelta
from jose import jwt
from core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class Hasher():
    @staticmethod 
    def verify_password(plain_password, hashed_password):
        return pwd_context.verify(plain_password, hashed_password)

    @staticmethod 
    def get_password_hash(password='password'):
        return pwd_context.hash(password)
    


    @staticmethod 
    def empty_password_hash(password : str):
        return pwd_context.hash(password)
    

    @staticmethod 
    def generate_reset_password_token(expires_delta: int = None):
        if expires_delta is not None:
            expires_delta = datetime.utcnow() + expires_delta
        else:
            expires_delta = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
            to_encode = {"exp": expires_delta}
            encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET_KEY, settings.ALGORITHM)
        return encoded_jwt
    
    
