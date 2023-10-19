from fastapi import Request, HTTPException, Depends
from jwt.exceptions import ExpiredSignatureError
from exceptions import BlacklistedToken
from database import SessionLocal
from email.generator import Generator 
from jose import JWTError, jwt

from core.config import settings

from fastapi.security import OAuth2PasswordBearer

def get_db() -> Generator:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

def validate_bearer(token: str = Depends(oauth2_scheme), db = Depends(get_db)):
    from routers.users.auth.crud import is_token_blacklisted 
    decode_jwt = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])

    try:
        if is_token_blacklisted(token, db):
            raise BlacklistedToken('token blacklisted')
        return decode_jwt

    except Exception as e:
        raise HTTPException(
            status_code=401 if isinstance(e, ExpiredSignatureError) else 500, 
            detail=raise_exc(loc="Bearer <token>[validate_bearer]", msg=f"{e}", type=f"{e.__class__}"), 
            headers={"WWW-Authenticate": "Bearer"}
        )