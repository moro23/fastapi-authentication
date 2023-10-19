from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt

from core.config import settings

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """
    This function creates an access token for authentication using jwt 

    Arg:
    data: dict 
    """
    ## lets create a copy of the data received
    to_encode = data.copy()

    ## lets set an expiration time for the access token
    if expires_delta:
        expire = datetime.utcnow() + expires_delta

    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire})

    ## lets use the secrete key and algo to encode the data dic to get a dedicated access token
    encode_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

    return encode_jwt