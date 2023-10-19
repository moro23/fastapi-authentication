from jose import jwt
from datetime import timedelta, datetime, date

from core import config


def create_jwt(data:dict, exp:timedelta=None):
    data.update({'exp':datetime.utcnow() + timedelta(minutes=exp if exp else config.settings.DEFAULT_TOKEN_DURATION_IN_MINUTES)})
    return jwt.encode(data, config.settings.SECRET, algorithm="")

def decode_jwt(token):
    return jwt.decode(token, config.settings.SECRET, algorithms="")