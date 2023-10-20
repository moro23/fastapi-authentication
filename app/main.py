from fastapi import FastAPI, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from typing import Annotated, Union
from sqlalchemy import Boolean, Column, ForeignKey, Integer, String
from sqlalchemy.orm import relationship
from pydantic import BaseModel, constr, EmailStr
import datetime
from typing import List, Optional


from core.database import Base


from core import database, dependencies, hashing, utils
from core.config import settings


## Schemas 

class EmailBase(BaseModel):
    #email: constr(regex='')
    email: EmailStr

class CreateUser(EmailBase):
    username: str
    email: EmailStr 
    password: constr(min_length=8) = None

class ShowUser(EmailBase):
    name: str
    email: EmailBase
   

    class Config():
        orm_mode = True


class Login(BaseModel):
    username: str
    password: str

    class Config():
        orm_mode = True

class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    #account: Optional[str]
 

    class Config:
        orm_mode = True

class Logout(BaseModel):
    access_token: str
    refresh_token: str


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None

class AccessToken(BaseModel):
    access_token: str

class RefreshToken(BaseModel):
    refresh_token: str

class TokenCreate(BaseModel):
    access_token: Optional[str]
    token_type: Optional[str]
    status : bool
    create_date: datetime.datetime




## Models 

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    email = Column(String(255), unique=True, index=True)
    hashed_password = Column(String(255),nullable=True)
    reset_password_token = Column(String(255), nullable=True)


class EmailVerificationCode():
    pass



#models.Base.metadata.create_all(bind=database.engine) 

## creating an instance of FastAPI
app = FastAPI()



## api-endpoints for our user registration route
@app.post('/', response_model=ShowUser, name="Sign Up", tags=['User Registration'])
def createUser(request: CreateUser, db: Session = Depends(database.get_db)):
    """
    Creating a User 
    """
    new_user = User(name=request.name, email=request.email, password=hashing.Hash.get_password_hash(request.password)).first()
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@app.get('/{id}', response_model=ShowUser, name='Get User', tags=['User Registration'])
def getUser(id:int, db: Session = Depends(database.get_db)):
    """
    Retrive an individual user with a specific id
    """
    user = db.query(User).filter(User.id == id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User with the {'name'} not available")
    return user 

## user authentication 

async def verify_user(payload:Login, account:str, db:Session):
  
    user = db.query(User).filter_by(email=payload.email).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not foundNotFound")
    if user.verify_hash(payload.password, user.password):
        return user
    raise HTTPException(status_code=401, detail="password wrong credentials Unauthorized" )
    
    # except Exception as e:
    #     print(e)

def read_by_id(id:str, db:Session):
    return db.query(User).get(id)

async def read_by_email(email:str,db:Session):
    return db.query(User).filter_by(email=email).first()

async def is_token_blacklisted(token:str, db:Session):
    return db.query(RevokedToken.id).filter_by(jti=token).first() is not None

async def add_email_verification_code(email, db:Session):
    user = db.query(User).filter_by(email=email)
    if not user:
        raise HTTPException(status_code=404, detail="email user not found NotFound")
    obj = EmailVerificationCode(email=email)
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj

async def revoke_token(payload:Union[Logout, str], db:Session):
    try:
        if isinstance(payload, str):
            db.add(RevokedToken(jti=payload))
        else:
            db.add_all([RevokedToken(jti=token) for token in payload.dict().values()])
        db.commit()
        return 'success', 'token(s) successfully blacklisted'
    except Exception as e: 
        print(e) 

## ## api-endpoints for our user authentication route

@app.post('/login', response_model=LoginResponse, name='Login', tags=["User Authentication"])
async def authenticate(payload:Login, db:Session=Depends(database.get_db)):
    user = await verify_user(payload, db)

    if not user.is_active:
        raise HTTPException(status_code=417, detail="account is not active")

    if not user.is_verified:
        raise HTTPException(status_code=417, detail="account is not verified")

    data = {"id":user.id}

    return {
        "access_token": utils.create_jwt(data=data, exp=settings.ACCESS_TOKEN_DURATION_IN_MINUTES),
        "refresh_token":utils.create_jwt(data=data, exp=settings.REFRESH_TOKEN_DURATION_IN_MINUTES),
        "user":user
    }

@app.post("/logout", name='Logout', tags=["User Authentication"])
async def logout(payload:Logout, db:Session=Depends(database.get_db)):
    return await revoke_token(payload, db)

@app.post("/token/refresh", response_model=Token, name='Refresh Token',tags=["User Authentication"])
async def refresh_token(payload:RefreshToken, db:Session=Depends(database.get_db)):
    if await is_token_blacklisted(payload.refresh_token, db):
        raise HTTPException(status_code=401, detail="refresh_token token blacklisted BlacklistedToken")
    
    if await revoke_token(payload, db):
        data = decode_jwt(token=payload.refresh_token)
        return {
            "access_token": utils.create_jwt(data=data, exp=settings.ACCESS_TOKEN_DURATION_IN_MINUTES),
            "refresh_token": utils.create_jwt(data=data, exp=settings.REFRESH_TOKEN_DURATION_IN_MINUTES),
        }

    raise HTTPException(status_code=417)

@app.get('/current-user', response_model=ShowUser, name='JWT User',tags=["User Authentication"])
def get_current_user(data:str=Depends(dependencies.validate_bearer), db:Session=Depends(database.get_db)):
    return read_by_id(data['id'], data['account'], db)

@app.post("/send-email-verification-code", name='Request Email verification code',tags=["User Authentication"])
async def request_email_verification_code(request:Request, payload:EmailBase, db:Session=Depends(database.get_db)):
    obj = await add_email_verification_code(payload.email, db)
    #schedule_del_code(obj.email)
    try:
        if async_send_email(mail={
            "subject":"Email Verification",
            "recipients":[obj.email],
            "body":{'code': f'{obj.code}', 'base_url':request.base_url},
            "template_name":"verification-code.html"
        }):return 'you will receive code shortly'
    except Exception as e:
        logger(__name__, e, 'critical')
    raise HTTPException(status_code=417)