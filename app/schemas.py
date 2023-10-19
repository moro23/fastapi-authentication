from pydantic import BaseModel, constr, EmailStr
import datetime
from typing import List, Optional

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

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None

class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    #account: Optional[str]
 

    class Config:
        orm_mode = True

class TokenCreate(BaseModel):
    access_token: Optional[str]
    token_type: Optional[str]
    status : bool
    create_date: datetime.datetime