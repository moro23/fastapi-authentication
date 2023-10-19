from fastapi import FastAPI, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from typing import Annotated, Union
import schemas, models


from core import database, dependencies, hashing, utils
from core.config import settings

models.Base.metadata.create_all(bind=database.engine) 

## creating an instance of FastAPI
app = FastAPI()

# router = APIRouter(
#     tags=['Login']
# )


@app.post('/', response_model=schemas.ShowUser, name="Sign Up", tags=['User Registration'])
def createUser(request: schemas.CreateUser, db: Session = Depends(database.get_db)):
    """
    Creating a User 
    """
    new_user = models.User(name=request.name, email=request.email, password=hashing.Hash.get_password_hash(request.password)).first()
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@app.get('/{id}', response_model=schemas.ShowUser, name='Get User', tags=['User Registration'])
def getUser(id:int, db: Session = Depends(database.get_db)):
    """
    Retrive an individual user with a specific id
    """
    user = db.query(models.User).filter(models.User.id == id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User with the {'name'} not available")
    return user 

## user authentication 

async def verify_user(payload:schemas.Login, account:str, db:Session):
  
    user = db.query(models.User).filter_by(email=payload.email).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not foundNotFound")
    if user.verify_hash(payload.password, user.password):
        return user
    raise HTTPException(status_code=401, detail="password wrong credentials Unauthorized" )
    
    # except Exception as e:
    #     print(e)

def read_by_id(id:str, db:Session):
    return db.query(models.User).get(id)

async def read_by_email(email:str,db:Session):
    return db.query(models.User).filter_by(email=email).first()

async def is_token_blacklisted(token:str, db:Session):
    return db.query(models.RevokedToken.id).filter_by(jti=token).first() is not None

async def add_email_verification_code(email, db:Session):
    user = db.query(models.User).filter_by(email=email)
    if not user:
        raise HTTPException(status_code=404, detail="email user not found NotFound")
    obj = models.EmailVerificationCode(email=email)
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj

async def revoke_token(payload:Union[schemas.Logout, str], db:Session):
    try:
        if isinstance(payload, str):
            db.add(models.RevokedToken(jti=payload))
        else:
            db.add_all([models.RevokedToken(jti=token) for token in payload.dict().values()])
        db.commit()
        return 'success', 'token(s) successfully blacklisted'
    except Exception as e: 
        print(e) 

## api route for user authentication

@app.post('/login', response_model=schemas.LoginResponse, name='Login', tags=["User Authentication"])
async def authenticate(payload:schemas.Login, db:Session=Depends(database.get_db)):
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
async def logout(payload:schemas.Logout, db:Session=Depends(database.get_db)):
    return await revoke_token(payload, db)

@app.post("/token/refresh", response_model=schemas.Token, name='Refresh Token',tags=["User Authentication"])
async def refresh_token(payload:schemas.RefreshToken, db:Session=Depends(database.get_db)):
    if await is_token_blacklisted(payload.refresh_token, db):
        raise HTTPException(status_code=401, detail="refresh_token token blacklisted BlacklistedToken")
    
    if await revoke_token(payload, db):
        data = decode_jwt(token=payload.refresh_token)
        return {
            "access_token": utils.create_jwt(data=data, exp=settings.ACCESS_TOKEN_DURATION_IN_MINUTES),
            "refresh_token": utils.create_jwt(data=data, exp=settings.REFRESH_TOKEN_DURATION_IN_MINUTES),
        }

    raise HTTPException(status_code=417)

@app.get('/current-user', response_model=schemas.ShowUser, name='JWT User',tags=["User Authentication"])
def get_current_user(data:str=Depends(dependencies.validate_bearer), db:Session=Depends(database.get_db)):
    return read_by_id(data['id'], data['account'], db)

@app.post("/send-email-verification-code", name='Request Email verification code',tags=["User Authentication"])
async def request_email_verification_code(request:Request, payload:schemas.EmailBase, db:Session=Depends(database.get_db)):
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