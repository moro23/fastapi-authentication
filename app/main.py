from fastapi import FastAPI

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from typing import Annotated
import schemas, models

from core import database, hashing
from core.config import settings

models.Base.metadata.create_all(bind=database.engine) 

## creating an instance of FastAPI
app = FastAPI()

# router = APIRouter(
#     tags=['Login']
# )


@app.post('/', response_model=schemas.ShowUser, tags=[''])
def createUser(request: schemas.CreateUser, db: Session = Depends(database.get_db)):
    """
    Creating a User 
    """
    ## lets hash the password coming from the user
    #hashed_password = pwd_context.hash(request.password)
    new_user = models.User(name=request.name, email=request.email, password=hashing.Hash.get_password_hash(request.password)).first()
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@app.get('/{id}', response_model=schemas.ShowUser)
def getUser(id:int, db: Session = Depends(database.get_db)):
    """
    Retrive an individual user with a specific id
    """
    user = db.query(models.User).filter(models.User.id == id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User with the {'name'} not available")
    return user 

## user authentication 

def authenticate_user(username: str, password: str, db: Session):

    user = get_user(username=username, db=db)
    
    if not user:
        return False
             
    if not Hasher.verify_password(password, user.hashed_password):
        return False 

    return user

@app.post('/token', response_model=schemas.LoginResponse, name='Login')
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db:Session=Depends(database.get_db)):
    user = authenticate_user(form_data.username, form_data.password, db)

    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="account is not active")

    # if not user.is:
    #     raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="account is not a super user")

    data = {"sub": user.email, "user_id": user.id}

    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data=data,
        expires_delta=access_token_expires
    )

    refresh_token = create_access_token(
        data=data,
        expires_delta=access_token_expires
    )

    token_db = TokenTable(id=user.id, access_toke=access_token, refresh_toke=refresh_token, status=True)
    db.add(token_db)
    db.commit()
    db.refresh(token_db)
    return {

        "access_token": access_token, 
        "refresh_token": refresh_token,
        "user":user,

    }


## 
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token") 
    
    
## lets create a function to create a dependency to indentify a current user
def get_current_user_from_token(token: str = Depends(oauth2_scheme), db: Session=Depends(database.get_db)):
    
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials"
    )

    try:

        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        print("username/email extracted is ", username)
        
    except JWTError:
        raise credentials_exception
    
    user = get_user(username=username, db=db)

    if user is None:
        raise credentials_exception
    return user 

@app.post("/logout", name='Logout')
async def logout(token: str = Depends(oauth2_scheme), db:Session=Depends(database.get_db)):
    #print(token)
    return await crud.log_revoke_token(token, db)