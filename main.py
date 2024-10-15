import fastapi
from fastapi import FastAPI,Depends,HTTPException,status,BackgroundTasks
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordBearer,OAuth2PasswordRequestForm
from jose import JWTError,jwt
from datetime import datetime,timedelta
from passlib.context import CryptContext
from models import User
from database import sessionlocal,engine
from pydantic import BaseModel,EmailStr
# from fastapi.middleware.cors import CORSMiddlewareuser
from fastapi import  BackgroundTasks
from uuid import uuid4
from typing import Dict,Annotated
import models,auth,random 
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import secrets,hashlib
import pandas as pd
import io
from enum_ import UserType
import os
from dotenv import load_dotenv

load_dotenv()


EMAIL = os.getenv("EMAIL")

PASSWORD = os.getenv("PASSWORD")

SMTP_SERVER = os.getenv("SMTP_SERVER")

SMTP_PORT = os.getenv("SMTP_PORT")

EMADATABASE_FILEIL = os.getenv("DATABASE_FILE")


app=FastAPI()
app.include_router(auth.router)

models.Base.metadata.create_all(bind=engine)

oauth2_scheme=OAuth2PasswordBearer(tokenUrl="token")


#dependency
def get_db():
    db=sessionlocal()
    try:
        yield db
    except:
        db.close()
        raise
    finally:
        db.rollback()

db_dependency=Annotated [Session,Depends(get_db) ]


pwd_context= CryptContext(schemes=["bcrypt"],deprecated="auto")



# ACCESS_TOKEN_EXPIRE_MINUTES=30


class UserCreate(BaseModel):
    name: str
    password :str
    email:EmailStr
    user_role:UserType
    
  

def generate_otp():
    return  ''.join(str(random.randint(0, 9)) for _ in range(6))


  
def get_user_by_username(db:Session,username:str):
    return db.query(User).filter(User.name==username).first()

# @app.post("/email",response_model=None)
def send_email(email,otp):
    
    
    message = MIMEMultipart()
    message['From'] = EMAIL
    message['To'] = email
    message['Subject'] = 'Your One-Time Password'

    body = f'Your OTP is: {otp}'
    message.attach(MIMEText(body, 'plain'))

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(EMAIL, PASSWORD)
        server.sendmail(EMAIL, email, message.as_string())
    return True
        
def password_rest_email(email,otp):
    
    
    message = MIMEMultipart()
    message['From'] = EMAIL
    message['To'] = email
    message['Subject'] = 'Your One-Time Password'

    body = f'Your link to reset your password is: {otp}'
    message.attach(MIMEText(body, 'plain'))

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(EMAIL, PASSWORD)
        server.sendmail(EMAIL, email, message.as_string())
    return True
        


def create_user(db: Session, user: UserCreate):
    hashed_password = pwd_context.hash(user.password)
    random_number = generate_otp()
    send_email(user.email, random_number)
    
    db_user = User(
        name=user.name,
        hashed_password=hashed_password,
        email=user.email,
        OTP=random_number,
        user_role=user.user_role
    )
    
    db.add(db_user)
    db.commit()  # Commit after adding the user
    return "User registered successfully"

def Verify_otp(email,otp, db : Session=Depends(get_db)):
    mailid=db.query(User.email).all()
    print(mailid)
    for email in mailid :
        if otp == User.OTP:

            return {"message": "OTP verified successfully"}
    else:
        return False

def generate_token():
    return secrets.token_urlsafe(32)
    





@app.post("/createuser")
def createuser(user:UserCreate,db : Session=Depends(get_db)):
    
    db_user=get_user_by_username(db,username=user.name)
    if db_user:
        raise HTTPException(status_code=400,detail="User already exits")
    db.commit()
    return create_user(db=db,user=user)

@app.get("/verify_otp")
async def verify_otp(mailid:EmailStr,otp:str,db : Session=Depends(get_db)):

    saved_otp = db.query(User).filter(User.email==mailid).filter(User.OTP).first()
    
    otp1 = saved_otp.OTP

    if otp1 == otp:
        db.query(User).filter(User.email==mailid).update({"VERIFIED":True})
        db.commit()
        return {"message": "OTP verified successfully"}
    else:
        raise HTTPException(status_code=400, detail="Invalid OTP/EMAIL")
    


# Endpoint to request password reset
@app.post("/reset_password")
async def request_password_reset(email: str,db : Session=Depends(get_db)):
    # Check if user exists with the provided email
    user = db.query(User).filter(User.email== email).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    # Generate a token and send reset email
    token = generate_token()
    password_rest_email(email, token)

    # Simulate storing the token (in a real app, store it in the database)
    print(token, 2222222222222222222)
    
    
    expire= datetime.now() + timedelta(hours=1)
    print(expire,333333333333333333333333333335454)
    db.query(User).filter(User.email==email).update({"password_reset_token":token})
    db.query(User).filter(User.email==email).update({"password_reset_expiration":expire})
    db.commit()



    return {"message": "Password reset email sent"}

# Endpoint to reset password
@app.post("/reset_password/{token}")
async def reset_password(token: str, new_password: str ,db : Session=Depends(get_db)):
    # Check if token is valid and not expired
    user = db.query(User).filter(User.password_reset_token== token).first()
    if not user or user.password_reset_expiration < str(datetime.now()):
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    print(5645564131321)

    # Update the user's password
    db.query(User).filter(User.password_reset_token==token).update({"hashed_password":pwd_context.hash(new_password)})

    


    # Remove password reset token
    db.query(User).filter(User.password_reset_token==token).update({"password_reset_token":None})
    db.query(User).filter(User.password_reset_token==token).update({"password_reset_expiration":None})

    db.commit()

    return {"message": "Password reset successfully"}



