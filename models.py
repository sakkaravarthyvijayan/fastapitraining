from sqlalchemy import Boolean,INTEGER, Column,String,Date,ForeignKey,ARRAY,Enum
from database import Base,engine
from typing import List
from passlib.context import CryptContext 
from enum_ import UserType
# importing pass lib for hashing the password


class User(Base):
    __tablename__="Userinfo"

    id=Column(INTEGER,primary_key=True,index=True)
    name=Column(String(500))
    hashed_password=Column(String(500))
    email=Column(String(500),unique=True)
    VERIFIED=Column(Boolean,default=False)
    OTP=Column(String(500))
    password_reset_token=Column(String(500))
    password_reset_expiration=Column(String(500))
    access_token=Column(String(5000))
    access_token_expire=Column(String(500))
    user_role=Column(Enum(UserType))
    access_token_verified=Column(Boolean,default=False)

    

    
User.metadata.create_all(bind=engine)