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
    role=Column(Enum(UserType))
    OTP=Column(String(500))
    password_reset_token=Column(String(500))
    password_reset_expiration=Column(String(500))
    OTP_verified=Column(Boolean,default=False)
    VERIFIED=Column(Boolean,default=False)
    BLOCKED=Column(Boolean,default=False)



class UserDetails(Base):
    __tablename__ = 'user_details'
    id = Column(INTEGER, primary_key=True, index=True, autoincrement=True)
    user_id=Column(INTEGER, ForeignKey('Userinfo.id'))
    session_ip = Column(String(5000)) 
    session_token=Column(String(5000))
    access_token=Column(String(5000))
    access_token_verified=Column(Boolean,default=False)
    session_token_verified=Column(Boolean,default=False)
    expire=Column(String(500))



    

    
Base.metadata.create_all(bind=engine)