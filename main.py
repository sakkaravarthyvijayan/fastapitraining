import fastapi
from fastapi import FastAPI, Depends, HTTPException, status, BackgroundTasks
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from datetime import datetime, timedelta
from passlib.context import CryptContext
from models import *
from database import sessionlocal, engine
from pydantic import BaseModel, EmailStr
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import secrets, random, os
from dotenv import load_dotenv
import models,random,auth

from middleware import *
from typing import Annotated
from enum_ import UserType


# from middleware import *
from typing import Annotated
from enum_ import UserType


# Load environment variables
load_dotenv()

EMAIL = os.getenv("EMAIL")
PASSWORD = os.getenv("PASSWORD")
SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = os.getenv("SMTP_PORT")
DATABASE_FILE = os.getenv("DATABASE_FILE")

# Initialize FastAPI app
app = FastAPI()

# Middleware
app.add_middleware(AuthMiddleware)
app.add_middleware(RoleBasedAuthMiddleware)
app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(GlobalErrorHandlingMiddleware)


app.include_router(auth.router)


# Database initialization
models.Base.metadata.create_all(bind=engine)

# Security dependencies
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Cryptography context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Dependency: Get DB session
def get_db():
    """
    Dependency to create and return a database session.
    Ensures the session is properly closed after use.
    """
    db = sessionlocal()
    try:
        yield db
    except:
        db.close()
        raise
    finally:
        db.rollback()


class UserCreate(BaseModel):
    name: str
    password :str
    email:EmailStr
    user_role:UserType

db_dependency = Annotated[Session, Depends(get_db)]

# Helper function to generate OTP
def generate_otp():
    """
    Generate a 6-digit OTP (One-Time Password) as a string.
    """
    return ''.join(str(random.randint(0, 9)) for _ in range(6))

# Function to get user by username
def get_user_by_username(db: Session, username: str):
    """
    Retrieve a user from the database by their username.
    
    Args:
        db: The database session.
        username: The username to search for.
    
    Returns:
        The user object if found, otherwise None.
    """
    return db.query(User).filter(User.name == username).first()

# Function to send OTP email
def send_email(email, otp):
    """
    Send an OTP (One-Time Password) to the user's email address.
    
    Args:
        email: The recipient's email address.
        otp: The OTP to send.
    
    Returns:
        True if the email is sent successfully.
    """
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

# Function to send password reset email
def password_rest_email(email, otp):
    """
    Send a password reset link (or token) to the user's email address.
    
    Args:
        email: The recipient's email address.
        otp: The password reset token to send.
    
    Returns:
        True if the email is sent successfully.
    """
    message = MIMEMultipart()
    message['From'] = EMAIL
    message['To'] = email
    message['Subject'] = 'Password Reset Link'

    body = f'Your link to reset your password is: {otp}'
    message.attach(MIMEText(body, 'plain'))

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(EMAIL, PASSWORD)
        server.sendmail(EMAIL, email, message.as_string())
    return True
# Function to create a user
def create_user(db: Session, user: UserCreate):
    """
    Create a new user in the database, send an OTP for verification, and hash the user's password.
    
    Args:
        db: The database session.
        user: The user data to create.
    
    Returns:
        A success message indicating that the user was registered successfully.
    """
    # Check if the email already exists
    if db.query(User).filter(User.email == user.email).first():
        return "Email already exists"

    # Hash the user's password
    hashed_password = pwd_context.hash(user.password)

    # Generate an OTP and send it via email
    random_number = generate_otp()
    send_email(user.email, random_number)

    # Create a new User instance
    db_user = User(
        name=user.name,
        email=user.email,
        role=user.user_role,
        OTP=random_number,
        hashed_password=hashed_password
    )

  

    # Add the user to the session
    db.add(db_user)
    if db_user.role==UserType.ADMIN:
        db_user.VERIFIED=True
        
    db.commit()  # Commit the transaction to create the user first
    
    return "User registered successfully"


def generate_token():
    return secrets.token_urlsafe(32)


# User creation
@app.post("/createuser", status_code=status.HTTP_201_CREATED)
def create_user_route(user: UserCreate, db: Session = Depends(get_db)):
    """
    Create a new user in the database and send an OTP to the user's email for verification.
    
    Args:
        user: The user data to create.
    
    Returns:
        A success message indicating that the user was created.
    """

    hashed_password = pwd_context.hash(user.password)
    random_number = generate_otp()
    send_email(user.email, random_number)

    db_user = get_user_by_username(db, username=user.name)
    if db_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists")
    
    create_user(db=db, user=user)
    return JSONResponse(status_code=status.HTTP_201_CREATED, content={"message": "User created successfully"})

    

# OTP verification
@app.get("/verify_otp", status_code=status.HTTP_200_OK)
async def verify_otp(mailid: EmailStr, otp: str, db: Session = Depends(get_db)):
    """
    Verify the OTP (One-Time Password) sent to the user's email.

    Args:
        mailid: The user's email address.
        otp: The OTP provided by the user.
    
    Returns:
        A success message if the OTP is verified, otherwise raises an error.
    """
    # Query for the user details based on the email
    user_details = db.query(User).filter(User.email == mailid).first()
    
    if not user_details:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Email not found")
    
    # Check if the provided OTP matches the saved OTP
    if user_details.OTP == otp:
        # Update the OTP_verified status
        user_details.OTP_verified = True
        db.commit()
        return JSONResponse(status_code=status.HTTP_200_OK, content={"message": "OTP verified successfully"})
    
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid OTP")


# Password reset request
@app.post("/reset_password", status_code=status.HTTP_200_OK)
async def request_password_reset(email: str, db: Session = Depends(get_db)):
    """
    Request a password reset by sending a reset token to the user's email.
    
    Args:
        email: The user's email address.
    
    Returns:
        A success message indicating that the password reset email has been sent.
    """
    # Query for the user details based on the email
    user_details = db.query(User).filter(User.email == email).first()
    
    if not user_details:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Email not found")

    # Check if there is already a reset token
    if user_details.password_reset_token:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password reset request already pending")

    # Generate a reset token and send the email
    token = generate_token()
    password_rest_email(email, token)

    # Set expiration time for the token
    expire = datetime.now() + timedelta(hours=1)

    # Update the user's password reset token and expiration in the UserDetails table
    user_details.password_reset_token = token
    user_details.password_reset_expiration = expire
    db.commit()

    return JSONResponse(status_code=status.HTTP_200_OK, content={"message": "Password reset email sent"})


@app.post("/reset_password/{token}", status_code=status.HTTP_200_OK)
async def reset_password(token: str, new_password: str, db: Session = Depends(get_db)):
    """
    Reset the user's password using a valid token.

    Args:
        token: The password reset token.
        new_password: The new password to set.
    
    Returns:
        A success message if the password is reset, otherwise raises an error.
    """
    # Retrieve user details using the token
    user_details = db.query(User).filter(User.password_reset_token == token).first()
    
    # Check if user details were found and verify token expiration
    if not user_details or user_details.password_reset_expiration < datetime.now():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired token")

    # Update the password in User and clear the reset token and expiration
    hashed_password = pwd_context.hash(new_password)
    
    user_details.hashed_password=hashed_password
    
    user_details.password_reset_token = None
    user_details.password_reset_expiration = None
    db.commit()

    return JSONResponse(status_code=status.HTTP_200_OK, content={"message": "Password reset successfully"})
