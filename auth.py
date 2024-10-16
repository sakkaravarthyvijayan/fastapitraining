from datetime import timedelta, datetime
from typing import Annotated,Optional,List
from fastapi import APIRouter, Depends, HTTPException, status,Form
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from database import sessionlocal
from models import User
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import jwt, JWTError
from pydantic import BaseModel, EmailStr
from enum import Enum
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import os
import traceback
from dotenv import load_dotenv
load_dotenv()

# Set up logging
logging.basicConfig(level=logging.INFO)

# Create router and define constants
router = APIRouter(prefix="/auth", tags=["authentication"])

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # Correct format

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")



EMAIL = os.getenv("EMAIL")

PASSWORD = os.getenv("PASSWORD")

SMTP_SERVER = os.getenv("SMTP_SERVER")

SMTP_PORT = os.getenv("SMTP_PORT")

EMADATABASE_FILEIL = os.getenv("DATABASE_FILE")

# UserType Enum for role-based access control
class UserType(str, Enum):
    ADMIN = "admin"
    MID_USER = "mid_user"
    END_USER = "end_user"

# Models
class Token(BaseModel):
    access_token: str
    token_type: str
    role: str

# Database Dependency
def get_db():
    db = sessionlocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]


# Email sending function
def send_email(email: str, subject: str, body: str):
    message = MIMEMultipart()
    message['From'] = EMAIL
    message['To'] = email
    message['Subject'] = subject
    message.attach(MIMEText(body, 'plain'))

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(EMAIL, PASSWORD)
        server.sendmail(EMAIL, email, message.as_string())


# Authenticate user function
def authenticate_user(username: str, password: str, db: db_dependency):
    user = db.query(User).filter(User.name == username).filter(User.VERIFIED == True).first()
    if not user or not pwd_context.verify(password, user.hashed_password):
        return False
    return user

# Token creation function
def create_access_token(username: str, mail_id: EmailStr, user_role: UserType, expires_delta: timedelta, verified: bool):
    to_encode = {
        "sub": username,
        "id": mail_id,
        "role": user_role.value,
        "verified": verified  # Store the role as a string
    }
    expires = datetime.now() + expires_delta
    to_encode.update({"exp": expires})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Get current user based on JWT token
def get_current_user(token: Annotated[str, Depends(oauth2_scheme)], db: db_dependency):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role")
        verified: bool = payload.get("verified")
        if username is None or role is None or verified is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials"
            )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )

    user = db.query(User).filter(User.name == username).first()
    if user is None or user.access_token is None:  # Check if the token is invalidated
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or token invalidated"
        )
    return {"name":user.name,"role":role}




# Role-based access control decorator
def require_role(*required_roles: UserType):
    def role_checker(current_user: Annotated[User, Depends(get_current_user)]):
        # Log the current user's role for debugging
        logging.info(f"Current User Role: {current_user['role']}")

        # Check if the user's role is a string and convert it to UserType Enum
        current_user_role = UserType(current_user['role'])

        # Compare the current user's role with the required roles
        if current_user_role not in required_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access forbidden: One of the following roles is required: {', '.join(role.value for role in required_roles)}"
            )
        return current_user
    return role_checker


# Combined Login and Authorization endpoint
@router.post("/token", response_model=Token)
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: db_dependency):
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )

    expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    expires = datetime.now() + expires_delta

    # Create access token
    token = create_access_token(user.name, user.email, user.user_role, expires_delta, user.access_token_verified)

    # Send email for verification if not admin
    if user.user_role.value!= UserType.ADMIN.value:
        db.query(User).filter(User.name == form_data.username).update({
            "access_token": token,
            "access_token_expire": expires,
               })
        db.commit()
        
        # send_email(EMAIL, "User Token Verification", f"User {user.name} needs token verification.")


    # Update user token if admin, and auto-verify their token
    if user.user_role.value == UserType.ADMIN.value:
        db.query(User).filter(User.name == form_data.username).update({
            "access_token": token,
            "access_token_expire": expires,
            "access_token_verified": True  # Auto-verify admin tokens
        })
        db.commit()

    return {"access_token": token, "token_type": "bearer", "role": user.user_role.value}


# Block user API (Admin only)
@router.post("/block-user")
async def block_user(username: str, db: db_dependency, current_user: Annotated[User, Depends(require_role(UserType.ADMIN))]):
    user_to_block = db.query(User).filter(User.name == username).first()
    if not user_to_block:
        raise HTTPException(status_code=404, detail="User not found")
    
    db.query(User).filter(User.name == username).update({"access_token_verified": False})
    db.commit()
    
    return {"message": f"User '{username}' has been blocked successfully"}

# Unblock user API (Admin only)
@router.post("/unblock-user")
async def unblock_user(username: str, db: db_dependency, current_user: Annotated[User, Depends(require_role(UserType.ADMIN))]):
    user_to_unblock = db.query(User).filter(User.name == username).first()
    if not user_to_unblock:
        raise HTTPException(status_code=404, detail="User not found")
    
    db.query(User).filter(User.name == username).update({"access_token_verified": True})
    db.commit()
    
    return {"message": f"User '{username}' has been unblocked successfully"}

@router.post("/admin-only")
async def admin_only_route(
    db: db_dependency,
    current_user: Annotated[User, Depends(require_role(UserType.ADMIN))],
    action: str = Form(..., description="Action to perform: view, edit, or delete", choices=["view", "edit", "delete"]),
    username: Optional[str] = Form(None),
    new_name: str = Form("", description="New name for the user"),
    new_email: str = Form("", description="New email for the user"),
    new_role: str = Form("", description="New role for the user"),
    verify:bool= Form( description="verify for the user")
):
    # View all users if no specific username is provided and action is 'view'
    if username is None and action == "view":
        users = db.query(User).all()
        user_info = [
            {
                "name": user.name,
                "email": user.email,
                "role": user.user_role,
                "token": user.access_token,
                "verified":user.access_token_verified
            }
            for user in users
        ]
        return {
            "message": f"Hello, Admin {current_user['name']}. You are authorized to access this route.",
            "users": user_info
        }
    
    if username is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username is required for edit and delete actions")

    # Fetch specific user if username is provided
    user_to_show = db.query(User).filter(User.name == username).first()
    if not user_to_show:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    if action == "view":
        # Return the selected user's information
        return {
            "message": f"Hello, Admin {current_user['name']}. You are authorized to access this route.",
            "content": f"user: {user_to_show.name} email: {user_to_show.email} role: {user_to_show.user_role} token: {user_to_show.access_token},verified:{user_to_show.access_token_verified}"
        }
    
    elif action == "edit":
        # Edit any provided field of the user
        if new_name:
            user_to_show.name = new_name
        if new_email:
            user_to_show.email = new_email
        if new_role:
            user_to_show.user_role = new_role
        if verify:
            user_to_show.access_token_verified=verify
        db.commit()  # Save the changes
        return {
            "message": f"User {username}'s information has been updated.",
            "content": f"user: {user_to_show.name} email: {user_to_show.email} role: {user_to_show.user_role} token: {user_to_show.access_token},verified:{user_to_show.access_token_verified}"
        }
    
    elif action == "delete":
        # Delete the user
        db.delete(user_to_show)
        db.commit()  # Commit the deletion
        return {
            "message": f"User {username} has been deleted successfully."
        }

    return {"error": "Invalid action"}


from fastapi import Form, HTTPException, status
from typing import Optional
@router.post("/admin_mid-user")
async def admin_mid_user(
    db: db_dependency,
    current_user: Annotated[User, Depends(require_role(UserType.ADMIN, UserType.MID_USER))],
    action: str = Form(..., description="Action to perform: view, edit, or delete", choices=["view", "edit", "delete"]),
    username: Optional[str] = Form(None),
    new_name: str = Form("", description="New name for the user"),
    new_email: str = Form("", description="New email for the user"),
    new_role: str = Form("", description="New role for the user")
):  
    if username is None:
        # Fetch all users
        if current_user['role'] == UserType.ADMIN:
            users = db.query(User).all()
        elif current_user['role'] == UserType.MID_USER:
            users = db.query(User).filter(User.user_role.in_([UserType.MID_USER, UserType.END_USER])).all()
        
        user_info = [
            {
                "name": user.name,
                "email": user.email,
                "role": user.user_role,
                "token": user.access_token,
                "verified": user.access_token_verified
            }
            for user in users
        ]
        
        return {
            "message": f"Hello, {current_user['name']}! You are authorized to access this route.",
            "users": user_info
        }
    
    # Fetch specific user if username is provided
    user_to_show = db.query(User).filter(User.name == username).first()
    if not user_to_show:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Admin logic: Can perform any action on any user
    if current_user['role'] == UserType.ADMIN:
        if action == "view":
            return {
                "message": f"Hello, Admin {current_user['name']}. You are authorized to view this user.",
                "content": f"user: {user_to_show.name}, email: {user_to_show.email}, role: {user_to_show.user_role}, token: {user_to_show.access_token},verified: {user_to_show.access_token_verified}"
            }
        elif action == "edit":
            if new_name:
                user_to_show.name = new_name
            if new_email:
                user_to_show.email = new_email
            if new_role:
                user_to_show.user_role = new_role
            db.commit()
            return {
                "message": f"User {username}'s information has been updated.",
                "content": f"user: {user_to_show.name}, email: {user_to_show.email}, role: {user_to_show.user_role}, token: {user_to_show.access_token},verified: {user_to_show.access_token_verified}"
            }
        elif action == "delete":
            db.delete(user_to_show)
            db.commit()
            return {
                "message": f"User {username} has been deleted successfully."
            }
    
    # MID_USER logic: Can only modify or delete END_USERs, and can view MID_USER and END_USER
    if current_user['role'] == UserType.MID_USER:
        if user_to_show.user_role not in [UserType.MID_USER, UserType.END_USER]:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You are not authorized to view this user.")
        
        if action == "view":
            return {
                "message": f"Hello, {current_user['name']}. You are authorized to view this user.",
                "content": f"user: {user_to_show.name}, email: {user_to_show.email}, role: {user_to_show.user_role}"
            }
        elif action == "edit":
            if user_to_show.user_role != UserType.END_USER:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You are not authorized to edit this user.")
            
            if new_name:
                user_to_show.name = new_name
            if new_email:
                user_to_show.email = new_email
            if new_role:
                user_to_show.user_role = new_role
            db.commit()
            return {
                "message": f"User {username}'s information has been updated.",
                "content": f"user: {user_to_show.name}, email: {user_to_show.email}, role: {user_to_show.user_role}, "
            }
        elif action == "delete":
            if user_to_show.user_role != UserType.END_USER:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You are not authorized to delete this user.")
            
            db.delete(user_to_show)
            db.commit()
            return {
                "message": f"User {username} has been deleted successfully."
            }

    return {"error": "Invalid action or permission denied"}


# @router.post("/protected-route")
# async def protected_route(
#     db: db_dependency,
#     current_user: Annotated[User, Depends(get_current_user)],
#     action: str = Form(..., description="Action to perform: view, edit, or delete", choices=["view", "edit", "delete"]),
#     new_name: str = Form("", description="New name for the user"),
#     new_email: str = Form("", description="New email for the user"),
#     new_role: str = Form("", description="New role for the user")
# ):
#     # Fetch the current user from the database
#     user_to_show = db.query(User).filter(User.id == current_user.id).first()
#     if not user_to_show:
#         raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

#     if action == "view":
#         return {
#             "message": f"Hello, {current_user['name']}({current_user['role']}). You are authorized to view your information.",
#             "content": {
#                 "user": user_to_show.name,
#                 "email": user_to_show.email,
#                 "role": user_to_show.user_role,
#                 "token": user_to_show.access_token,
#                 "verified":user_to_show.access_token_verified
#             }
#         }
    
#     elif action == "edit":
#         # Edit any provided field of the current user
#         if new_name:
#             user_to_show.name = new_name
#         if new_email:
#             user_to_show.email = new_email
#         if new_role:
#             user_to_show.user_role = new_role
#         db.commit()  # Save the changes
#         return {
#             "message": "Your information has been updated.",
#             "content": {
#                 "user": user_to_show.name,
#                 "email": user_to_show.email,
#                 "role": user_to_show.user_role,
#                 "token": user_to_show.access_token,
#                 "verified":user_to_show.access_token_verified


#             }
#         }
    
#     elif action == "delete":
#         # Delete the current user
#         db.delete(user_to_show)
#         db.commit()  # Commit the deletion
#         return {
#             "message": "Your account has been deleted successfully."
#         }

#     return {"error": "Invalid action"}

@router.post("/protected-route")
async def protected_route(
    db: db_dependency,
    current_user: Annotated[User, Depends(get_current_user)],
    username: Optional[str] = Form(None, description="Username to search for"),
    role: Optional[UserType] = Form(None, description="Role to search for"),
    page: int = Form(1, description="Page number for pagination"),
    limit: int = Form(10, description="Number of users to return per page"),
):
    query = db.query(User)

    if username:
        query = query.filter(User.name.ilike(f"%{username}%"))
    if role:
        query = query.filter(User.user_role == role)

    # Apply pagination
    offset = (page - 1) * limit
    users = query.offset(offset).limit(limit).all()

    total_users = query.count()  # Total number of users matching the criteria

    if not users:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No users found matching the search criteria."
        )

    user_info = [
        {
            "name": user.name,
            "email": user.email,
            "role": user.user_role,
        }
        for user in users
    ]

    return {
        "total_users": total_users,
        "page": page,
        "limit": limit,
        "users": user_info,
    }




# Logout endpoint (protected)
@router.post("/logout")
async def logout(current_user: Annotated[User, Depends(get_current_user)],db: db_dependency):
    # Invalidate the token by removing it from the database
    db.query(User).filter(User.name == current_user['name']).update({
        "access_token": None,
        "access_token_expire": None,
        "access_token_verified":False
    })
    db.commit()

    return {"detail": "Logged out successfully"}










