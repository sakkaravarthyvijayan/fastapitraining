from datetime import timedelta, datetime
from typing import Annotated,Optional,List,Tuple
from fastapi import APIRouter, Depends, HTTPException, status,Form
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from database import sessionlocal
from models import *
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import jwt, JWTError
from pydantic import BaseModel, EmailStr
from enum import Enum
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import socket
import uuid
import hashlib

import csv
from io import StringIO
from fastapi.responses import StreamingResponse

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
DATE_FORMAT = '%Y-%m-%d %H:%M:%S.%f'  # Format for converting the expire string to datetime


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


class Access(str,Enum):
    verified="verfied"
    access_token="access_token"
    session_token="Session_token"
    block="block"

class Verify(str,Enum):
    verified="verfied"
    block="block"
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
    # Query for user details with verification and block status
    user = (
        db.query(User)
        .filter(User.name == username)
        .filter(User.VERIFIED == True)  # Ensure user is verified
        .filter(User.BLOCKED == False)  # Ensure user is not blocked
        .first()
    )
    
    # Check if user exists and verify password
    if user is None or not pwd_context.verify(password, user.hashed_password):
        return False

    return user


def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)], 
    db: Session = Depends(get_db)
):
    try:
        # Decode the JWT token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role")
        verified: bool = payload.get("verified")
        blocked: bool = payload.get("block")
        token_expiry: int = payload.get("exp")  # Get the token's expiration timestamp

        if username is None or role is None or verified is None or blocked:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials"
            )

        # Check if the token has expired
        current_time = datetime.utcnow()
        token_expiry_time = datetime.utcfromtimestamp(token_expiry)

        if current_time > token_expiry_time:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired"
            )

    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )

    # Fetch user details from the database
    user = db.query(User).filter(User.name == username).first()
    
    if user is None:  # Check if the user exists
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )

    # Return the user information as needed
    return {"name": user.name, "role": role, "verified": verified, "blocked": blocked}


# Role-based access control decorator
def require_role(*required_roles: UserType):
    def role_checker(current_user: Annotated[User, Depends(get_current_user)]):
        # Log the current user's role for debugging
        logging.info(f"Current User Role: {current_user['role']}")

        # Check if the user's role is a string and convert it to UserType Enum
        current_role = UserType(current_user['role'])

        # Compare the current user's role with the required roles
        if current_role not in required_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access forbidden: One of the following roles is required: {', '.join(role.value for role in required_roles)}"
            )
        return current_user
    return role_checker

# Helper function to get local IP address
def get_local_ip_address():
    """Retrieve the local IP address."""
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    return local_ip, hostname

# Helper function to create session ID
def create_session_id(username: str, email: EmailStr, role: str) -> Tuple[str, Tuple[str, str]]:
    """Create a unique session ID based on the system IP address and username."""
    local_ip = get_local_ip_address()  # Assume this returns (ip, some_other_value)
    unique_string = f"{local_ip[1]}-{username}--{email}--{role}--{str(uuid.uuid4())}"
    session_id = hashlib.sha256(unique_string.encode()).hexdigest()  # Hash the string to create a session ID
    return session_id, local_ip

# Function to create access token
def create_access_token(username: str, mail_id: EmailStr, role: str, expires_delta: timedelta, verified: bool, blocked: bool) -> Tuple[str, datetime]:
    """Create an access token."""
    to_encode = {
        "sub": username,
        "id": mail_id,
        "role": role,
        "verified": verified,
        "blocked": blocked
    }
    expires = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expires})
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return token, expires

def enforce_max_tokens(user_id: int, db: Session, username: str, mail_id: EmailStr, role: str, verified: bool, blocked: bool, expires_delta: timedelta) -> Tuple[str, str]:
    """Enforce a maximum of 5 tokens per user, deleting older ones if necessary."""
    
    # Generate a new token
    new_token, new_token_expiry = create_access_token(
        username=username,
        mail_id=mail_id,
        role=role,
        expires_delta=expires_delta,
        verified=verified,
        blocked=blocked
    )
    
    # Create a session ID
    session_id, local_ip = create_session_id(username, mail_id, role)

    # Fetch user's token details
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return "User not found.", None

    # Fetch all active tokens for the user, sorted by expire date
    active_tokens = db.query(UserDetails).filter(UserDetails.user_id == user_id).order_by(UserDetails.expire).all()

    # Remove oldest tokens if there are more than 5
    if len(active_tokens) >= 5:
        # Calculate the number of tokens to delete (leave only 4)
        tokens_to_delete = active_tokens[:len(active_tokens) - 4]
        
        # Delete the old tokens
        for token in tokens_to_delete:
            db.delete(token)
        db.commit()

        token_message = f"{len(tokens_to_delete)} old token(s) deleted, new token added."
    else:
        token_message = "New token added."

    # Add the new token
    token_details = UserDetails(
        user_id=user_id,
        access_token=new_token,
        expire=new_token_expiry,
        access_token_verified=(user.role.value == UserType.ADMIN),
        session_token_verified=(user.role.value == UserType.ADMIN),
        session_token=session_id,
        session_ip=local_ip[0]
    )
    db.add(token_details)
    db.commit()

    return token_message, new_token


# Route for user login and token creation
@router.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Session = Depends(get_db)
):
    """
    User login route for generating an access token.

    Args:
        form_data (OAuth2PasswordRequestForm): Login form with username and password.
        db (Session): Database session for querying user information.

    Returns:
        JSONResponse: A response containing the generated access token, role, and related information.
    
    Raises:
        HTTPException: If user authentication fails or token creation is unsuccessful.
    """
    # Authenticate user
    user = authenticate_user(form_data.username, form_data.password, db)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )

    expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    # Enforce max 5 tokens per user
    token_message, new_token = enforce_max_tokens(
        user_id=user.id,
        db=db,
        username=user.name,
        mail_id=user.email,
        role=user.role.value,
        verified=user.VERIFIED,
        blocked=user.BLOCKED,
        expires_delta=expires_delta
    )

    # Ensure new_token is defined before proceeding
    if not new_token:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create a new token."
        )

    # Update VERIFIED status in the User table if the role is ADMIN
    if user.role == UserType.ADMIN:
        user.VERIFIED = True
    # send_email(EMAIL, "User Token Verification", f"User {user.name} needs token verification.")


    db.commit()

    # Return the token and messages
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "access_token": new_token,
            "token_type": "bearer",
            "role": user.role.value,
            "token_message": token_message
        }
    )


# Route to verify or block a user
@router.post("/verify-user")
async def block_or_verify_user(
    db: db_dependency,
    current_user: Annotated[User, Depends(require_role(UserType.ADMIN))],
    username: str = Form(..., description="Username to verify/block"),
    verify: Optional[Verify] = Form(..., description="Action to perform: verify/block"),
    access: Optional[bool] = Form(..., description="True to verify/unblock, False to block"),
):
    """
    Admin route to verify or block a user based on the username and access level.

    Args:
        db (Session): Database session for querying and updating user information.
        current_user (User): The current authenticated admin user.
        username (str): The username to verify or block.
        verify (Verify): Action to either verify or block the user.
        access (bool): True for verification, False for blocking.

    Returns:
        JSONResponse: Success message based on action taken, or error message.
    
    Raises:
        HTTPException: If user is not found or invalid action is provided.
    """
    user_to_access = db.query(User).filter(User.name == username).first()

    if not user_to_access:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"error": "User not found"}
        )

    if verify is None:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": "Verification action (verify/block) is required"}
        )

    if verify == Verify.verified:
        if access:
            user_to_access.VERIFIED = True
            db.commit()
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content={"message": f"User '{username}' has been verified successfully"}
            )
        else:
            user_to_access.VERIFIED = False
            db.commit()
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content={"message": f"User '{username}' has been blocked successfully"}
            )

    if verify == Verify.block:
        if access:
            user_to_access.VERIFIED = True
            db.commit()
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content={"message": f"User '{username}' has been unblocked successfully"}
            )
        else:
            user_to_access.VERIFIED = False
            db.commit()
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content={"message": f"User '{username}' has been blocked successfully"}
            )

    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"error": "Invalid verification action"}
    )


# Block user API (Admin only)
@router.post("/block-user")
async def Block_User(
    db: db_dependency,
    current_user: Annotated[User, Depends(require_role(UserType.ADMIN))],
    username: str,
    access: Optional[Access] = Form(None, description="Access type to block (access_token or session_token)")
):
    """
    Admin route to block a user by username and optionally block access or session tokens.

    Args:
        db (Session): Database session for querying user and token information.
        current_user (User): The current authenticated admin user.
        username (str): The username of the user to block.
        access (Access): Optional parameter to specify the type of access to block (access_token or session_token).

    Returns:
        JSONResponse: Success message indicating user has been blocked, or an error message.
    
    Raises:
        HTTPException: If user or session details are not found.
    """
    user_to_block = db.query(User).filter(User.name == username).first()

    if not user_to_block:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"error": "User not found"}
        )

    Access_details = db.query(UserDetails).filter(UserDetails.user_id == user_to_block.id).first()

    if not Access_details:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"error": "User token/session details not found"}
        )

    if access == Access.access_token:
        Access_details.access_token_verified = False
        db.add(Access_details)
        db.commit()

    elif access == Access.session_token:
        Access_details.session_token_verified = False
        db.add(Access_details)
        db.commit()

    elif access is None:
        Access_details.access_token_verified = False
        Access_details.session_token_verified = False
        db.add(Access_details)
        db.commit()

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"message": f"User '{username}' has been blocked successfully"}
    )


# Unblock user API (Admin only)
@router.post("/unblock-user")
async def Un_Block_User(
    db: db_dependency,
    current_user: Annotated[User, Depends(require_role(UserType.ADMIN))],
    username: str,
    access: Optional[Access] = Form(None, description="Access type to unblock (access_token or session_token)")
):
    """
    Admin route to unblock a user by username and optionally unblock access or session tokens.

    Args:
        db (Session): Database session for querying user and token information.
        current_user (User): The current authenticated admin user.
        username (str): The username of the user to unblock.
        access (Access): Optional parameter to specify the type of access to unblock (access_token or session_token).

    Returns:
        JSONResponse: Success message indicating user has been unblocked, or an error message.
    
    Raises:
        HTTPException: If user or session details are not found.
    """
    user_to_UN_block = db.query(User).filter(User.name == username).first()

    if not user_to_UN_block:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"error": "User not found"}
        )

    Access_details = db.query(UserDetails).filter(UserDetails.user_id == user_to_UN_block.id).first()

    if not Access_details:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"error": "User token/session details not found"}
        )

    if access == Access.access_token:
        Access_details.access_token_verified = True
        db.add(Access_details)
        db.commit()

    elif access == Access.session_token:
        Access_details.session_token_verified = True
        db.add(Access_details)
        db.commit()

    elif access is None:
        Access_details.access_token_verified = True
        Access_details.session_token_verified = True
        db.add(Access_details)
        db.commit()

    db.commit()

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"message": f"User '{username}' has been UN-blocked successfully"})




@router.post("/admin-only")
async def admin_only_route(
    db: db_dependency,
    current_user: Annotated[User, Depends(require_role(UserType.ADMIN))],
    action: str = Form(..., description="Action to perform: view, edit, or delete", choices=["view", "edit", "delete"]),
    username: Optional[str] = Form(None),
    new_name: str = Form("", description="New name for the user"),
    new_email: str = Form("", description="New email for the user"),
    new_role: str = Form("", description="New role for the user"),
    verify_token: bool = Form(False, description="Verify user token"),
    verify_session: bool = Form(False, description="Verify user session"),
    block: bool = Form(False, description="Block/unblock the user")
):
    """
    Admin-only route to perform user management actions such as view, edit, or delete.
    
    Args:
        db: Database dependency injection.
        current_user: The current authenticated user with ADMIN role.
        action: The action to perform - "view", "edit", or "delete".
        username: Optional username of the user being acted upon. Required for "edit" and "delete".
        new_name: New name to update for the user (for edit action).
        new_email: New email to update for the user (for edit action).
        new_role: New role to assign to the user (for edit action).
        verify_token: Boolean flag to verify the user’s token.
        verify_session: Boolean flag to verify the user’s session.
        block: Boolean flag to block/unblock the user.
    
    Returns:
        JSONResponse: A response message with the outcome of the action (view, edit, or delete).
    """
    # Check for action 'view' with no username provided
    if action == "view" and username is None:
        users = db.query(User).all()
        user_info = [
            {
                "name": user.name,
                "email": user.email,
                "role": user.role.value,
                "verified": user.VERIFIED,
                "blocked": user.BLOCKED
            }
            for user in users
        ]
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "message": f"Hello, Admin {current_user['name']}. You are authorized to access this route.",
                "users": user_info
            }
        )
    
    if username is None:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": "Username is required for edit and delete actions"}
        )

    # Fetch specific user
    user_to_show = db.query(User).filter(User.name == username).first()

    if not user_to_show:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"error": "User not found"}
        )

    # Handle actions: view, edit, delete
    if action == "view":
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "message": f"Hello, Admin {current_user['name']}. You are authorized to access this route.",
                "content": {
                    "user": user_to_show.name,
                    "email": user_to_show.email,
                    "role": user_to_show.role.value,
                    "verified": user_to_show.VERIFIED,
                    "blocked": user_to_show.BLOCKED
                }
            }
        )

    elif action == "edit":
        # Edit fields if provided
        if new_name:
            user_to_show.name = new_name
        if new_email:
            user_to_show.email = new_email
        if new_role and new_role.upper() in UserType.__members__:
            user_to_show.role = UserType[new_role.upper()]
        if verify_token is not None:
            user_to_show.VERIFIED = verify_token
        if verify_session is not None:
            user_to_show.VERIFIED = verify_session
        if block is not None:
            user_to_show.BLOCKED = block
        
        db.commit()  # Save the changes
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "message": f"User {username}'s information has been updated.",
                "content": {
                    "user": user_to_show.name,
                    "email": user_to_show.email,
                    "role": user_to_show.role.value,
                    "verified": user_to_show.VERIFIED,
                    "blocked": user_to_show.BLOCKED
                }
            }
        )

    elif action == "delete":
        db.delete(user_to_show)
        db.commit()  # Commit the deletion
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"message": f"User {username} has been deleted successfully."}
        )

    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"error": "Invalid action"}
    )


@router.post("/admin_mid-user")
async def admin_mid_user(
    db: db_dependency,
    current_user: Annotated[User, Depends(require_role(UserType.ADMIN, UserType.MID_USER))],
    action: str = Form(..., description="Action to perform: view, edit, or delete", choices=["view", "edit", "delete"]),
    username: Optional[str] = Form(None),
    new_name: str = Form("", description="New name for the user"),
    new_email: str = Form("", description="New email for the user"),
    new_role: str = Form("", description="New role for the user"),
    verify_token: bool = Form(description="verify for the user token"),
    verify_session: bool = Form(description="verify for the user session"),
    block: bool = Form(description="block/unblock the user")
):  
    """
    Route accessible to both ADMIN and MID_USER roles to perform user management actions.
    
    Args:
        db: Database dependency injection.
        current_user: The current authenticated user with either ADMIN or MID_USER role.
        action: The action to perform - "view", "edit", or "delete".
        username: Optional username of the user being acted upon. Required for "edit" and "delete".
        new_name: New name to update for the user (for edit action).
        new_email: New email to update for the user (for edit action).
        new_role: New role to assign to the user (for edit action).
        verify_token: Boolean flag to verify the user’s token.
        verify_session: Boolean flag to verify the user’s session.
        block: Boolean flag to block/unblock the user (only Admin can perform this action).
    
    Returns:
        JSONResponse: A response message with the outcome of the action (view, edit, or delete).
    """
    if username is None:
        # Fetch all users
        if current_user['role'] == UserType.ADMIN:
            users = db.query(User).all()
        elif current_user['role'] == UserType.MID_USER:
            users = db.query(User).filter(User.role.in_([UserType.MID_USER, UserType.END_USER])).all()
        
        user_info = [
            {
                "name": user.name,
                "email": user.email,
                "role": user.role.value,
                "verified": user.VERIFIED
            }
            for user in users
        ]
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "message": f"Hello, {current_user['name']}! You are authorized to access this route.",
                "users": user_info
            }
        )
    
    # Fetch specific user if username is provided
    user_to_show = db.query(User).filter(User.name == username).first()

    # Query for token and session details
    Access_details = db.query(UserDetails).filter(UserDetails.user_id == user_to_show.id).first()

    if not user_to_show:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"error": "User not found"}
        )

    # Admin logic: Can perform any action on any user
    if current_user['role'] == UserType.ADMIN:
        if action == "view":
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content={
                    "message": f"Hello, Admin {current_user['name']}. You are authorized to view this user.",
                    "content": {
                        "user": user_to_show.name,
                        "email": user_to_show.email,
                        "role": user_to_show.role.value,
                        "verified": user_to_show.VERIFIED
                    }
                }
            )
        elif action == "edit":
            if new_name:
                user_to_show.name = new_name
            if new_email:
                user_to_show.email = new_email
            if new_role:
                user_to_show.role = UserType[new_role.upper()]  # Assuming new_role is a string representing a valid UserType
            if verify_token :
                user_to_show.VERIFIED = verify_token
                verify_token = Access_details.access_token_verified = verify_token
                db.commit()
            if verify_session :
                user_to_show.VERIFIED = verify_session
                verify_session = Access_details.session_token_verified == verify_session
                db.commit()

            if block:
                user_to_show.BLOCKED = block
                verify_session = Access_details.session_token_verified == block
                verify_token = Access_details.access_token_verified = block
                db.commit()

            db.commit()
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content={
                    "message": f"User {username}'s information has been updated.",
                    "content": {
                        "user": user_to_show.name,
                        "email": user_to_show.email,
                        "role": user_to_show.role.value,
                        "verified": user_to_show.VERIFIED
                    }
                }
            )
        elif action == "delete":
            db.delete(user_to_show)
            db.commit()
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content={"message": f"User {username} has been deleted successfully."}
            )

    # MID_USER logic: Can only modify or delete END_USERs, and can view MID_USER and END_USER
    if current_user['role'] == UserType.MID_USER:
        if user_to_show.role not in [UserType.MID_USER, UserType.END_USER]:
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"error": "You are not authorized to perform this action on this user."}
            )
        if action == "view":
                return JSONResponse(
                    status_code=status.HTTP_200_OK,
                    content={
                        "message": f"Hello, Mid User {current_user['name']}. You are authorized to view this user.",
                        "content": {
                            "user": user_to_show.name,
                            "email": user_to_show.email,
                            "role": user_to_show.role.value,
                            "verified": user_to_show.VERIFIED
                        }
                    }
                )
        elif action == "edit":
            if user_to_show.role != UserType.END_USER:
                return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"error": "You are not authorized to perform this action on this user."}
            )
            if new_name:
                user_to_show.name = new_name
            if new_email:
                user_to_show.email = new_email
            if new_role:
                user_to_show.role = UserType[new_role.upper()]  # Assuming new_role is a string representing a valid UserType
            if verify_token :
                user_to_show.VERIFIED = verify_token
                verify_token = Access_details.access_token_verified = verify_token
                db.commit()
            if verify_session :
                user_to_show.VERIFIED = verify_session
                verify_session = Access_details.session_token_verified == verify_session
                db.commit()

            if block :
                return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"error": "You are not authorized to perform this action "}
                )
            db.commit()
            return JSONResponse(
                    status_code=status.HTTP_200_OK,
                    content={
                        "message": f"User {username}'s information has been updated.",
                        "content": {
                            "user": user_to_show.name,
                            "email": user_to_show.email,
                            "role": user_to_show.role.value,
                            "verified": user_to_show.access_token_verified
                        }
                    }
                )
        elif action == "delete":
            if user_to_show.role != UserType.END_USER:
                return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"error": "You are not authorized to perform this action on this user."}
            )
            db.delete(user_to_show)
            db.commit()
            return JSONResponse(
                    status_code=status.HTTP_200_OK,
                    content={"message": f"User {username} has been deleted successfully."}
                )
      
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"error": "Invalid action"}
    )

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
#                 "role": user_to_show.role,
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
#             user_to_show.role = new_role
#         db.commit()  # Save the changes
#         return {
#             "message": "Your information has been updated.",
#             "content": {
#                 "user": user_to_show.name,
#                 "email": user_to_show.email,
#                 "role": user_to_show.role,
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
        query = query.filter(User.role == role)

    # Apply pagination
    offset = (page - 1) * limit
    users = query.offset(offset).limit(limit).all()

    total_users = query.count()  # Total number of users matching the criteria

    if not users:
        return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"error": "No users found matching the search criteria."}
            )

    user_info = [
        {
            "name": user.name,
            "email": user.email,
            "role": user.role.value,
            "verified":user.VERIFIED,
            "block":user.BLOCKED,

        }
        for user in users
    ]
    return JSONResponse(content={
        "total_users": total_users,
        "page": page,
        "limit": limit,
        "users": user_info,
    })


@router.post("/logout")
async def logout(current_user: Annotated[User, Depends(get_current_user)], db: db_dependency):
    # Get the user's ID
    user = db.query(User).filter(User.name == current_user['name']).first()

    # Retrieve the current session's IP
    current_ip = get_local_ip_address()  # Call your function to get the current IP
    session_details = db.query(UserDetails).filter(
        UserDetails.user_id == user.id,
        UserDetails.session_ip == current_ip  # Match the session IP
    ).first()

    if not session_details:
        return JSONResponse(content={"detail": "No active session found for this IP."}, status_code=404)

    # Invalidate the session by setting its token and expiration to None
    session_details.session_token = None
    session_details.session_token_verified = False  # Mark as not verified

    # Commit changes to the database
    db.commit()

    return JSONResponse(content={"detail": f"{current_user['name']} logged out successfully from IP {current_ip}."})





# Log out from other devices
@router.post("/logout-other-devices")
async def logout_other_devices(user_id: int, current_session_token: str, 
    db: db_dependency,
    current_user: Annotated[User, Depends(require_role(UserType.ADMIN, UserType.MID_USER))]):
    sessions = db.query(UserDetails).filter(UserDetails.user_id == user_id).all()
    for session in sessions:
        if session.session_token != current_session_token:
            db.delete(session)
    db.commit()
    return {"message": "Logged out from other devices"}

# Session expiration check
@router.get("/check-session/{user_id}")
async def check_session(user_id: int, 
    db: db_dependency,
    current_user: Annotated[User, Depends(require_role(UserType.ADMIN, UserType.MID_USER))]):
    session = db.query(UserDetails).filter(UserDetails.user_id == user_id).first()
    if session and datetime.fromisoformat(session.expire) < datetime.utcnow():
        return {"message": "Session expired"}
    return {"message": "Session active"}

# Generate simple reports
@router.get("/report/active-users")
async def active_users_report(
    db: db_dependency,
    current_user: Annotated[User, Depends(require_role(UserType.ADMIN, UserType.MID_USER))]):
    active_users = db.query(User).filter(User.VERIFIED == True, User.BLOCKED == False).count()
    return {"active_users": active_users}

@router.get("/report/recent-registrations")
async def recent_registrations_report(
    db: db_dependency,
    current_user: Annotated[User, Depends(require_role(UserType.ADMIN, UserType.MID_USER))],):
    recent_users = db.query(User).filter(User.VERIFIED == True).order_by(User.id.desc()).limit(10).all()
    return {"recent_registrations": [user.name for user in recent_users]}

# Export user data to CSV
@router.get("/export/users-csv")
async def export_users_to_csv(
    db: db_dependency,
    current_user: Annotated[User, Depends(require_role(UserType.ADMIN))],):
    users = db.query(User).all()
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Name", "Email", "Role", "Verified", "Blocked"])
    for user in users:
        writer.writerow([user.id, user.name, user.email, user.role.value, user.VERIFIED, user.BLOCKED])
    output.seek(0)
    return StreamingResponse(output, media_type="text/csv", headers={"Content-Disposition": "attachment; filename=users.csv"})








