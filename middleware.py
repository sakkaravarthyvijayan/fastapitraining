from fastapi import Request, HTTPException, Depends,BackgroundTasks
from fastapi.responses import JSONResponse,Response
from starlette.middleware.base import BaseHTTPMiddleware
import jwt
import logging
import time
import traceback
import os
from collections import defaultdict
from dotenv import load_dotenv
import shutil
from collections import defaultdict
from datetime import datetime, timedelta
from starlette.responses import JSONResponse


load_dotenv()


SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")


# Directory to store logs

LOG_DIR = 'logs'  # Replace with the actual path to the log directory

# Create a folder for the current month and year
def setup_monthly_log_folder():
    """
    Creates a directory for the current month and year if it does not exist.
    Returns the path to the log file named with the current date.
    """
    current_month_year = datetime.now().strftime('%Y-%m')  # e.g., '2024-10'
    monthly_log_dir = os.path.join(LOG_DIR, current_month_year)
    
    if not os.path.exists(monthly_log_dir):
        os.makedirs(monthly_log_dir)

    # Return the full path to the log file with date and month
    log_file_name = datetime.now().strftime('%d-%m-%Y.log')  # e.g., '18-10-2024.log'
    return os.path.join(monthly_log_dir, log_file_name)

# Remove log folders older than a month
def remove_old_folders():
    """
    Removes folders in the LOG_DIR that are older than one month.
    """
    now = datetime.now()
    one_month_ago = now - timedelta(days=30)

    if not os.path.exists(LOG_DIR):
        return

    for folder_name in os.listdir(LOG_DIR):
        folder_path = os.path.join(LOG_DIR, folder_name)

        if os.path.isdir(folder_path):
            try:
                folder_date = datetime.strptime(folder_name, '%Y-%m')
                if folder_date < one_month_ago:
                    shutil.rmtree(folder_path)
                    logger.info(f"Deleted old log folder: {folder_name}")
            except ValueError:
                continue  # Skip folders not matching the format 'YYYY-MM'

# Set up the logger
logger = logging.getLogger('example_logger')
logger.setLevel(logging.INFO)

# Create a file handler for logging to a file, using the monthly folder structure
log_file_path = setup_monthly_log_folder()
file_handler = logging.FileHandler(log_file_path)
file_handler.setLevel(logging.INFO)

# Create a console handler for logging to the console
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

# Define a formatter for the logs
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

# Add the handlers to the logger
logger.addHandler(file_handler)
logger.addHandler(console_handler)

# Run the cleanup function to remove old folders
remove_old_folders()

# In-memory metrics storage
metrics = defaultdict(int)

def setup_monthly_log_folder():
    """
    Creates a folder for the current month and year to store logs.
    
    Returns:
        str: The full path to the log file with the date and month (e.g., '2024-10/18-10-2024.log').
    """
    current_month_year = datetime.now().strftime('%Y-%m')  # e.g., '2024-10'
    monthly_log_dir = os.path.join(LOG_DIR, current_month_year)
    
    if not os.path.exists(monthly_log_dir):
        os.makedirs(monthly_log_dir)

    log_file_name = datetime.now().strftime('%d-%m-%Y.log')  # e.g., '18-10-2024.log'
    return os.path.join(monthly_log_dir, log_file_name)


def remove_old_folders():
    """
    Removes log folders older than one month.

    It compares the folder's creation date with the current date and removes any folder that is older than 30 days.
    """
    now = datetime.now()
    one_month_ago = now - timedelta(days=30)

    if not os.path.exists(LOG_DIR):
        return

    for folder_name in os.listdir(LOG_DIR):
        folder_path = os.path.join(LOG_DIR, folder_name)

        if os.path.isdir(folder_path):
            try:
                folder_date = datetime.strptime(folder_name, '%Y-%m')
                if folder_date < one_month_ago:
                    shutil.rmtree(folder_path)
                    logger.info(f"Deleted old log folder: {folder_name}")
            except ValueError:
                continue  # Skip folders not matching the format 'YYYY-MM'


def increment_metric(metric_name: str):
    """
    Increments a specified metric.

    Args:
        metric_name (str): The name of the metric to be incremented.
    """
    metrics[metric_name] += 1
    logger.info(f"Metric {metric_name} incremented, current value: {metrics[metric_name]}")


def get_metrics():
    """
    Retrieves the current metrics stored in memory.

    Returns:
        dict: A dictionary containing the metrics and their current values.
    """
    return dict(metrics)


def log_critical_action(action: str, user_id: int):
    """
    Logs critical actions such as user logins, profile updates, etc.

    Args:
        action (str): The action performed by the user.
        user_id (int): The ID of the user who performed the action.
    """
    logger.info(f"CRITICAL ACTION: {action} performed by User ID: {user_id}")


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware to log all incoming HTTP requests and their responses.

    It logs the HTTP method, URL path, status code, and the time taken to process the request.
    """
    async def dispatch(self, request: Request, call_next):
        method = request.method
        path = request.url.path
        start_time = time.time()

        logger.info(f"Request received: {method} {path}")

        try:
            response = await call_next(request)
            status_code = response.status_code
            process_time = time.time() - start_time

            logger.info(f"Request completed: {method} {path} | Status: {status_code} | Time: {process_time:.4f}s")
            return response
        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"Error processing request: {method} {path} | Execution Time: {execution_time:.4f}s | Exception: {str(e)}")
            return JSONResponse(status_code=500, content={"detail": "Internal Server Error"})


class AuthMiddleware(BaseHTTPMiddleware):
    """
    Middleware to enforce JWT authentication for protected routes.

    It checks if the request contains a valid JWT token for routes that require authentication. 
    If the token is invalid or missing, it returns a 401 Unauthorized response.
    """
    async def dispatch(self, request: Request, call_next):
        protected_routes = ["/verify-user", "/block-user", "/unblock-user", "/admin-only", "/admin_mid-user", "/protected-route",
                            "/check-session", "/report/active-users", "/report/recent-registrations", "/export/users-csv"]
        if any(route in request.url.path for route in protected_routes):
            token = request.headers.get("Authorization")

            if not token:
                return JSONResponse(status_code=401, content={"detail": "Authentication required"})
            
            try:
                if token.startswith("Bearer "):
                    token = token.split("Bearer ")[1]
                else:
                    return JSONResponse(status_code=401, content={"detail": "Invalid Authorization header format"})
                
                payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
                request.state.user = payload  # Store user information in the request state

            except jwt.ExpiredSignatureError:
                return JSONResponse(status_code=401, content={"detail": "JWT token has expired"})
            except jwt.InvalidTokenError:
                logger.error("Invalid JWT token")
                return JSONResponse(status_code=401, content={"detail": "Invalid JWT token"})
            except Exception as e:
                logger.error(f"JWT verification failed: {str(e)}")
                return JSONResponse(status_code=401, content={"detail": "Authentication failed"})

        response = await call_next(request)
        return response


class RoleBasedAuthMiddleware(BaseHTTPMiddleware):
    """
    Middleware to enforce role-based access control (RBAC).

    It checks the user's role in the JWT token and ensures they have the required role to access specific protected routes.
    """
    async def dispatch(self, request: Request, call_next):
        protected_routes = {
            "/verify-user": ["admin"],
            "/admin-only": ["admin"],
            "/block-user": ["admin"],
            "/unblock-user": ["admin"],
            "/admin_mid-user": ["mid_user", "admin"],
            "/protected-route": ["end_user", "mid_user", "admin"],
            "/check-session": ["mid_user", "admin"],
            "/report/active-users": ["mid_user", "admin"],
            "/report/recent-registrations": ["mid_user", "admin"],
            "/export/users-csv": ["admin"],
        }

        if any(route in request.url.path for route in protected_routes):
            token = request.headers.get('Authorization')

            if not token:
                return JSONResponse(status_code=401, content={"detail": "Authentication required"})
            
            try:
                if token.startswith('Bearer'):
                    token = token.split("Bearer ")[1]
                else: 
                    return JSONResponse(status_code=401, content={"detail": "Invalid or missing Authorization header"})
                
                payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
                request.state.user = payload  

                user_role = payload.get('role')

                if not user_role:
                    return JSONResponse(status_code=403, content={'detail':'User role not found in token'})
                
                for route, allowed_roles in protected_routes.items():
                    if route in request.url.path:
                        if user_role not in allowed_roles:
                            return JSONResponse(status_code=403, content={"detail": f"'{user_role}' not authorized to access this route"})
                        break
                
            except jwt.ExpiredSignatureError:
                return JSONResponse(status_code=401, content={"detail": "JWT token has expired"})
            except jwt.PyJWTError as e:
                logger.error(f"JWT verification failed: {str(e)}")
                return JSONResponse(status_code=401, content={"detail": "Invalid JWT token"})

        response = await call_next(request)
        return response


class GlobalErrorHandlingMiddleware(BaseHTTPMiddleware):
    """
    Middleware to handle global errors that occur during the request-response cycle.

    It catches unhandled exceptions and logs them while returning a generic error response.
    """
    async def dispatch(self, request, call_next):
        try:
            response = await call_next(request)
            return response
        except Exception as e:
            logger.error(f"Unhandled error: {str(e)}")
            traceback.print_exc()
            return JSONResponse(status_code=500, content={"detail": "Internal Server Error"})
