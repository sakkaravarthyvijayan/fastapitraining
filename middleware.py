from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
import jwt
import logging
import time
import traceback
import os
from dotenv import load_dotenv
load_dotenv()


SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        protected_routes = ["/block-user", "/unblock-user", "/admin-only,/admin_mid-user,/protected-route"]
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

                # payload = jwt.decode(token, config['jwt']['secret_key'], algorithms=[config['jwt']['algorithm']])
                request.state.user = payload  

            except jwt.ExpiredSignatureError:
                return JSONResponse(status_code=401, content={"detail": "JWT token has expired"})
            except jwt.InvalidTokenError:
                logging.error("Invalid JWT token")
                return JSONResponse(status_code=401, content={"detail": "Invalid JWT token"})
            except Exception as e:
                logging.error(f"JWT verification failed: {str(e)}")
                return JSONResponse(status_code=401, content={"detail": "Authentication failed"})

        response = await call_next(request)
        return response

class RoleBasedAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request : Request, call_next):
        protected_routes = {
            "/admin-only": ["admin"],
            "/block-user":["admin"],
            "/unblock-user":["admin"],
            "/admin_mid-user": ["mid_user", "admin"],
            "/protected-route": ["end_user", "mid_user", "admin"]
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
                
                
                # payload = jwt.decode(token, config['jwt']['secret_key'], algorithms=[config['jwt']['algorithm']])
                # request.state.user = payload  
                
                # user_role = payload.get('role')
                payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

                # payload = jwt.decode(token, config['jwt']['secret_key'], algorithms=[config['jwt']['algorithm']])
                request.state.user = payload  

                user_role = payload.get('role')

                
                if not user_role:
                    return JSONResponse(status_code=403, content={'detail':'user role not found in token'})
                
                for route,allowed_roles in protected_routes.items():
                    
                    if route in request.url.path:
                        if user_role not in allowed_roles:
                            return JSONResponse(status_code=403, content={"detail":f" '{user_role}'not authorized to access this route"})
                    
                    break
                
            except jwt.ExpiredSignatureError:
                return JSONResponse(status_code=401, content={"detail": "JWT token has expired"})
            except jwt.PyJWTError as e:
                logging.error(f"JWT verification failed: {str(e)}")
                return JSONResponse(status_code=401, content={"detail": "Invalid JWT token"})

        
        response = await call_next(request)
        return response
    

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        method = request.method
        url = str(request.url)

        start_time = time.time()

        logging.info(f"received request: {method} {url}")

        try:
            response = await call_next(request)

            status_code = response.status_code
            process_time = time.time() - start_time

            logging.info(f"Completed request: {method} {url} with status {status_code} in {process_time:.4f} seconds")

            return response
        
        except Exception as e:
            end_time = time.time()
            execution_time = end_time - start_time
            
            logging.error(
                f"Error processing request: {method} {url} | "
                f"Start Time: {start_time:.4f} | "
                f"End Time: {end_time:.4f} | "
                f"Execution Time: {execution_time:.4f} seconds | "
                f"Exception: {str(e)}"
            )

            return JSONResponse(status_code=500, content={"detail": "Internal Server Error"})
        


class GlobalErrorHandlingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        try:
            response = await call_next(request)
            return response
        except Exception as e:
            logging.error(f"unhandled error:{str(e)}")
            traceback.print_exc()
