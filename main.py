import os
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import RedirectResponse, JSONResponse
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.cors import CORSMiddleware
import secrets
import redis
from httpx import AsyncClient

import jwt
from datetime import datetime, timedelta, UTC
import json
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = FastAPI(
    title="SAML Auth API",
    description="API for handling SAML authentication",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

# Session middleware
# app.add_middleware(SessionMiddleware, secret_key="your-secret-key")

FRONTEND_BASE_URL = os.getenv("FRONTEND_BASE_URL")
FRONTEND_REDIRECT_URL = os.getenv("FRONTEND_REDIRECT_URL")
BACKEND_BASE_URL = os.getenv("BACKEND_BASE_URL")

REDIS_HOST = os.getenv("REDIS_HOST")
REDIS_PORT = os.getenv("REDIS_PORT")
REDIS_DB = os.getenv("REDIS_DB")

SP_ACS_URL = os.getenv("SP_ACS_URL")
SP_SLO_URL = os.getenv("SP_SLO_URL")
SP_CERT = os.getenv("SP_CERT")
SP_KEY = os.getenv("SP_KEY")

IDP_ENTITY_ID = os.getenv("IDP_ENTITY_ID")
IDP_SSO_URL = os.getenv("IDP_SSO_URL")
IDP_SLO_URL = os.getenv("IDP_SLO_URL")
IDP_CERT = os.getenv("IDP_CERT")

SECRET_KEY = os.getenv("SECRET_KEY")

# Redis client
redis_client = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    db=REDIS_DB,
    decode_responses=True
)


REDIRECT_URL = FRONTEND_REDIRECT_URL

# SAML settings
saml_settings = {
    "strict": True,  # Set to True for production
    "debug": True,
    "security": {
        "nameIdEncrypted": False,
        "authnRequestsSigned": True,  # Enable request signing
        "logoutRequestSigned": True,
        "logoutResponseSigned": True,
        "signMetadata": True,
        "wantMessagesSigned": True,
        "wantAssertionsSigned": True,  # Require signed assertions
        "wantNameIdEncrypted": False,
        "allowRepeatAttributeName": True,
        "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256"
    },
    "sp": {
        "entityId": "saml-client",
        "assertionConsumerService": {
            "url": SP_ACS_URL,
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        },
        "singleLogoutService": {
            "url": SP_SLO_URL,
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
        "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        "x509cert": SP_CERT,
        "privateKey": SP_KEY
    },
    "idp": {
        "entityId": IDP_ENTITY_ID,
        "singleSignOnService": {
            "url": IDP_SSO_URL,
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
        "singleLogoutService": {
            "url": IDP_SLO_URL,
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
        "x509cert": IDP_CERT
    }
    
}

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        # Verify JWT token
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=["HS256"]
        )
        
        # Get session data from Redis
        session_data_str = redis_client.get(f"saml_session:{payload['session_index']}")
        if not session_data_str:
            raise HTTPException(
                status_code=401,
                detail="Session expired"
            )
            
        session_data = json.loads(session_data_str)
        return session_data
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=401,
            detail="Token has expired"
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=401,
            detail="Invalid token"
        )
    except Exception as e:
        print(f"******* Exception IN TOKEN VALIDATION: {e} *******")
        raise HTTPException(
            status_code=401,
            detail=str(e)
        )


def init_saml_auth(req):
    auth = OneLogin_Saml2_Auth(req, saml_settings)
    return auth

def create_access_token(sub:str, session_index: str, roles: list):
    payload = {
        "sub": sub,
        "session_index": session_index,
        "roles": roles,
        "exp": datetime.now(UTC) + timedelta(hours=1)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def create_refresh_token(sub:str, session_index: str):
    payload = {
        "sub": sub,
        "session_index": session_index,
        "exp": datetime.now(UTC) + timedelta(days=30)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


@app.get("/saml-login")
async def initiate_saml(request: Request, provider: str):
    try:
        req = {
            'https': 'on' if request.url.scheme == 'https' else 'off',
            'http_host': '127.0.0.1:8000',
            'server_port': 8000,
            'script_name': request.url.path,
            'get_data': dict(request.query_params),
            'post_data': {},
            'base_url': BACKEND_BASE_URL 
        }
    
        auth = init_saml_auth(req)

        # Generate state and relay state
        state = secrets.token_urlsafe(32)
        
        # Store state in Redis
        redis_client.setex(
            f"saml_state:{state}",
            300,  # 5 minutes
            "true"
        )
        
        # Initialize SAML auth
        auth = init_saml_auth(req)
        
        # Set RelayState to include frontend callback URL and state
        relay_state = f"{REDIRECT_URL}?state={state}"
        
        sso_built_url = auth.login(
            return_to=relay_state,
        )
        
        sso_built_url += f"&kc_idp_hint={provider}&prompt=select_account"
        
        return {
            "saml_request": sso_built_url,
            "state": state
        }
        
    except Exception as e:
        print(f"******* Exception: {e} *******")
        raise HTTPException(status_code=500, detail=str(e))
    
    
@app.post("/acs")
async def acs(request: Request):
    try:
        form_data = await request.form()
        saml_response = form_data.get('SAMLResponse')
        relay_state = form_data.get('RelayState')
        print(f"******* Relay State: {relay_state} *******")
        
        # Extract state from relay_state
        state = relay_state.split('state=')[1] if relay_state else None
        
        # Verify state
        stored_state = redis_client.get(f"saml_state:{state}")
        if not stored_state:
            frontend_url = f"{REDIRECT_URL}?error=invalid_state"
            return RedirectResponse(url=frontend_url)
            
        # Delete used state
        redis_client.delete(f"saml_state:{state}")
        
        req = {
            'https': 'on' if request.url.scheme == 'https' else 'off',
            'http_host': '127.0.0.1:8000',
            'server_port': 8000,
            'script_name': request.url.path,
            'get_data': dict(request.query_params),
            'post_data': form_data,
            'base_url': BACKEND_BASE_URL
        }

        modified_settings = saml_settings.copy()        
        
        auth = OneLogin_Saml2_Auth(req, modified_settings)
        
#         # Process the response
        auth.process_response()
        errors = auth.get_errors()
        
        if len(errors) > 0:
            raise HTTPException(status_code=401, detail=f"SAML Error: {', '.join(errors)}")
            
        if not auth.is_authenticated():
            raise HTTPException(status_code=401, detail="Authentication failed")

        # Get SAML data
        attributes = auth.get_attributes()
        name_id = auth.get_nameid()
        session_index = auth.get_session_index()
        
        print(f"Attributes: {attributes}")
        print(f"Name ID: {name_id}")
        print(f"Session Index: {session_index}")

        # Generate temporary code
        temp_code = secrets.token_urlsafe(32)
        
        # Store SAML session data
        session_data = {
            "name_id": name_id,
            "session_index": session_index,
            "attributes": attributes,
            "created_at": datetime.now(UTC).isoformat()
        }
        
        redis_client.setex(
            f"saml_code:{temp_code}",
            300,
            json.dumps(session_data)
        )

        # Redirect to frontend with code and session_index
        frontend_url = f"{REDIRECT_URL}?code={temp_code}&session_index={session_index}&state={state}"
        return RedirectResponse(url=frontend_url, status_code=303)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
    
@app.get("/api/auth/token")
async def get_tokens(
    code: str,
    session_index: str
):
    try:
        # Get and validate temporary code
        session_data = redis_client.get(f"saml_code:{code}")
        if not session_data:
            return JSONResponse(
                status_code=400,
                content={
                    "error": "invalid_code",
                    "error_description": "Invalid or expired code",
                    "status": "error"
                }
            )
            
        session_data = json.loads(session_data)
        
        # Verify session_index
        if session_data['session_index'] != session_index:
            raise HTTPException(status_code=400, detail="Invalid session")
            
        # Delete used code
        redis_client.delete(f"saml_code:{code}")
        
        # Extract user information
        email = session_data["name_id"]  # or session_data["attributes"]["urn:oid:1.2.840.113549.1.9.1"][0]
        first_name = session_data["attributes"]["urn:oid:2.5.4.42"][0]  # givenName
        last_name = session_data["attributes"]["urn:oid:2.5.4.4"][0]    # surname
        roles = session_data["attributes"]["Role"]
        
        # Create tokens
        access_token = create_access_token(email, session_index, roles)
        refresh_token = create_refresh_token(email, session_index)
        
        # Create session data
        session_data = {
            "name_id": email,
            "email": email,
            "firstName": first_name,
            "lastName": last_name,
            "roles": roles,
            "session_index": session_index
        }
        
        # Store session in Redis
        redis_client.setex(
            f"saml_session:{session_index}",
            60 * 60 * 24 * 30,  # 30 days
            json.dumps(session_data)
        )
        
        return JSONResponse({
            "access_token": access_token,
            "refresh_token": refresh_token,
        })
        
    except Exception as e:
        print(f"******* Exception: {e} *******")
        raise HTTPException(status_code=500, detail=str(e))
    
    

@app.get("/api/auth/refresh")
async def refresh_token(current_user: dict = Depends(get_current_user)):
    try:
        session_index = current_user.get("session_index")
        # Get session data from Redis using session_index
        session_data_str = redis_client.get(f"saml_session:{session_index}")
        if not session_data_str:
            return JSONResponse(
                status_code=400,
                content={
                    "error": "invalid_session",
                    "error_description": "Session not found",
                    "status": "error"
                }
            )

        session_data = json.loads(session_data_str)
        
        print(f"******* Session Data in Refresh Token: {session_data} *******")
        
        email = session_data.get("email")
        roles = session_data.get("roles")
        
        # Generate new access token
        new_access_token = create_access_token(email, session_index, roles)
        # Generate new refresh token
        new_refresh_token = create_refresh_token(email, session_index)
                
        return JSONResponse({
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
        })
        
    except Exception as e:
        print(f"Refresh token error: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={
                "error": "server_error",
                "error_description": str(e),
                "status": "error"
            }
        )


@app.get("/api/auth/me")
async def get_user_info(current_user: dict = Depends(get_current_user)):
    try:
        return JSONResponse({
            "status": "success",
            "user": {
                "id": current_user.get("email"),
                "email": current_user.get("email"),
                "firstName": current_user.get("firstName"),
                "lastName": current_user.get("lastName"),
                "roles": current_user.get("roles"),
                "sessionIndex": current_user.get("session_index"),
            }
        })
        
    except Exception as e:
        print(f"******* Exception IN GET USER INFO API: {e} *******")
        return JSONResponse(
            status_code=500,
            content={
                "error": "server_error",
                "error_description": str(e),
                "status": "error"
            }
        )
    

@app.get("/logout")
async def logout(request: Request, current_user: dict = Depends(get_current_user)):
    try:
        name_id = current_user.get("name_id")
        session_index = current_user.get("session_index")
        
        if not name_id or not session_index:
            return JSONResponse(
                status_code=400,
                content={
                    "error": "invalid_session_index",
                    "error_description": "Invalid Session Index",
                    "status": "error"
                }
            )

        req = {
            'https': 'on' if request.url.scheme == 'https' else 'off',
            'http_host': '127.0.0.1:8000',
            'server_port': 8000,
            'script_name': request.url.path,
            'get_data': dict(request.query_params),
            'post_data': {},
            'base_url': BACKEND_BASE_URL
        }
        
        auth = init_saml_auth(req)

        slo_url = auth.logout(
            name_id=name_id,
            session_index=session_index,
            return_to=FRONTEND_BASE_URL
        )
        redis_client.delete(f"saml_session:{session_index}")

        async with AsyncClient() as client:
            await client.get(slo_url, follow_redirects=True)

        return JSONResponse(
            status_code=200,
            content={
                "status": "success",
                "message": "Logout successful",
            }
        )
        
    except Exception as e:
        print(f"Logout error: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={
                "error": "logout_error",
                "error_description": str(e),
                "status": "error"
            }
        )


@app.get("/slo")
async def slo(request: Request):
    print(f"*********************** SLO CALLED ********************")
    try:
        req = {
            'https': 'on' if request.url.scheme == 'https' else 'off',
            'http_host': '127.0.0.1:8000',
            'server_port': 8000,
            'script_name': request.url.path,
            'get_data': dict(request.query_params),
            'post_data': await request.form() if request.method == "POST" else {},
            'base_url': BACKEND_BASE_URL
        }
        
        auth = init_saml_auth(req)
        
        def delete_session_callback():
            if hasattr(request, 'session'):
                request.session.clear()

        url = auth.process_slo(
            delete_session_cb=delete_session_callback,
            keep_local_session=False,
        )
        
        return RedirectResponse(
            url=FRONTEND_BASE_URL,
            status_code=303
        )
            
    except Exception as e:
        print(f"SLO error: {str(e)}")
        return RedirectResponse(
            url=FRONTEND_BASE_URL,
            status_code=303
        )
