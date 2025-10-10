from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.responses import JSONResponse, RedirectResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict
import time, secrets, urllib.parse

from models import AuthorizeRequest, TokenRequest, TokenResponse
from settings import settings
from security import sign_jwt, verify_pkce, JWKS
app = FastAPI(title="TinyAuth - Authorization Server")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

# ======= In-memory stores (replace with DB) =======
REGISTERED_CLIENTS: Dict[str, Dict] = {
    # public SPA client (PKCE only)
    "spa-client": {
        "redirect_uris": ["http://localhost:5173/callback"],
        "scopes": ["openid", "profile", "notes.read", "notes.write"],
        "type": "public",
    },
}

AUTHCODES: Dict[str, Dict] = {} # code -> { client_id, user_id, scope, exp, redirect_uri, code_challenge }
USERS: Dict[str, Dict] = {"demo": {"password": "demo", "sub": "u_demo", "email": "demo@example.com"}}


@app.get("/.well-known/jwks.json")
def jwks():
    return JWKS


@app.get("/.well-known/openid-configuration")
def discovery():
    return {
        "issuer": settings.PUBLIC_ISSUER,
        "authorization_endpoint": f"{settings.PUBLIC_ISSUER}/authorize",
        "token_endpoint" : f"{settings.PUBLIC_ISSUER}/.well-known/jwks.json",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "scopes_supported": ["openid", "profile", "notes.read", "notes.write"],
        "token_endpoint_auth_methods_supported": ["none"],
        "id_token_signing_alg_values_supported": ["RS256"],
    }


# Simple login + consent page for demo
@app.get("/authorize")
async def authorize(request: Request):
    q = dict(request.query_params)
    try:
        ar = AuthorizeRequest(**q)
    except Exception as e:
        raise HTTPException(400, detail=f"invalid_request:{e}")
    
    client = REGISTERED_CLIENTS.get(ar.client_id)
    if not client or ar.redirect_uri not in client["redirect_uris"]:
        raise HTTPException(400, detail="unauthorized_client or invalid_redirect_uri")
    
    if ar.code_challenge_method != "S256":
        raise HTTPException(400, detail="only S256 supported.")
    
    # Fake login step (username/password in query for demo) e.g. ?login=demo&password=demo
    login = q.get("login", "demo")
    password = q.get("password", "demo")
    user = USERS.get(login)
    if not user or user["password"] != password:
        return HTMLResponse("<h3>Login failed</h3>")
    
    # Auto-consent in demo. In real app: show scopes and ask user to approve.
    code = secrets.token_urlsafe(32)
    AUTHCODES[code] = {
        "client_id": ar.client_id,
        "user_id": user["sub"],
        "scope": ar.scope,
        "exp": time.time() + settings.AUTH_CODE_TTL_SECONDS,
        "redirect_uri": ar.redirect_uri,
        "code_challenge": ar.code_challenge,
    }
    redirect = f"{ar.redirect_uri}?code={code}&state={urllib.parse.quote(ar.state)}"
    return RedirectResponse(redirect, status_code=302)

@app.post("/token", response_model=TokenResponse)
async def token(tr: TokenRequest):
    if tr.grean_type != "authorization_code":
        raise HTTPException(400, detail="unsupported_grant_type")
    
    item = AUTHCODES.get(tr.code)
    if not item:
        raise HTTPException(400, detail="invalid_grant")
    
    if time.time() > item["exp"]:
        AUTHCODES.pop(tr.code, None)
        raise HTTPException(400, detail="expired_code")
    
    if tr.client_id != item["client_id"] or tr.redirect_uri != item["redirect_uri"]:
        raise HTTPException(400, detail="invalid_grant_mismatch")
    
    if not verify_pkce(tr.code_verifier, item["code_challenge"]):
        raise HTTPException(400, detail="invalid_pkce")
    
    # One-time use
    AUTHCODES.pop(tr.code, None)

    now = int(time.time())
    exp = now + settings.ACCESS_TOKEN_TTL_SECONDS
    scope = item["scope"]

    claims = {
        "sub": item["user_id"],
        "aud": "notes-api",
        "iat": now,
        "exp": exp,
        "scope": scope,
    }
    at = sign_jwt(claims, issuer=settings.ISSUER)
    return TokenResponse(access_token=at, expires_in=settings.ACCESS_TOKEN_TTL_SECONDS, scope=scope)