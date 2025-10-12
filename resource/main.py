from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional, Dict
import requests
from jose import jwt

from settings import settings

app = FastAPI(title="TinyAuth - Resource Server (Notes API)")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Simple in-memory user notes
NOTES: Dict[str, list[str]] = {"u_demo": ["Welcome to TinyAuth!", "Your second note"]}

# Cache JWKS in memory (simple)
_JWKS = None

def get_jwks():
    global _JWKS
    if _JWKS is None:
        _JWKS = requests.get(settings.JWKS_URL, timeout = 3).json()
    return _JWKS

def verify_token(auth_header: Optional[str]):
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(401, detail="missing_bearer")
    token = auth_header.split(" ", 1)[1]

    jwks = get_jwks()

    try:
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        key = next((k for k in jwks["keys"] if k.get("kid") == kid), None)
        if not key:
            raise HTTPException(401, detail="unknown_kid")
        claims = jwt.decode(token, key, algorithms=["RS256"], audience=settings.AUDIENCE, options={"verify_iss": True}, issuer=settings.AUTH_ISSUER)
        return claims
    except Exception as e:
        raise HTTPException(401, detail=f"Invalid_token: {e}")
    

@app.get("/api/notes")
async def list_notes(authorization: Optional[str] = Header(None)):
    claims = verify_token(authorization)
    # scope check
    scopes = set((claims.get("scope") or "").split())
    if "notes.read" not in scopes:
        raise HTTPException(403, detail="insufficient_scope")
    user = claims["sub"]
    return {"notes": NOTES.get(user, [])}


@app.post("/api/notes")
async def add_note(note: str, authorization: Optional[str] = Header(None)):
    claims = verify_token(authorization)
    scopes = set((claims.get("scope") or "").split())
    if "notes.write" not in scopes:
        raise HTTPException(403, detail="insufficient_scope")
    user = claims["sub"]
    NOTES.setdefault(user, []).append(note)
    return {"ok": True}