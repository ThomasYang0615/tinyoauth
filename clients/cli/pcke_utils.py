"""
PKCE helpers (RFC 7636, S256) – no external dependencies.

Usage (CLI):
  python pkce_utils.py
  python pkce_utils.py --issuer http://localhost:8000 \
      --client-id spa-client \
      --redirect-uri http://localhost:5173/callback \
      --scope "notes.read notes.write" \
      --state xyz

Typical programmatic use:
  from pkce_utils import generate_verifier, generate_challenge, verify_pkce

  verifier = generate_verifier()                 # str (43–128 chars, unpadded base64url)
  challenge = generate_challenge(verifier)       # str (unpadded base64url)
  assert verify_pkce(verifier, challenge)        # True if they match
"""

from __future__ import annotations

import os
import base64
import hashlib
import secrets
import urllib.parse
from dataclasses import dataclass


# ===== Base64url helpers (unpadded) =====

def _b64url_unpadded(data: bytes) -> str:
    """Base64url encode without '=' padding (per RFC 7636)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# ===== PKCE core =====

def generate_verifier(n_bytes: int = 64) -> str:
    """
    Generate a code_verifier as unpadded base64url string.

    - RFC 7636 requires length in [43, 128] characters AFTER encoding.
    - With n_bytes in [32..96], length typically falls in 43..128.
    - Default n_bytes=64 → good entropy and compliant length.

    Returns:
        str: code_verifier (base64url, no padding)
    """
    if not (32 <= n_bytes <= 96):
        raise ValueError("n_bytes must be in [32, 96] to keep encoded length within [43, 128].")
    raw = secrets.token_bytes(n_bytes)  # cryptographically secure
    verifier = _b64url_unpadded(raw)

    if not (43 <= len(verifier) <= 128):
        # Extremely unlikely with the chosen bounds; re-generate if it happens
        return generate_verifier(n_bytes=n_bytes)

    return verifier


def generate_challenge(code_verifier: str) -> str:
    """
    Compute code_challenge (S256) from a code_verifier.
    Returns base64url (unpadded) string.
    """
    return _b64url_unpadded(_sha256(code_verifier.encode("ascii")))


def verify_pkce(code_verifier: str, code_challenge: str) -> bool:
    """
    True if the given verifier derives to the given challenge (S256).
    """
    try:
        return secrets.compare_digest(generate_challenge(code_verifier), code_challenge)
    except Exception:
        return False


# ===== Convenience: authorize URL builder =====

@dataclass(frozen=True)
class AuthorizeParams:
    issuer: str                      # e.g., "http://localhost:8000"
    client_id: str                   # e.g., "spa-client"
    redirect_uri: str                # e.g., "http://localhost:5173/callback"
    scope: str = "openid profile"    # space-separated
    state: str | None = None
    code_challenge_method: str = "S256"
    response_type: str = "code"
    extra: dict | None = None        # any extra query params

def build_authorize_url(p: AuthorizeParams, code_challenge: str) -> str:
    """
    Build an /authorize URL with PKCE parameters included.
    Note: you keep the associated code_verifier on the client for the /token call.
    """
    q = {
        "response_type": p.response_type,
        "client_id": p.client_id,
        "redirect_uri": p.redirect_uri,
        "scope": p.scope,
        "code_challenge": code_challenge,
        "code_challenge_method": p.code_challenge_method,
    }
    if p.state is None:
        # If no state supplied, generate one (recommended for CSRF protection)
        q["state"] = _b64url_unpadded(os.urandom(16))
    else:
        q["state"] = p.state

    if p.extra:
        q.update(p.extra)

    base = p.issuer.rstrip("/") + "/authorize"
    return f"{base}?{urllib.parse.urlencode(q)}"


# ===== CLI demo =====

def _print_pair_and_url(issuer: str, client_id: str, redirect_uri: str, scope: str, state: str | None):
    verifier = generate_verifier()
    challenge = generate_challenge(verifier)
    url = build_authorize_url(
        AuthorizeParams(
            issuer=issuer,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            state=state,
        ),
        code_challenge=challenge,
    )
    print("PKCE PAIR")
    print("---------")
    print(f"code_verifier: {verifier}")
    print(f"code_challenge: {challenge}")
    print()
    print("Authorize URL")
    print("-------------")
    print(url)
    print()
    print("Next step:")
    print("  1) Open the URL in a browser to obtain `code` (from the redirect).")
    print("  2) Exchange at /token with JSON body:")
    print('     {')
    print('       "grant_type":"authorization_code",')
    print('       "code":"<PASTE_CODE>",')
    print('       "redirect_uri":"%s",' % redirect_uri)
    print('       "client_id":"%s",' % client_id)
    print('       "code_verifier":"%s"' % verifier)
    print('     }')


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="PKCE utilities (verifier/challenge generation and authorize URL builder).")
    ap.add_argument("--issuer", default="http://localhost:8000", help="Authorization Server base URL")
    ap.add_argument("--client-id", default="spa-client", help="OAuth2 client_id")
    ap.add_argument("--redirect-uri", default="http://localhost:5173/callback", help="redirect_uri")
    ap.add_argument("--scope", default="notes.read notes.write", help="space-separated scope string")
    ap.add_argument("--state", default=None, help="optional state (random if omitted)")
    ap.add_argument("--verify", nargs=2, metavar=("VERIFIER", "CHALLENGE"),
                    help="verify a verifier/challenge pair and exit")
    args = ap.parse_args()

    if args.verify:
        v, c = args.verify
        print("match:" if verify_pkce(v, c) else "mismatch")
    else:
        _print_pair_and_url(args.issuer, args.client_id, args.redirect_uri, args.scope, args.state)
