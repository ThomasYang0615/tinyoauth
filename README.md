# TinyAuth (OAuth 2.0 / OIDC-ish Demo, Python/FastAPI)

TinyAuth is a **runnable** OAuth 2.0 / OIDC-style teaching project built with Python/FastAPI. It demonstrates:

* **Authorization Server**: `/authorize` (Authorization Code + PKCE), `/token`, `/.well-known/jwks.json`, `/.well-known/openid-configuration`
* **Resource Server**: a Notes API that validates RS256 JWTs via JWKS and enforces scopes
* **Docker Compose**: one command to boot both services locally

> This repository is intended for **education/demo**. It uses in-memory stores and a minimal fake login/consent flow. Expansion points are marked for you to productionize.

---

## Project Structure

```
tinyoauth/
  auth/
    main.py           # /authorize, /token, discovery, JWKS
    security.py       # RSA key gen, JWT signing, PKCE, JWKS
    models.py         # Pydantic request/response models
    settings.py       # Issuer, TTLs
    requirements.txt
    .env.example
  resource/
    main.py           # /api/notes protected endpoints
    settings.py       # issuer, jwks, audience
    requirements.txt
    .env.example
  scripts/
    pkce_demo.sh
  clients/
    cli/
      pkce_utils.py
  Makefile
  docker-compose.yml
  README.md           # this file
```

---

## Quickstart

### 1) Prepare environment files (do not commit real `.env`)

```bash
cp auth/.env.example auth/.env
cp resource/.env.example resource/.env
```

### 2) Start services

```bash
docker compose up --build
```

* Authorization Server: [http://localhost:8000](http://localhost:8000)
* Resource Server: [http://localhost:8001](http://localhost:8001)

### 3) Authorization Code + PKCE manual demo

**(A) PKCE values (example)**

* `code_verifier`: `abc123abc123abc123abc123abc123abc123abc123`
* `code_challenge`: base64url(SHA256(code_verifier)) → `VbW3Hq2O6x1lN0w1JzvF7m7W0qOBCm9bX4Xh2z5l3bE`

**(B) Get authorization code**

Open the browser to:

```
http://localhost:8000/authorize?response_type=code&client_id=spa-client&redirect_uri=http://localhost:5173/callback&scope=notes.read%20notes.write&state=xyz&code_challenge=VbW3Hq2O6x1lN0w1JzvF7m7W0qOBCm9bX4Xh2z5l3bE&code_challenge_method=S256&login=demo&password=demo
```

This will 302 to `http://localhost:5173/callback?code=...&state=xyz`. If you are not running a SPA, copy the `code` from the URL.

**(C) Exchange code for an access token**

```bash
curl -s -X POST http://localhost:8000/token \
  -H 'Content-Type: application/json' \
  -d '{
    "grant_type":"authorization_code",
    "code":"<PASTE_CODE>",
    "redirect_uri":"http://localhost:5173/callback",
    "client_id":"spa-client",
    "code_verifier":"abc123abc123abc123abc123abc123abc123abc123"
  }'
```

You should receive `access_token`, `expires_in`, `scope`, `token_type`.

**(D) Call the protected API**

```bash
AT="<ACCESS_TOKEN>"
curl -s http://localhost:8001/api/notes -H "Authorization: Bearer $AT"
```

**(E) Create a note (requires `notes.write`)**

```bash
curl -s -X POST 'http://localhost:8001/api/notes?note=hello%20world' \
  -H "Authorization: Bearer $AT"
```

---

## Security Notice

This repository is public and for educational/demo purposes.

* **Do NOT** commit any real secrets, private keys, or user data.
* All configuration must be supplied via **environment variables** (`.env`) or **CI/CD Secrets**.
* Access tokens are short‑lived RS256‑signed JWTs. If you later persist refresh tokens, auth codes, or client secrets, store **hashes only**.
* RSA keys are generated **in-memory** on startup and are **not** persisted in git.

### Suggested `.gitignore`

```gitignore
# ignore real env files
.env
.env.*
*.env

# keep example templates
!.env.example
!**/.env.example

# others
.DS_Store
__pycache__/
*.pyc
*.pem
*.key
*.crt
node_modules/
```

### GitHub Secrets (if using Actions)

Add repository secrets under **Settings → Secrets and variables → Actions**, e.g.:

* `PROD_PUBLIC_ISSUER`, `PROD_JWKS_URL`, `PROD_DB_URL` (if you add a DB)

Reference them in workflows via `${{ secrets.PROD_PUBLIC_ISSUER }}` (never hardcode values in YAML).

---

## If you accidentally committed secrets

1. **Rotate** keys/passwords immediately.
2. Stop tracking real files locally but keep them on disk:

   ```bash
   git rm --cached auth/.env resource/.env
   git commit -m "Stop tracking real .env"
   git push
   ```
3. Rewrite history if secrets were committed before:

   * Use `git filter-repo` or **BFG Repo-Cleaner**
4. For third-party keys, follow the provider’s compromise procedure and revoke.
