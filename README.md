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
  docker-compose.yml
  README.md           # this file
```
