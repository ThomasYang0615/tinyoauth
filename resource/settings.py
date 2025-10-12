from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    AUTH_ISSUER: str = "http://auth:8000"
    JWKS_URL: str = "http://auth:8000/.well-known/jwks.json"
    AUDIENCE: str = "notes-api"

    class Config:
        env_file = ".env"

settings = Settings()