from pydantic_settings import BaseSettings
from pydantic import AnyHttpUrl

class Settings(BaseSettings):
        ISSUER: str = "http://auth:8000"    # inside docker network
        PUBLIC_ISSUER: AnyHttpUrl | str = "http://localhost:8000"   # for local curl
        ACCESS_TOKEN_TTL_SECONDS: int = 900     # 15 min
        AUTH_CODE_TTL_SECONDS: int = 300

        class Config:
            env_file: ".env"

settings = Settings()