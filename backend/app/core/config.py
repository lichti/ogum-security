from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    APP_ENV: str = "development"
    APP_SECRET_KEY: str = "change-me-in-production"
    LOG_LEVEL: str = "INFO"

    CORS_ORIGINS: list[str] = ["http://localhost:3000"]

    # ArangoDB
    ARANGO_HOST: str = "localhost"
    ARANGO_PORT: int = 8529
    ARANGO_DB: str = "ogum_security"
    ARANGO_USER: str = "root"
    ARANGO_PASSWORD: str = "changeme"

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # Vault — credential store dos providers (US-06.11, ADR-015: sem fallback
    # para credencial em banco)
    VAULT_ENABLED: bool = True
    VAULT_ADDR: str = "http://localhost:8200"
    VAULT_TOKEN: str = "ogum-dev-root"
    VAULT_MOUNT: str = "secret"

    # Redpanda / Kafka
    REDPANDA_BROKERS: str = "localhost:9092"

    # Qdrant
    QDRANT_HOST: str = "localhost"
    QDRANT_PORT: int = 6333

    # Ollama
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "llama3:instruct"

    # Dev / seed
    DEV_MODE: bool = False

    # Auth (Epic 06 — fundação + gate interim US-06.09; ADR-016: default true
    # desde o fechamento da Wave 1; dev desativa via env ou `AUTH_ENABLED=false`)
    AUTH_ENABLED: bool = True
    INTERIM_TOKEN_EXPIRE_DAYS: int = 30
    JWT_ALGORITHM: str = "HS256"  # RS256 (tokens de IdP) chega com a US-06.01
    JWT_SECRET_KEY: str = ""  # fallback: APP_SECRET_KEY
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # OIDC (US-06.01 — login federado; cookies HttpOnly para o browser)
    PUBLIC_BASE_URL: str = "http://localhost:8000"  # redirect_uri do IdP
    FRONTEND_URL: str = "http://localhost:3000"  # redirect pós-login
    ACCESS_COOKIE_NAME: str = "ogum_access"
    REFRESH_COOKIE_NAME: str = "ogum_refresh"

    # Rate limiting por tenant (US-06.13 — security.md §3.1: 100 req/s padrão)
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_PER_SECOND: int = 100
    RATE_LIMIT_WINDOW_SECONDS: int = 1

    # IaC scan — allowlist de hosts do git clone (US-01.19, anti-SSRF)
    IAC_ALLOWED_HOSTS: list[str] = ["github.com", "gitlab.com", "bitbucket.org"]


settings = Settings()
