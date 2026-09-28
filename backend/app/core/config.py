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

    # Auth (Epic 06 — Sprint 1 fundação + US-06.09 gate interim)
    AUTH_ENABLED: bool = False
    INTERIM_TOKEN_EXPIRE_DAYS: int = 30
    JWT_ALGORITHM: str = "HS256"  # RS256 (tokens de IdP) chega com a US-06.01
    JWT_SECRET_KEY: str = ""  # fallback: APP_SECRET_KEY
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7


settings = Settings()
