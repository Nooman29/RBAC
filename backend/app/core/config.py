from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    DATABASE_URL: str
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # Biometric settings
    BIOMETRIC_MODEL: str = "Facenet512"
    BIOMETRIC_DETECTOR: str = "retinaface"
    BIOMETRIC_DISTANCE_THRESHOLD: float = 0.30

    # SMTP (OTP)
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USER: str
    SMTP_PASSWORD: str
    OTP_EXPIRY_SECONDS: int = 300

    # Pending-auth token (short-lived, issued after password check, before 2nd factor)
    PENDING_TOKEN_EXPIRE_SECONDS: int = 300

    model_config = SettingsConfigDict(env_file=".env")


settings = Settings()