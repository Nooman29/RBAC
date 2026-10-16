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

    # Isolation Forest anomaly detection — artifacts produced by
    # scripts/train_isolation_forest.py, loaded by app/services/anomaly_service.py
    ISOLATION_FOREST_MODEL_PATH: str = "app/ml/models/isolation_forest.joblib"
    ISOLATION_FOREST_SCALER_PATH: str = "app/ml/models/scaler.joblib"
    ISOLATION_FOREST_THRESHOLD_PATH: str = "app/ml/models/threshold.json"

    # Browser-facing base URL for account and alert email links.
    FRONTEND_URL: str = "http://127.0.0.1:5173"

    # Extra browser origins allowed to call the API (comma-separated), e.g. the
    # frontends of other DSFS modules: "http://localhost:3000,https://attendance.example.com"
    CORS_EXTRA_ORIGINS: str = ""

    model_config = SettingsConfigDict(env_file=".env")


settings = Settings()