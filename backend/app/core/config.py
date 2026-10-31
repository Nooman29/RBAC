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

    # Isolation Forest anomaly detection — the LIVE model's artifacts, loaded by
    # app/services/anomaly_service.py. Every trained version is kept next to them in
    # versions/<version_id>/ and recorded in registry.json (model_registry_service).
    ISOLATION_FOREST_MODEL_PATH: str = "app/ml/models/isolation_forest.joblib"
    ISOLATION_FOREST_SCALER_PATH: str = "app/ml/models/scaler.joblib"
    ISOLATION_FOREST_THRESHOLD_PATH: str = "app/ml/models/threshold.json"

    # Retraining schedule. The background check retrains when the newest version is
    # older than MODEL_RETRAIN_INTERVAL_DAYS; a new version only goes live if it
    # passes the guardrails. Set MODEL_AUTO_RETRAIN=false to retrain only by hand.
    MODEL_AUTO_RETRAIN: bool = True
    MODEL_RETRAIN_INTERVAL_DAYS: int = 7
    MODEL_RETRAIN_CHECK_HOURS: int = 24
    MODEL_RETRAIN_FIRST_CHECK_SECONDS: int = 600

    # Time zone the detection features read clock hours and weekdays in (login hour, off-hours,
    # weekend, live "unusual hour"). Timestamps are still stored in UTC. Changing it changes the
    # model's features, so retrain afterwards.
    BUSINESS_TIMEZONE: str = "Africa/Nairobi"

    # Browser-facing base URL for account and alert email links.
    FRONTEND_URL: str = "http://127.0.0.1:5173"

    # Extra browser origins allowed to call the API (comma-separated), e.g. the
    # frontends of other DSFS modules: "http://localhost:3000,https://attendance.example.com"
    CORS_EXTRA_ORIGINS: str = ""

    # Proxies we run in front of the backend. Each appends the address it received the request
    # from to X-Forwarded-For, so the real client is this many entries from the END; entries
    # before it were written by the client and can be forged. Local compose: 1 (nginx).
    # Production: 2 (Caddy, then nginx). 0 ignores the header.
    TRUSTED_PROXY_HOPS: int = 1

    model_config = SettingsConfigDict(env_file=".env")


settings = Settings()