from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.db.database import get_db, Base, engine
from app.core.config import settings
from app import models
from app.api.routes import users, roles, auth, dashboard
from app.models import anomaly
from app.api.routes import notifications

import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

app = FastAPI()

@app.on_event("startup")
def preload_biometric_models():
    import logging
    logger = logging.getLogger(__name__)
    try:
        from deepface.models.spoofing.FasNet import Fasnet
        Fasnet()
        logger.info("Anti-spoofing model preloaded successfully.")
    except Exception:
        logger.exception("Anti-spoofing model failed to preload at startup.")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        settings.FRONTEND_URL.rstrip("/"),
        "http://127.0.0.1:5173",
        "http://localhost:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(roles.router)
app.include_router(dashboard.router)
app.include_router(notifications.router)


@app.get("/health")
def health(db: Session = Depends(get_db)):
    result = db.execute(text("SELECT 1")).scalar()
    return {"status": "ok", "db_check": result}


@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)
    logger = logging.getLogger(__name__)
    logger.info("Frontend (browser URL): %s", settings.FRONTEND_URL)
    logger.info("Swagger UI (local browser URL): http://127.0.0.1:8000/docs")