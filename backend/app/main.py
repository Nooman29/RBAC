from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.db.database import get_db, Base, engine
from app.core.config import settings
from app.core.rate_limit import limit_sensitive_auth
from app import models
from app.api.routes import users, roles, auth, dashboard, service_clients, module_events, audit, model
from app.api.v1.app import v1_app
from app.models import anomaly
from app.models import guardian  # noqa: F401  (registers the guardian_links table)
from app.models import service_client  # noqa: F401  (registers service_clients + authz_audit_logs)
from app.models import module_event  # noqa: F401  (registers module_events)
from app.models import ui_event  # noqa: F401  (registers ui_events)
from app.api.routes import notifications
from app.db.migrations import apply_dsfs_pass1_schema
from app.services import model_registry_service

import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

app = FastAPI()


def _cors_origins() -> list:
    origins = {
        settings.FRONTEND_URL.rstrip("/"),
        "http://127.0.0.1:5173",
        "http://localhost:5173",
    }
    for origin in settings.CORS_EXTRA_ORIGINS.split(","):
        origin = origin.strip().rstrip("/")
        if origin:
            origins.add(origin)
    return sorted(origins)


@app.on_event("startup")
def preload_biometric_models():
    # Loads the anti-spoofing model through DeepFace's own model cache, so the first Face ID check after a
    # restart is not slowed down by loading it. (Importing the model class directly broke when DeepFace
    # moved it into per-engine packages.)
    try:
        from deepface.modules import modeling
        modeling.build_model(task="spoofing", model_name="Fasnet")
        logger.info("Anti-spoofing model preloaded successfully.")
    except Exception:
        logger.exception("Anti-spoofing model failed to preload at startup.")

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Browser-facing routes (user JWT). The router-level dependency rate-limits the
# sensitive auth endpoints per client IP and ignores every other path.
app.include_router(auth.router, dependencies=[Depends(limit_sensitive_auth)])
app.include_router(users.router)
app.include_router(roles.router)
app.include_router(dashboard.router)
app.include_router(notifications.router)
app.include_router(service_clients.router)
app.include_router(module_events.router)
app.include_router(audit.router)
app.include_router(model.router)

# Integration API for other DSFS modules (service-client credentials).
# Mounted as a sub-app so it has its own docs (/api/v1/docs) and error format.
app.mount("/api/v1", v1_app)


@app.get("/health")
def health(db: Session = Depends(get_db)):
    result = db.execute(text("SELECT 1")).scalar()
    return {"status": "ok", "db_check": result}


@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)
    apply_dsfs_pass1_schema(engine)
    model_registry_service.start_scheduler()
    logger.info("Frontend (browser URL): %s", settings.FRONTEND_URL)
    logger.info("Allowed browser origins: %s", ", ".join(_cors_origins()))
    logger.info("Swagger UI (local browser URL): http://127.0.0.1:8000/docs")
    logger.info("Integration API docs: http://127.0.0.1:8000/api/v1/docs")