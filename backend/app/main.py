from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.db.database import get_db, Base, engine
from app import models
from app.api.routes import users, roles, auth
from app.models import anomaly

app = FastAPI()

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(roles.router)


@app.get("/health")
def health(db: Session = Depends(get_db)):
    result = db.execute(text("SELECT 1")).scalar()
    return {"status": "ok", "db_check": result}


@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)