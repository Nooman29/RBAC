import os

# Must be set before any app module is imported: Settings() and the engine are built at import time.
os.environ["DATABASE_URL"] = "sqlite://"
os.environ["SECRET_KEY"] = "test-secret-key"
os.environ.setdefault("SMTP_USER", "test@example.com")
os.environ.setdefault("SMTP_PASSWORD", "test-password")

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.database import Base
import app.models  # noqa: F401  registers core tables
import app.models.anomaly  # noqa: F401
import app.models.notification  # noqa: F401
from app.models.user import User
from app.models.role import Role, Permission


@pytest.fixture
def db():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine, autoflush=False)()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture
def make_user(db):
    counter = {"n": 0}

    def _make(roles=(), department="Engineering"):
        counter["n"] += 1
        n = counter["n"]
        user = User(
            username=f"user{n}",
            password="x",
            email=f"user{n}@example.com",
            department=department,
        )
        user.roles.extend(roles)
        db.add(user)
        db.commit()
        db.refresh(user)
        return user

    return _make


@pytest.fixture
def make_role(db):
    def _make(name, permissions=()):
        role = Role(role_name=name)
        for resource, action in permissions:
            role.permissions.append(Permission(resource_name=resource, action_type=action))
        db.add(role)
        db.commit()
        db.refresh(role)
        return role

    return _make
