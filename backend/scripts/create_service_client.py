"""
Create a service client from the command line (the dashboard UI comes later).

    python -m scripts.create_service_client --name "Payments module" --scopes auth:introspect,authz:check

The secret is printed ONCE; only its hash is stored.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.service_scopes import SERVICE_SCOPES
from app.db.database import SessionLocal
from app.models.service_client import ServiceClient
from app.services.service_client_service import (
    generate_client_id,
    generate_client_secret,
    hash_client_secret,
    invalid_scopes,
    serialize_scopes,
)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", required=True)
    parser.add_argument("--description", default=None)
    parser.add_argument("--scopes", required=True, help=f"comma-separated, from: {', '.join(SERVICE_SCOPES)}")
    args = parser.parse_args()

    scopes = [s.strip() for s in args.scopes.split(",") if s.strip()]
    bad = invalid_scopes(scopes)
    if bad or not scopes:
        sys.exit(f"Invalid scopes: {bad or 'none given'}. Valid: {', '.join(SERVICE_SCOPES)}")

    db = SessionLocal()
    try:
        if db.query(ServiceClient).filter(ServiceClient.name == args.name).first():
            sys.exit(f"A service client named '{args.name}' already exists.")
        secret = generate_client_secret()
        client = ServiceClient(
            client_id=generate_client_id(),
            name=args.name,
            description=args.description,
            secret_hash=hash_client_secret(secret),
            scopes=serialize_scopes(scopes),
            is_active=True,
        )
        db.add(client)
        db.commit()
        print(f"Service client created: {client.name}")
        print(f"  X-Client-Id:     {client.client_id}")
        print(f"  X-Client-Secret: {secret}")
        print(f"  Scopes:          {client.scopes}")
        print("Store the secret now; it cannot be shown again.")
    finally:
        db.close()


if __name__ == "__main__":
    main()