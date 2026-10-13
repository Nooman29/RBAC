# Project: RBAC + Biometric Auth + Isolation Forest, evolving into the central
# auth/authorization service for a Digital School Feeding System (DSFS)

Stack: FastAPI, SQLAlchemy (db.query style), PostgreSQL, python-jose, passlib;
React 18 (Vite) frontend; Docker Compose (postgres, backend, nginx frontend).
Repo layout is documented in PROJECT_STRUCTURE.md.

## Hard rules (never violate)
1. The roles "Administrator", "Manager", "Standard User" are used for the
   anomaly-simulation demo. Never rename them or change their existing
   permissions or behaviour. Changes to them may only ADD new things.
2. Do not change existing route paths, request/response shapes, or the
   behaviour/signature of `require_permission`, `user_has_permission`,
   `get_current_user_and_session`. New behaviour goes in NEW functions/routes.
3. Do not modify the anomaly detection (ml/, anomaly_service.py), biometric
   (biometric_service.py), OTP, or frontend code unless the task says so.
4. Scripts and migrations must be idempotent and non-destructive: no dropped
   tables, no data wipes, safe to run twice.
5. All timestamps are naive UTC. Match existing code style and imports.
6. Add dependencies to backend/requirements.txt only if truly needed, and say so.
7. Never put secrets in code or commit .env files.

## Working rules
- Inspect the relevant existing files before editing; match their patterns.
- After changes, actually run the verification commands the task lists
  (docker compose build backend && docker compose up -d, scripts, etc.).
- Do not push, merge, or rebase. Commit on the current branch only.
- Commit message format (multi-section, grouped by subsystem):
    <type>(<scope>): <summary>

    <Subsystem>
    - bullet
    <Subsystem>
    - bullet

    Compatibility
    - what is guaranteed unchanged

    Refs #<issue>
- Final report must list: files changed, commands run with their real output,
  anything NOT verified, assumptions made, and follow-ups noticed but not done.