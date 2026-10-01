# RBAC with ML-based Anomaly Detection

Role-Based Access Control system with multi-factor authentication and an Isolation Forest engine that flags anomalous user sessions in real time.

- **Backend:** FastAPI, SQLAlchemy, PostgreSQL, JWT, OTP over email and face verification (DeepFace)
- **ML engine:** scikit-learn Isolation Forest with per-user z-score features and SHAP explanations (`backend/app/ml`, `backend/scripts`)
- **Frontend:** React and Vite dashboard served by Nginx
- **Runtime:** Docker Compose (PostgreSQL, API, web)

## Repository structure

```
.
├── backend/
│   ├── app/
│   │   ├── api/routes/      # FastAPI route definitions
│   │   ├── core/            # config, JWT security, RBAC dependencies
│   │   ├── ml/              # feature engineering (+ trained artifacts, git-ignored)
│   │   ├── models/          # SQLAlchemy models
│   │   └── services/        # anomaly scoring, sessions, OTP, biometrics, notifications
│   ├── scripts/             # seeding and Isolation Forest training
│   ├── tests/               # pytest suite
│   └── .env.example
├── frontend/                # React and Vite dashboard
├── .github/workflows/ci.yml # pytest and Vite build on every PR
├── docker-compose.yml
└── .env.example
```

## Prerequisites

- Docker Desktop (for the containerised run)
- Python 3.11 and Node.js 22 (for local development and tests)

## 1. Configure environment

No credentials are committed. Copy the templates and fill in real values:

```bash
cp .env.example .env                          # Postgres credentials for docker-compose
cp backend/.env.example backend/.env.docker   # API settings used inside Docker
cp backend/.env.example backend/.env          # API settings for local runs
```

In `backend/.env.docker`, `DATABASE_URL` must use host `db` and the same password as `POSTGRES_PASSWORD` in `.env`. Generate a `SECRET_KEY` with `python -c "import secrets; print(secrets.token_hex(32))"`.

## 2. Build and run with Docker

```bash
docker compose up --build -d
docker compose ps
```

| Service  | URL                          |
|----------|------------------------------|
| Frontend | http://localhost:5173        |
| API docs | http://localhost:8000/docs   |
| Health   | http://localhost:8000/health |

First-time data setup:

```bash
docker compose exec backend python -m scripts.seed_roles_and_permissions
docker compose exec backend python -m scripts.seed_synthetic_data
docker compose exec backend python -m scripts.train_isolation_forest
```

Trained model artifacts are stored in the `ml_models` volume and are never committed.

## 3. Local development (without Docker)

```bash
# backend
cd backend
python -m venv ../venv && ../venv/Scripts/activate   # macOS/Linux: source ../venv/bin/activate
pip install -r requirements.txt --extra-index-url https://download.pytorch.org/whl/cpu
uvicorn app.main:app --reload

# frontend (new terminal)
cd frontend
npm ci
npm run dev
```

## 4. Run tests

```bash
cd backend
pip install -r requirements-ci.txt
pytest -v
```

Tests run against an in-memory SQLite database and never touch PostgreSQL. The same suite and a production frontend build run in GitHub Actions on every pull request.

## Development workflow

- Work is tracked in GitHub Issues under milestones M1 to M4 and shown on the project board.
- Branches use `feature/<issue>-<name>` or `fix/<issue>-<name>` and are created from `main`.
- Commits follow Conventional Commits (`feat`, `fix`, `test`, `chore`, `ci`, `docs`).
- Changes reach `main` only through a pull request that references its issue (`Closes #N`) and passes CI.
