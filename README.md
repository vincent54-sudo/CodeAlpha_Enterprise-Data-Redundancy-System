# Data Redundancy Removal System

A FastAPI web application for removing duplicate rows from CSV, Excel, and JSON datasets. It includes client registration, administrator access, per-client audit history, downloadable cleaned datasets, and PDF reports.

## Run locally

Requires Python 3.11 or newer.

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Set a unique admin email and password in `.env`, then load the variables and start the server:

```bash
set -a
source .env
set +a
uvicorn main:app --reload
```

Open <http://127.0.0.1:8000>. New registrations create client accounts. The first administrator is provisioned from `ADMIN_EMAIL` and `ADMIN_PASSWORD` at startup.

## Deploy on Render

The included `render.yaml` creates a Python web service with a persistent 1 GB disk for the SQLite database. Persistent disks require a paid Render instance; without persistent storage, accounts and audit records would not survive redeploys.

1. Push this repository to GitHub.
2. In Render, choose **New > Blueprint** and select the GitHub repository.
3. When prompted, set `ADMIN_EMAIL` and a unique `ADMIN_PASSWORD` as secret environment variables.
4. Deploy the Blueprint and open the service URL when the `/health` check passes.

The app listens on Render's `$PORT`, stores its database under `/var/data`, and should be served only over Render's HTTPS URL. Never commit `.env`, database files, or virtual environments.
