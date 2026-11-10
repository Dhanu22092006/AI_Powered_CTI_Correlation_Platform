# AI-Powered CTI Correlation Platform

A defensive Cyber Threat Intelligence (CTI) MVP implementing the workflow from the supplied presentation:

**Collect → Normalize → Correlate → Alert**

## What is included

- FastAPI backend with JWT authentication and Admin/Analyst roles
- MongoDB as the primary application database
- Neo4j graph database for threat entities and relationships
- Redis + Celery worker service (worker foundation included; NVD sync currently runs through the API request)
- NVD CVE API integration (no API key required for basic use; an optional key improves rate limits)
- Optional AlienVault OTX integration
- JSON/CSV upload and sample-data loading
- IOC extraction for IPv4/IPv6, domains, URLs, hashes and CVE IDs
- Deduplication, provenance, evidence-based correlation and explainable risk scores
- Alert management, analyst feedback, audit events and CSV/JSON export
- React + TypeScript + Vite dashboard
- Docker Compose setup

This is a defensive hackathon MVP, not a certified production SOC product. Correlations are heuristic and must be reviewed by an analyst. Demo data is explicitly labelled. The MISP connector and fully queued ingestion workflows are not implemented in this version.

## Requirements

- Docker Desktop with Docker Compose
- 4 GB+ RAM recommended
- A modern browser

## Start

1. Copy `.env.example` to `.env`.
2. Change `JWT_SECRET` and the initial admin password.
3. Run:

```bash
docker compose up --build
```

4. Open:
   - Frontend: http://localhost:5173
   - API docs: http://localhost:8000/docs
   - Neo4j Browser: http://localhost:7474

Default demo admin (change in `.env` before first startup):
- Email: `admin@example.com`
- Password: `ChangeThisAdminPassword123!`

The admin account is created only when the users collection is empty.

## Configure integrations

- NVD: set `NVD_API_KEY` optionally.
- OTX: set `OTX_API_KEY` to enable OTX ingestion.
- MISP: this MVP reserves configuration fields but does not claim a completed MISP connector. Add it only when you have a MISP instance and can test the integration.

Never commit `.env`. The provided `.gitignore` excludes it.

## First demo

1. Sign in.
2. Click **Load demo data**.
3. Open **Indicators** and **Alerts**.
4. Open an alert to see its supporting evidence and correlation explanation.
5. Open **Graph** to inspect stored Neo4j relationships.
6. Upload a CSV or JSON file to ingest your own sample intelligence.
7. Use **Sync NVD** to retrieve current CVE records.

## CSV format

The importer accepts a CSV with a `text` column, or columns such as `indicator`, `value`, `type`, `description`, `source`. JSON accepts an array of objects or an object containing `records`.

## Security notes

- Passwords are hashed with Argon2.
- API routes require JWT authentication; Admin-only routes are protected.
- CORS is configurable.
- File size is limited; file contents are parsed as data, never executed.
- Cypher values are parameterized.
- Database credentials and JWT secret come from environment variables.
- This MVP does not fetch arbitrary URLs from uploaded data, reducing SSRF exposure.
- For production, add HTTPS termination, managed secrets, backups, centralized monitoring, stricter network policies, refresh-token rotation, formal threat modelling and independent penetration testing.

## Run backend tests locally

The test suite is in `backend/tests`. With Python 3.12 and dependencies installed:

```bash
cd backend
pip install -r requirements.txt
pytest
```

Tests for database-dependent endpoints require Docker services. Pure IOC/risk tests can run without them.

## Architecture

- `backend/app`: API, ingestion, extraction, scoring and persistence
- `frontend`: React UI
- `docker-compose.yml`: MongoDB, Neo4j, Redis, API, worker and frontend

## Important interpretation

An IOC appearing in the same document as another IOC is not proof that they belong to the same attack. The MVP labels links as inferred and records the source evidence. Risk scores are heuristic prioritization scores, not probabilities of compromise.
