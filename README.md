# BioRisk Sentinel

BioRisk Sentinel is a Flask/Jinja cybersecurity assessment tool for evaluating
fictional biometric-authentication systems in financial environments.

**Live demo:** https://biorisk-sentinel-cloud.onrender.com

It accepts only fictional organisation details and synthetic or aggregate metrics.
It is not a biometric login or identity-verification system and never accepts
biometric images, templates, embeddings, research models, banking records, or
customer data. App-account passwords are securely hashed.

## Features

- Assessor registration, login, logout, and protected workspaces
- Fictional assessment creation with ownership and audit logging
- Reliability, privacy, and authorized simulated-attack assessment sections
- Deterministic composite score, risk band, urgent warnings, findings, and recommendations
- Printable HTML reports
- Local SQLite development and managed PostgreSQL deployment
- Production CSRF protection, secure cookies, and Render configuration

## Run locally

Requirements: Python 3.10+.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python app.py
```

Open http://127.0.0.1:5000. The local database is created at
`instance/biorisk.db`. Check http://127.0.0.1:5000/health for service status.

Run the tests with:

```powershell
python -m unittest discover -s tests -v
```

## Cloud deployment

The application is deployed on Render with Gunicorn and PostgreSQL.
`render.yaml` defines the web service, database connection, generated secret,
and `/health` health check.

Required production environment variables:

- `SECRET_KEY`: a strong generated secret
- `DATABASE_URL`: the managed PostgreSQL connection string
- `FLASK_DEBUG=0`

The production entry point is `wsgi.py`. Do not commit `.env`, credentials,
database files, virtual environments, research notebooks, or models.

## Assessment workflow

1. Register an assessor and sign in.
2. Create an assessment using fictional organisation/application information.
3. Enter aggregate reliability metrics.
4. Complete yes/no privacy controls.
5. Enter results from authorized simulated attacks as aggregate counts.
6. Review scores, risk band, urgent warnings, findings, recommendations, and report.

Biometric type is categorization only; no sample upload or biometric processing
is implemented. The administrator-access question refers to the fictional
system under assessment, not BioRisk Sentinel's own admin role.

## Scoring

- Reliability: 45% authentication accuracy, 30% FAR resistance, 20% FRR resistance,
  and 5% response-time quality.
- Privacy: weighted controls totaling 100.
- Attack resistance: equal-weighted mean of authorized attack detection rates.
- Overall: 35% reliability, 30% privacy, and 35% attack resistance.
- Risk bands: Low (85–100), Medium (70–84), High (50–69), Critical (below 50).

Missing template encryption, raw biometric-data storage, low spoof detection,
high FAR without MFA, and missing audit logging for administrator-accessible
systems can trigger urgent review.

The canonical scoring source is `services/scoring.py`; results are assembled by
`services/results.py` and rendered by Jinja templates.

## Routes

| Route | Purpose |
| --- | --- |
| `/health` | Service health check |
| `/auth/register` | Create an assessor account |
| `/auth/login` | Sign in |
| `/assessments/` | Protected assessment workspace |
| `/assessments/new` | Create an assessment |
| `/assessments/<id>/results` | View scores and findings |
| `/assessments/<id>/report` | Printable report |

## Administration and schema

Create an administrator locally from a trusted terminal:

```powershell
flask --app app create-admin
```

Use a password of at least 12 characters. Public registration always creates
assessor accounts. The prototype currently creates tables at startup; reviewed
Alembic/Flask-Migrate migrations are recommended before production data is
managed at scale.
