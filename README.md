# Hybrid Intrusion Detection System for E-Voting Platform

## Overview

A real-time **Hybrid Intrusion Detection System (IDS)** built on top of a Django-based electronic voting platform. The system combines rule-based detection with an Isolation Forest machine learning model to identify and block malicious activity such as brute force attacks, SQL injection, duplicate voting, and abnormal traffic patterns.

Every HTTP request passes through a synchronous IDS pipeline inside Django middleware. Threats are detected, scored, and acted upon before the view logic ever runs.

---

## Key Features

- **Hybrid detection** — rule engine + Isolation Forest ML model fused via weighted risk score
- **6 detection rules** — brute force, duplicate vote, blocked IP, SQL injection, rapid requests, admin abuse
- **Real-time blocking** — CRITICAL threats receive HTTP 403 at the middleware layer
- **SOC dashboard** — live charts and alert feed polling every 30 seconds
- **Compliance mapping** — every event tagged with ISO 27001 and NIST CSF controls
- **Audit reports** — management command generates full PDF audit logs
- **No external services** — no Redis, no Celery, no WebSockets; runs entirely in Django + SQLite

---

## IDS Pipeline

```
HTTP Request → LoggingMiddleware
                    ↓
             run_ids_pipeline()
             /              \
      rule_engine        ml_detector
      (6 rules)      (Isolation Forest)
             \              /
              risk_scorer
          (0.6 × rule + 0.4 × ML)
                    ↓
            decision_engine
          LOW → ALLOW
          MEDIUM → ALERT
          HIGH → ALERT + SOC flag
          CRITICAL → BLOCK (403)
                    ↓
           compliance_mapper
          (ISO 27001 + NIST CSF)
                    ↓
          SecurityEvent.save()
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11+, Django 5.0.4 |
| API | Django REST Framework 3.15.1 |
| ML | scikit-learn 1.4.2 (IsolationForest), pandas, NumPy, joblib |
| Frontend | Bootstrap 5.3 CDN, Chart.js 4.x CDN, Vanilla JS |
| Database | SQLite (development) |
| Config | python-decouple (.env) |

---

## Project Structure

```
evoting_ids/
├── manage.py
├── requirements.txt
├── evoting_ids/          ← Django project settings & root URLs
├── accounts/             ← CustomUser model, login, register
├── voting/               ← Election, Candidate, Vote models + views
├── ids_engine/           ← IDS core: middleware, rules, ML, pipeline
│   └── management/
│       └── commands/     ← train_ids_model, evaluate_ids, generate_audit_report
├── dashboard/            ← SOC dashboard HTML + 4 JSON API endpoints
├── templates/            ← base.html
├── synthetic_data/       ← scripts to generate training data
└── ml_models/            ← saved isolation_forest.joblib + scaler.joblib
```

---

## Detection Rules

| Rule | Trigger | Score | Severity |
|---|---|---|---|
| Brute Force | >5 failed logins from same IP in 60s | 80 | HIGH |
| Duplicate Vote | Same user + election already voted | 100 | CRITICAL |
| Blocked IP | IP present in BlockedIP table | 95 | CRITICAL |
| SQL Injection | Regex match on payload (OR 1=1, UNION SELECT, etc.) | 75 | HIGH |
| Rapid Requests | >30 requests/min from same IP | 50 | MEDIUM |
| Admin Abuse | Admin accessed >20 voter records in one session | 70 | HIGH |

---

## Risk Scoring

```
final_score = (0.6 × rule_score) + (0.4 × ml_score)

> 85  →  CRITICAL  →  BLOCK
> 60  →  HIGH      →  ALERT
> 30  →  MEDIUM    →  ALERT
≤ 30  →  LOW       →  ALLOW
```

---

## Compliance Coverage

| Threat | ISO 27001 | NIST CSF |
|---|---|---|
| Brute Force | A.9.4.2 | PR.AC-7 |
| Duplicate Vote | A.12.4.1 | DE.CM-7 |
| SQL Injection | A.14.2.5 | PR.IP-12 |
| Admin Abuse | A.9.2.3 | PR.AC-4 |
| Rapid Requests | A.12.6.1 | DE.CM-1 |
| Blocked IP | A.13.1.3 | PR.AC-3 |
| ML Anomaly | A.16.1.2 | DE.AE-2 |

---

## Setup & Installation

**Prerequisites:** Python 3.11+, pip

```bash
# 1. Clone the repository
git clone https://github.com/your-username/hybrid-ids.git
cd hybrid-ids

# 2. Create and activate virtual environment
python -m venv env
env\Scripts\activate          # Windows
source env/bin/activate       # Linux/Mac

# 3. Install dependencies
pip install -r evoting_ids/requirements.txt

# 4. Create .env file in evoting_ids/
echo SECRET_KEY=your-secret-key-here > evoting_ids/.env
echo DEBUG=True >> evoting_ids/.env

# 5. Run migrations
cd evoting_ids
python manage.py makemigrations
python manage.py migrate

# 6. Create superuser
python manage.py createsuperuser

# 7. Generate synthetic training data and train the ML model
python synthetic_data/generate_normal_logs.py
python synthetic_data/simulate_attacks.py
python manage.py train_ids_model

# 8. Start the server
python manage.py runserver
```

Visit `http://127.0.0.1:8000/` to access the platform and `http://127.0.0.1:8000/dashboard/` for the SOC dashboard.

---

## Dashboard API Endpoints

| Endpoint | Description |
|---|---|
| `GET /api/alerts/latest/` | Last 20 HIGH + CRITICAL events |
| `GET /api/stats/today/` | Total events, blocked count, detection rate |
| `GET /api/risk-distribution/` | Count per risk level today |
| `GET /api/hourly-events/` | Events per hour for last 24 hours |

---

## ML Model Evaluation

Run the evaluation command to compare hybrid detection against rule-only and ML-only baselines:

```bash
python manage.py evaluate_ids
```

Generate a full compliance audit report:

```bash
python manage.py generate_audit_report
```

---

## Important Notes

- Never commit the `.env` file — it is listed in `.gitignore`
- `ml_models/` is excluded from git — regenerate with `train_ids_model` after cloning
- `AUTH_USER_MODEL` is set to `accounts.CustomUser` — do not run migrations before this is configured
- SQLite is used for development only; switch to PostgreSQL for production
