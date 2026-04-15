# security_honeypot
A Python security honeypot that imitates a payment gateway and payment operations platform.

It exposes realistic bait pages, fake payment-data endpoints, attacker interaction logging, Geo/IP enrichment, and a dashboard for reviewing captured events.

## Features

- **Payment-themed deception surface**
  - Landing page that looks like a merchant payment platform
  - Bait authentication page at `GET /auth/login`
  - Bait admin portal at `GET /portal/admin`

- **Decoy APIs and data**
  - Fake login endpoint
  - Fake payment search and card lookup endpoints
  - Fake refund and export endpoints
  - Seeded decoy payment records stored in SQLite

- **Attack collection**
  - Captures request path, method, query, body, headers, and form fields
  - Scores suspicious activity using markers such as SQLi, XSS, traversal, and recon behavior
  - Classifies basic attacker personas

- **Enrichment and analysis**
  - Geo/IP enrichment from forwarded IP and geo headers
  - IP scope classification: loopback, private, public, reserved
  - Dashboard charts for risk, personas, top targeted paths, and IP scope mix

## Project files

- **`app.py`**
  - Thin application entry point

- **`honeypot/__init__.py`**
  - Flask app factory and route registration

- **`honeypot/db.py`**
  - SQLite initialization and database connection helpers

- **`honeypot/analysis.py`**
  - Suspicion scoring, request parsing, and Geo/IP enrichment helpers

- **`honeypot/hooks.py`**
  - Request lifecycle hooks and event logging

- **`honeypot/bait_routes.py`**
  - Bait landing and authentication page routes

- **`honeypot/api_routes.py`**
  - Login, search, lookup, refund, export, and health endpoints

- **`honeypot/dashboard.py`**
  - Dashboard endpoints and rendering

- **`honeypot/services.py`**
  - Query and analytics service layer

- **`honeypot/templates/`**
  - Jinja templates for bait pages and dashboard

- **`simulate_attackers.py`**
  - Runs one attacker session against the honeypot

- **`run_attackers.py`**
  - Runs the attacker simulation for `N` attacker sessions

- **`export_logs.py`**
  - Exports captured event data to CSV for coursework analysis

- **`reset_data.py`**
  - Clears captured event data from the SQLite database

- **`honeypot.db`**
  - SQLite database storing decoy records and captured events

## Installation

```bash
pip install -r requirements.txt
```

## Package structure

The application is now organized into focused modules so that routes, database code, logging hooks, templates, and analytics logic are separated.

This makes it easier to extend the honeypot with more endpoints, dashboard features, and analysis workflows without growing a single large file.

## Running the honeypot

```bash
python3 app.py
```

Then open:

```text
http://127.0.0.1:5000/
```

Dashboard:

```text
http://127.0.0.1:5000/dashboard
```

## Simulating attackers

Run a single attacker session:

```bash
python3 simulate_attackers.py
```

Run a single session against a custom target:

```bash
python3 simulate_attackers.py --host 127.0.0.1 --port 5001
```

Run `N` attacker sessions:

```bash
python3 run_attackers.py 10
```

Optional pause tuning between sessions:

```bash
python3 run_attackers.py 10 --pause-min 0.1 --pause-max 0.5
```

Run `N` sessions against a custom target URL:

```bash
python3 run_attackers.py 10 --base-url http://127.0.0.1:5001
```

## Exporting captured data

Export captured logs to CSV:

```bash
python3 export_logs.py
```

Export to a custom path:

```bash
python3 export_logs.py --output reports/session1.csv
```

## Resetting captured data

Clear current captured event logs from the database:

```bash
python3 reset_data.py
```

Skip the confirmation prompt:

```bash
python3 reset_data.py --force
```

This clears `event_logs` and keeps the seeded decoy payment records intact.

## Captured data and analysis

The honeypot stores data in `honeypot.db`.

The dashboard shows:

- **Captured event totals**
- **High-risk event counts**
- **Attacker persona counts**
- **Country and IP scope summaries**
- **Top targeted paths**
- **Recent captured attacker activity**
- **Charts for risk and behavior analysis**

## Suggested workflow

1. Start the honeypot with `python3 app.py`.
2. Generate traffic with `python3 simulate_attackers.py` or `python3 run_attackers.py 10`.
3. Open `http://127.0.0.1:5000/dashboard`.
4. Review the event table, Geo/IP enrichment, and charts.
5. Use `python3 reset_data.py` to clear captured events before a fresh run.
