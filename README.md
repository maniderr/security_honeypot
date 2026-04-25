# security_honeypot
A Python security honeypot designed to emulate a payment gateway and payment operations platform.

The application exposes realistic bait pages, decoy payment-data endpoints, attacker interaction logging, Geo/IP enrichment, and a dashboard for reviewing captured events.

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

- **Scanner decoy surface**
  - Fake sensitive files at `/.env`, `/.env.backup`, `/.git/config`, `/.git/HEAD`, `/.aws/credentials`, `/.ssh/id_rsa`
  - Fake application bait at `/wp-login.php`, `/wp-admin/`, `/xmlrpc.php`, `/phpmyadmin/`, `/server-status`
  - Fake operations bait at `/actuator/env`, `/actuator/health`, `/admin/config.json`, `/config.json`, `/backup.sql`
  - Path discovery bait at `/robots.txt` and `/sitemap.xml`

- **Attack collection**
  - Captures request path, method, query, body, headers, and form fields
  - Scores suspicious activity using markers such as SQLi, XSS, traversal, and recon behavior
  - Boosts score when scanner decoy paths are accessed
  - Classifies basic attacker personas
  - Tracks per-visitor session via a signed session cookie
  - Measures per-request processing latency

- **Enrichment and analysis**
  - Geo/IP enrichment from forwarded IP and geo headers
  - IP scope classification: loopback, private, public, reserved
  - Dashboard charts for risk, personas, top targeted paths, IP scope mix, and time-series activity
  - Dashboard filters for persona, country, IP scope, minimum risk score, and session identifier
  - Auto-refresh and per-event drilldown with full request metadata
  - Realistic response behavior: randomized latency jitter, MFA-style login teasers

## Project layout

```
security_honeypot/
├── app.py                              entry point
├── honeypot.db                         SQLite database (decoy records + captured events)
├── requirements.txt
├── README.md
├── honeypot/                           Flask application package
│   ├── __init__.py                     app factory
│   ├── config.py                       decoy data, attacker pools, scanner decoy paths
│   ├── analysis/                       request analysis helpers
│   │   ├── scoring.py                  suspicion scoring, persona detection, request parsing
│   │   └── enrichment.py               Geo/IP enrichment and client IP resolution
│   ├── data/                           persistence layer
│   │   ├── db.py                       SQLite initialization, migrations, connection
│   │   └── services.py                 queries, dashboard snapshot, CSV export
│   ├── http/                           HTTP layer
│   │   ├── hooks.py                    request lifecycle hooks, latency, sessions
│   │   └── routes/                     route blueprints
│   │       ├── bait.py                 landing, auth, admin portal
│   │       ├── api.py                  login, search, lookup, refund, export, health
│   │       ├── scanner_decoys.py       fake .env, .git, wp-login, phpmyadmin, etc.
│   │       └── dashboard.py            dashboard rendering and JSON API
│   └── templates/                      Jinja templates
└── tools/                              operator scripts
    ├── simulate_attackers.py           one attacker session
    ├── run_attackers.py                N attacker sessions
    ├── export_logs.py                  CSV export of captured events
    └── reset_data.py                   clears captured events
```

## Installation

```bash
pip install -r requirements.txt
```

## Package structure

The application is organized into focused modules so that routes, database code, logging hooks, templates, and analytics logic are separated.

This structure supports future extension of endpoints, dashboard features, and analysis workflows without relying on a single monolithic file.

## Running the honeypot

```bash
python3 app.py
```

Application root:

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
python3 tools/simulate_attackers.py
```

Run a specific attacker archetype:

```bash
python3 tools/simulate_attackers.py --archetype sqli_operator
```

Run a deterministic simulation using a fixed seed:

```bash
python3 tools/simulate_attackers.py --archetype recon --seed 42
```

Run a single session against a custom target:

```bash
python3 tools/simulate_attackers.py --host 127.0.0.1 --port 5001
```

Available attacker archetypes:

- **`random`**
- **`recon`**
- **`credential_stuffer`**
- **`sqli_operator`**
- **`admin_hunter`**
- **`api_abuser`**
- **`low_slow_intruder`**

Run `N` attacker sessions:

```bash
python3 tools/run_attackers.py 10
```

Optional pause tuning between sessions:

```bash
python3 tools/run_attackers.py 10 --pause-min 0.1 --pause-max 0.5
```

Run `N` sessions using a specific archetype:

```bash
python3 tools/run_attackers.py 10 --archetype api_abuser
```

Run `N` deterministic sessions with a base seed:

```bash
python3 tools/run_attackers.py 5 --archetype credential_stuffer --seed 100
```

Run `N` sessions against a custom target URL:

```bash
python3 tools/run_attackers.py 10 --base-url http://127.0.0.1:5001
```

## Exporting captured data

Export captured logs to CSV:

```bash
python3 tools/export_logs.py
```

Export to a custom path:

```bash
python3 tools/export_logs.py --output reports/session1.csv
```

## Resetting captured data

Clear current captured event logs from the database:

```bash
python3 tools/reset_data.py
```

Skip the confirmation prompt:

```bash
python3 tools/reset_data.py --force
```

This operation clears `event_logs` while preserving the seeded decoy payment records.

## Captured data and analysis

The honeypot stores data in `honeypot.db`.

The dashboard presents:

- **Captured event totals**
- **High-risk event counts**
- **Unique attacker sessions**
- **Average request latency**
- **Attacker persona counts**
- **Country and IP scope summaries**
- **Top targeted paths**
- **Top attacker sessions**
- **Recent captured attacker activity with click-through detail**
- **Time-series chart of activity over the last 60 minutes**
- **Charts for risk, persona, path, and IP scope analysis**

Dashboard filters can be combined through query parameters:

```text
http://127.0.0.1:5000/dashboard?persona=active_intruder&country=Germany&min_score=6
```

Programmatic access:

- **`GET /dashboard/data`** returns the current snapshot as JSON (honors the same filter query parameters).
- **`GET /dashboard/events/<id>`** returns the full captured request for a specific event.

## Suggested workflow

1. Start the honeypot with `python3 app.py`.
2. Generate traffic with `python3 tools/simulate_attackers.py` or `python3 tools/run_attackers.py 10`.
3. Open `http://127.0.0.1:5000/dashboard`.
4. Review captured events, Geo/IP enrichment, and dashboard charts.
5. Use `python3 tools/reset_data.py` to clear captured events before a new test cycle.
