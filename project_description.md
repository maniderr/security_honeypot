# Security Honeypot — Project Description

## What it is and why I built it

The project is a web-based honeypot that impersonates a payment operations platform. The idea is straightforward: put up a convincing fake application, expose it to the network, and watch what attackers actually do when they think they have found something worth exploiting.

The payment theme is deliberate. A generic "admin panel" attracts mostly automated scanners. A system that looks like it holds card data, refund workflows, and merchant credentials attracts a wider range of behavior — automated tools alongside people who are actively probing. That difference matters when the goal is to study attacker patterns, not just count hits.

---

## Architecture

The application is a Flask app, organized into subpackages rather than a single monolithic file.

```
honeypot/
├── __init__.py          app factory
├── config.py            all static data: decoys, markers, geo profiles, archetypes
├── analysis/            scoring and geo/IP enrichment
├── data/                SQLite layer — schema, migrations, query services
├── http/
│   ├── hooks.py         before/after request lifecycle
│   └── routes/          bait, API, scanner decoys, dashboard
└── templates/           Jinja HTML
```

The separation is practical. The data layer does not know about Flask routes. The analysis layer does not know about persistence. The hooks wire them together on every request. This made it easy to extend each piece without touching the others.

The database is SQLite — single file, no setup, easy to inspect directly with any SQLite viewer. There are two tables: `payment_records` (seeded fake data that decoy API endpoints serve) and `event_logs` (one row per captured attacker request).

---

## The deception surface

The goal is to look real enough that an attacker keeps going. There are three layers of bait:

**Application bait.** A landing page styled as a merchant payment gateway. An authentication page at `/auth/login`. An admin portal at `/portal/admin`. A fake login endpoint, payment search, card lookup, refund, and export endpoints — all returning plausible JSON with seeded fake cardholder records (names, last-four digits, amounts, statuses like `settled`, `flagged`, `chargeback`).

**Scanner decoy paths.** These are paths that automated scanners hit on almost every target: `/.env`, `/.git/config`, `/.aws/credentials`, `/.ssh/id_rsa`, `/wp-login.php`, `/xmlrpc.php`, `/phpmyadmin/`, `/actuator/env`, `/backup.sql`, and others. Each one returns a plausible but fake response — the `.env` file has fake database credentials, the git config has a fake origin URL, the AWS credentials file has a fake access key. Hitting any of these paths adds +4 to that request's suspicion score.

**Fingerprint deception.** Every response going to an attacker includes `Server: nginx/1.24.0` and `X-Powered-By: PHP/8.1.27` headers, even though the app is running on Flask. This is intentional misdirection — a scanner that fingerprints the server will record the wrong stack.

There is also a randomized latency jitter of 20–180 ms injected on every bait request. A real payment gateway has network and processing delay. Without the jitter, a timing-aware tool could distinguish the honeypot from a real service.

---

## How requests are scored

Every captured request gets a suspicion score. The score is built from several independent signals that add up:

- **Marker matching (+3 each):** The full request — path, query string, body, and headers — is scanned against a library of attack signatures. These cover SQL injection (`union select`, `' or 1=1`, `sleep(5)`, `information_schema`), XSS (`<script`, `<img src=x onerror=`), path traversal (both literal `../` and percent-encoded forms like `%2e%2e%2f`, `..%2f`, `%252e%252e%252f`), Log4Shell (`${jndi:`, `${lower:`, `${upper:`), server-side template injection (`{{7*7}}`, `<%= `, `{%print`), NoSQL injection (`$where:`, `$ne:`), AWS metadata endpoint (`169.254.169.254`), and post-exploitation patterns (`powershell -e`, `wget http`, `; nc -e`, `/bin/sh`, `base64 -d`).

- **Suspicious user-agent (+2 each):** Recognized tool signatures in the User-Agent header: `sqlmap`, `nikto`, `gobuster`, `curl`, `python-requests`.

- **High-value path access (+2):** Requests to segments like `/admin`, `/dump`, `/export`, `/cards`, `/vault`, `/config`.

- **Scanner decoy path (+4):** Accessing any of the known scanner target paths listed above.

- **Large body (+1):** Request bodies over 500 bytes, which can indicate fuzzing or payload injection attempts.

A score of 6 or above is flagged as `active_intruder`. Below that, persona detection looks at path patterns to classify the session as `credential_stuffer` or `curious_recon`.

---

## Session tracking

Each visitor gets a signed `hp_session` cookie on their first request. The cookie is set `HttpOnly` and `SameSite=Lax`, which is consistent with how a real application would behave. The session ID is stored alongside every event, so all requests from the same attacker session can be grouped and reviewed together.

---

## The `/login` rate limit

The fake login endpoint enforces a sliding-window rate limit: 5 attempts per 60-second window, keyed on session ID or IP address. On the sixth attempt, it returns `429 Too Many Requests` with a `Retry-After: 60` header. A real application would do the same. The intent is two-fold: it makes the honeypot harder to dismiss as obviously fake, and it catches credential stuffers who exceed the threshold, which they nearly always do.

On a successful login attempt with a valid decoy credential, the endpoint does not return a session token — it returns an MFA challenge instead. The attacker thinks they are one step away. They never get past it.

---

## Geo/IP enrichment

Client IP is resolved from `X-Forwarded-For` with a fallback to the direct socket address. The geo context (country, region, city, IP scope) is populated from forwarded geo headers, which is where enrichment normally happens in a reverse-proxied deployment. IP scope is classified as `loopback`, `private`, `public`, or `reserved` so traffic from local testing can be distinguished from external traffic at a glance.

---

## Dashboard

The dashboard is a single-page HTML template served by Flask. It polls `/dashboard/data` every 10 seconds to refresh without a page reload. The data endpoint returns a JSON snapshot of the current event database.

The dashboard shows:
- Live counters: total events, high-risk events, unique sessions, average latency, number of countries
- Four bar charts: risk score distribution, attacker persona breakdown, top targeted paths, IP scope mix
- A time-series line chart of activity over the last 60 minutes, broken into 5-minute buckets
- A table of recent events, each row clickable for a full drilldown — method, path, status code, score, reasons, raw headers, body, and parsed form fields

Filters can be combined freely: persona, country, IP scope, minimum score, session ID, and a UTC time range. They apply both to the dashboard view and to the CSV export endpoint. The export downloads a filtered CSV of everything the honeypot has captured.

---

## Attacker simulator

The simulator exists because the honeypot needs traffic to demonstrate. It sends real HTTP requests to the running application from different synthetic attacker profiles.

There are seven attacker archetypes, each with a fixed request sequence and a preferred user-agent group:

| Archetype | Behavior |
|---|---|
| `recon` | Browses the landing page, auth page, admin portal, search, and export |
| `credential_stuffer` | Hammers the login endpoint multiple times with different credentials |
| `sqli_operator` | Focuses on the login and search endpoints with SQL injection payloads |
| `admin_hunter` | Targets admin portal and export endpoints directly |
| `api_abuser` | Cycles through the search, card lookup, and refund APIs |
| `low_slow_intruder` | Same steps as recon but using only browser user-agents, mimicking a careful manual attacker |
| `random` | Mixed sequence with any user-agent group |

Each archetype is paired with a geo profile (Amsterdam, Frankfurt, Singapore, London, California, Bucharest) and injects a realistic `X-Forwarded-For` and geo headers so the dashboard shows meaningful country and city data.

Running `python3 tools/run_attackers.py 10` launches 10 sequential attacker sessions, randomly drawing from profiles and archetypes unless overridden with `--archetype`. Sessions can also be made deterministic with a `--seed` argument, which is useful for reproducible demos.

---

## What the data looks like

After 10 simulated attacker sessions, the database has roughly 50–60 events. The dashboard shows a mix of personas, scoring spread across low and high risk, geographic distribution across European and US cities, and path targeting concentrated on `/api/payments/search`, `/portal/admin`, and `/admin/export`.

The CSV export captures the same columns that are stored in `event_logs`: timestamp, IP, method, path, query string, geo fields, score, reasons, status code, persona, session ID, latency, and a response preview. This format is meant to be usable directly in a spreadsheet or fed into a SIEM.

---

## Design decisions worth explaining

**Why SQLite?** No infrastructure dependency. The database is a single file that travels with the project and can be reset, inspected, or copied without any additional tooling. For a honeypot deployed to study a specific event or campaign, this is practical.

**Why a custom canvas chart instead of a charting library?** Keeping dependencies minimal. The dashboard has no JavaScript dependencies at all — no node_modules, no CDN fetches. The charts are drawn directly on HTML canvas elements in about 80 lines of vanilla JS.

**Why fake headers on every response?** A real nginx/PHP stack would send those headers on every response. Not sending them on some responses (e.g., error pages) would create a detectable inconsistency. Consistency in the deception is important.

**Why log dashboard requests separately?** The hooks skip logging for paths under `/dashboard` and `/health`. This keeps the event log clean — it should contain attacker interactions, not the operator reviewing them.
