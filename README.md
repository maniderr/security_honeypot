# security_honeypot
Simple security honeypot.

How to run
Install deps
pip install -r requirements.txt
Start the honeypot
python3 app.py
Simulate attackers
In a second terminal:
python3 simulate_attackers.py
View analysis
Open:
http://127.0.0.1:5000/dashboard
Notes
The honeypot stores data in honeypot.db.
The dataset is intentionally fake/decoy payment-style data.
The dashboard shows:
event counts
high-risk events
targeted paths
recent captured attacker interactions
