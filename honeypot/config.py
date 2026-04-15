from __future__ import annotations

DECOY_USERS = {
    "svc-payments": "P@yments2024!",
    "db_admin": "CardVault#2024",
    "reporting": "Analytics!2024",
    "risk_analyst": "RiskOps!2024",
    "merchant_support": "MerchantCare#7",
    "finance_ops": "TreasuryFlow$9",
    "vault_auditor": "VaultAudit!88",
}

DECOY_PAYMENT_RECORDS = [
    {
        "record_id": "pay_1001",
        "cardholder": "Elena M.",
        "last4": "4242",
        "brand": "Visa",
        "amount": 219.94,
        "currency": "USD",
        "status": "settled",
        "email": "elena.merchant@example-payments.com",
    },
    {
        "record_id": "pay_1002",
        "cardholder": "Marco T.",
        "last4": "1881",
        "brand": "Mastercard",
        "amount": 58.11,
        "currency": "EUR",
        "status": "refunded",
        "email": "marco.billing@example-payments.com",
    },
    {
        "record_id": "pay_1003",
        "cardholder": "Priya K.",
        "last4": "0005",
        "brand": "Amex",
        "amount": 910.35,
        "currency": "USD",
        "status": "flagged",
        "email": "priya.ops@example-payments.com",
    },
    {
        "record_id": "pay_1004",
        "cardholder": "Jonas R.",
        "last4": "7714",
        "brand": "Visa",
        "amount": 12.99,
        "currency": "GBP",
        "status": "settled",
        "email": "jonas.accounts@example-payments.com",
    },
    {
        "record_id": "pay_1005",
        "cardholder": "Aisha N.",
        "last4": "6401",
        "brand": "Mastercard",
        "amount": 1499.50,
        "currency": "USD",
        "status": "pending_review",
        "email": "aisha.risk@example-payments.com",
    },
    {
        "record_id": "pay_1006",
        "cardholder": "Mateo L.",
        "last4": "3019",
        "brand": "Visa",
        "amount": 74.20,
        "currency": "EUR",
        "status": "chargeback",
        "email": "mateo.disputes@example-payments.com",
    },
    {
        "record_id": "pay_1007",
        "cardholder": "Sofia P.",
        "last4": "1183",
        "brand": "Amex",
        "amount": 343.89,
        "currency": "USD",
        "status": "authorized",
        "email": "sofia.settlement@example-payments.com",
    },
    {
        "record_id": "pay_1008",
        "cardholder": "Noah D.",
        "last4": "5588",
        "brand": "Discover",
        "amount": 888.00,
        "currency": "USD",
        "status": "refunded",
        "email": "noah.refunds@example-payments.com",
    },
]

SUSPICIOUS_MARKERS = [
    "union select",
    " or 1=1",
    "../",
    "<script",
    "drop table",
    "xp_cmdshell",
    "information_schema",
    "admin'--",
    "../../",
    "sleep(5)",
    "benchmark(",
    "/etc/passwd",
    "169.254.169.254",
    "{{7*7}}",
    "$(whoami)",
    "; cat /etc/passwd",
    "<img src=x onerror=alert(1)>",
    "select @@version",
    "waitfor delay",
]

COUNTRY_BY_PREFIX = {
    "102.": ("Romania", "Bucharest", "Bucharest"),
    "185.": ("Germany", "Hesse", "Frankfurt"),
    "31.": ("Netherlands", "North Holland", "Amsterdam"),
    "8.": ("United States", "California", "Mountain View"),
    "41.": ("United Kingdom", "England", "London"),
    "45.": ("France", "Ile-de-France", "Paris"),
    "91.": ("Sweden", "Stockholm", "Stockholm"),
    "103.": ("Singapore", "Singapore", "Singapore"),
    "154.": ("Poland", "Masovian", "Warsaw"),
}

ATTACKER_GEO_PROFILES = [
    {
        "label": "frankfurt-probe",
        "X-Forwarded-For": "185.220.101.45",
        "X-Country-Code": "DE",
        "X-Region": "Hesse",
        "X-City": "Frankfurt",
    },
    {
        "label": "amsterdam-recon",
        "X-Forwarded-For": "31.7.62.18",
        "X-Country-Code": "NL",
        "X-Region": "North Holland",
        "X-City": "Amsterdam",
    },
    {
        "label": "bucharest-scanner",
        "X-Forwarded-For": "102.143.81.9",
        "X-Country-Code": "RO",
        "X-Region": "Bucharest",
        "X-City": "Bucharest",
    },
    {
        "label": "london-bot",
        "X-Forwarded-For": "41.92.14.201",
        "X-Country-Code": "GB",
        "X-Region": "England",
        "X-City": "London",
    },
    {
        "label": "singapore-api-hunter",
        "X-Forwarded-For": "103.24.77.66",
        "X-Country-Code": "SG",
        "X-Region": "Singapore",
        "X-City": "Singapore",
    },
    {
        "label": "california-cloud-vm",
        "X-Forwarded-For": "8.44.12.190",
        "X-Country-Code": "US",
        "X-Region": "California",
        "X-City": "Mountain View",
    },
]

ATTACKER_USER_AGENTS = {
    "browser": [
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/123.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15",
    ],
    "scanner": [
        "sqlmap/1.8",
        "nikto/2.5.0",
        "gobuster/3.6",
        "zgrab/0.x",
    ],
    "script": [
        "python-requests/2.32",
        "curl/8.0",
        "ReconBot/4.0",
        "Go-http-client/1.1",
    ],
}

ATTACKER_PAYLOADS = {
    "login_usernames": [
        "admin'--",
        "svc-payments",
        "db_admin",
        "finance_ops",
        "' or 1=1 --",
        "vault_auditor",
    ],
    "login_passwords": [
        "anything",
        "Password123!",
        "P@yments2024!",
        "letmein",
        "CardVault#2024",
        "Spring2026!",
    ],
    "search_queries": [
        "' UNION SELECT * FROM cards --",
        "<script>alert(1)</script>",
        "pay_1001",
        "refund",
        "admin'--",
        "{{7*7}}",
        "select @@version",
        "../secrets",
    ],
    "card_last4": ["4242", "1881", "0005", "1183", "5588", "9999"],
    "refund_notes": [
        "../../etc/passwd",
        "manual review override",
        "$(whoami)",
        "merchant escalation ticket",
        "http://169.254.169.254/latest/meta-data/",
    ],
}

ATTACKER_ARCHETYPES = {
    "random": {
        "name": "randomized_intruder",
        "sequence": ["landing", "auth_page", "admin_portal", "login", "search", "card_lookup", "refund", "export"],
        "user_agent_group": ["browser", "scanner", "script"],
    },
    "recon": {
        "name": "curious_recon",
        "sequence": ["landing", "auth_page", "admin_portal", "search", "export"],
        "user_agent_group": ["browser", "script"],
    },
    "credential_stuffer": {
        "name": "credential_stuffer",
        "sequence": ["auth_page", "login", "login", "admin_portal", "login", "search"],
        "user_agent_group": ["browser", "script"],
    },
    "sqli_operator": {
        "name": "sqli_operator",
        "sequence": ["auth_page", "login", "search", "search", "card_lookup", "export"],
        "user_agent_group": ["scanner", "script"],
    },
    "admin_hunter": {
        "name": "admin_hunter",
        "sequence": ["landing", "admin_portal", "export", "search", "login"],
        "user_agent_group": ["browser", "scanner"],
    },
    "api_abuser": {
        "name": "api_abuser",
        "sequence": ["search", "card_lookup", "refund", "search", "card_lookup"],
        "user_agent_group": ["script", "scanner"],
    },
    "low_slow_intruder": {
        "name": "low_and_slow_intruder",
        "sequence": ["landing", "auth_page", "search", "admin_portal", "card_lookup", "export"],
        "user_agent_group": ["browser"],
    },
}
