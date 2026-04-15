from __future__ import annotations

DECOY_USERS = {
    "svc-payments": "P@yments2024!",
    "db_admin": "CardVault#2024",
    "reporting": "Analytics!2024",
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
]

COUNTRY_BY_PREFIX = {
    "102.": ("Romania", "Bucharest", "Bucharest"),
    "185.": ("Germany", "Hesse", "Frankfurt"),
    "31.": ("Netherlands", "North Holland", "Amsterdam"),
    "8.": ("United States", "California", "Mountain View"),
    "41.": ("United Kingdom", "England", "London"),
}
