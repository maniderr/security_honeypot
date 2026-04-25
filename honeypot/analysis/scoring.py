from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qs

from flask import request

from ..config import SCANNER_DECOY_PATHS, SUSPICIOUS_MARKERS


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_text(payload: str) -> str:
    return payload.lower().strip()


def evaluate_suspicion(path: str, query_string: str, body_text: str, headers: dict[str, str]) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    combined = "\n".join([path, query_string, body_text, json.dumps(headers)]).lower()
    for marker in SUSPICIOUS_MARKERS:
        if marker in combined:
            score += 3
            reasons.append(f"marker:{marker}")
    user_agent = headers.get("User-Agent", "")
    suspicious_agents = ["sqlmap", "nikto", "curl", "python-requests", "gobuster"]
    for agent in suspicious_agents:
        if agent in user_agent.lower():
            score += 2
            reasons.append(f"agent:{agent}")
    high_value_paths = ["/admin", "/dump", "/export", "/cards", "/vault", "/config"]
    if any(segment in path.lower() for segment in high_value_paths):
        score += 2
        reasons.append("high_value_path")
    if path in SCANNER_DECOY_PATHS or any(path.startswith(decoy.rstrip("/") + "/") for decoy in SCANNER_DECOY_PATHS if decoy.endswith("/")):
        score += 4
        reasons.append("scanner_decoy")
    if len(body_text) > 500:
        score += 1
        reasons.append("large_body")
    return score, reasons


def detect_persona(path: str, score: int) -> str:
    lowered = path.lower()
    if score >= 6:
        return "active_intruder"
    if any(term in lowered for term in ["admin", "export", "cards", "refund"]):
        return "credential_stuffer"
    return "curious_recon"


def serialize_headers() -> dict[str, str]:
    return {key: value for key, value in request.headers.items()}


def serialize_form() -> dict[str, Any]:
    if request.form:
        return {key: request.form.getlist(key) if len(request.form.getlist(key)) > 1 else request.form.get(key) for key in request.form.keys()}
    if request.query_string:
        parsed = parse_qs(request.query_string.decode("utf-8", errors="ignore"))
        return {key: values if len(values) > 1 else values[0] for key, values in parsed.items()}
    return {}
