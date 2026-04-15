from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qs

from flask import request

from .config import COUNTRY_BY_PREFIX, SUSPICIOUS_MARKERS


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


def get_client_ip() -> str:
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        first_ip = forwarded_for.split(",")[0].strip()
        if first_ip:
            return first_ip
    real_ip = request.headers.get("X-Real-IP", "").strip()
    if real_ip:
        return real_ip
    return request.remote_addr or "unknown"


def enrich_ip_context(remote_addr: str, headers: dict[str, str]) -> dict[str, str]:
    try:
        ip_obj = ipaddress.ip_address(remote_addr)
    except ValueError:
        return {
            "geo_country": headers.get("CF-IPCountry", "Unknown"),
            "geo_region": headers.get("X-Region", "Unknown"),
            "geo_city": headers.get("X-City", "Unknown"),
            "ip_scope": "invalid",
        }
    if ip_obj.is_loopback:
        return {
            "geo_country": "Localhost",
            "geo_region": "Loopback",
            "geo_city": "Loopback",
            "ip_scope": "loopback",
        }
    if ip_obj.is_private:
        city = "Internal-LAN"
        if remote_addr.startswith("10."):
            city = "Internal-VPC-A"
        elif remote_addr.startswith("172."):
            city = "Internal-VPC-B"
        return {
            "geo_country": "Private Network",
            "geo_region": "RFC1918",
            "geo_city": city,
            "ip_scope": "private",
        }
    if ip_obj.is_multicast or ip_obj.is_reserved:
        return {
            "geo_country": "Reserved",
            "geo_region": "Reserved",
            "geo_city": "Reserved",
            "ip_scope": "reserved",
        }
    header_country = headers.get("CF-IPCountry") or headers.get("X-Country-Code") or headers.get("X-Appengine-Country")
    header_region = headers.get("X-Region") or headers.get("X-Appengine-Region")
    header_city = headers.get("X-City") or headers.get("X-Appengine-City")
    for prefix, (country, region, city) in COUNTRY_BY_PREFIX.items():
        if remote_addr.startswith(prefix):
            return {
                "geo_country": header_country or country,
                "geo_region": header_region or region,
                "geo_city": header_city or city,
                "ip_scope": "public",
            }
    return {
        "geo_country": header_country or "Unknown",
        "geo_region": header_region or "Unknown",
        "geo_city": header_city or "Unknown",
        "ip_scope": "public",
    }
