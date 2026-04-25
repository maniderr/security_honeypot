from __future__ import annotations

import ipaddress

from flask import request

from ..config import COUNTRY_BY_PREFIX


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
