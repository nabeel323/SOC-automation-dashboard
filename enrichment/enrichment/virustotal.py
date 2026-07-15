"""
VirusTotal enrichment.

Queries VirusTotal's v3 API for reputation data on an IP, domain, URL,
or file hash and normalizes the response into a consistent dict.
"""

import os
import base64
import requests

VT_API_KEY = os.getenv("VT_API_KEY")
VT_BASE_URL = "https://www.virustotal.com/api/v3"


def _headers():
    return {"x-apikey": VT_API_KEY}


def _resolve_url(indicator, indicator_type):
    if indicator_type == "ip":
        return f"{VT_BASE_URL}/ip_addresses/{indicator}"
    if indicator_type == "domain":
        return f"{VT_BASE_URL}/domains/{indicator}"
    if indicator_type == "hash":
        return f"{VT_BASE_URL}/files/{indicator}"
    if indicator_type == "url":
        url_id = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
        return f"{VT_BASE_URL}/urls/{url_id}"
    # auto: best-effort guess based on indicator shape
    if all(part.isdigit() for part in indicator.split(".")) and indicator.count(".") == 3:
        return f"{VT_BASE_URL}/ip_addresses/{indicator}"
    if len(indicator) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in indicator):
        return f"{VT_BASE_URL}/files/{indicator}"
    return f"{VT_BASE_URL}/domains/{indicator}"


def check_indicator(indicator, indicator_type="auto"):
    """
    Returns a normalized dict of VirusTotal detection stats for the given
    indicator, or an {"error": ...} dict if the lookup could not be
    completed (e.g. missing API key, rate limit, indicator not found).
    """
    if not VT_API_KEY:
        return {"error": "VT_API_KEY not configured. Add it to your .env file."}

    try:
        url = _resolve_url(indicator, indicator_type)
        response = requests.get(url, headers=_headers(), timeout=10)
        response.raise_for_status()
        data = response.json()

        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attributes.get("reputation"),
            "raw": stats,
        }

    except requests.exceptions.RequestException as exc:
        return {"error": str(exc)}
