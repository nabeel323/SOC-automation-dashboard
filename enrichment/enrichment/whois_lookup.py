"""
WHOIS enrichment.

Pulls registration details for a domain (or, where supported, an IP)
so an analyst can quickly gauge indicator age and ownership -
newly-registered domains are a common phishing/C2 red flag.
"""

import whois


def whois_lookup(indicator):
    try:
        record = whois.whois(indicator)
        return {
            "registrar": record.get("registrar"),
            "creation_date": str(record.get("creation_date")),
            "expiration_date": str(record.get("expiration_date")),
            "name_servers": record.get("name_servers"),
            "country": record.get("country"),
        }
    except Exception as exc:
        return {"error": str(exc)}
