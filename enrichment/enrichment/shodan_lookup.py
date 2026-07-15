"""
Shodan enrichment.

Looks up open ports, service banners, and known CVEs associated with an
IP address - useful for spotting exposed or vulnerable infrastructure
tied to an alert.
"""

import os
import shodan

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")


def shodan_lookup(ip_address):
    if not SHODAN_API_KEY:
        return {"error": "SHODAN_API_KEY not configured. Add it to your .env file."}

    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        host = api.host(ip_address)
        return {
            "org": host.get("org"),
            "os": host.get("os"),
            "ports": host.get("ports"),
            "vulns": list(host.get("vulns", [])),
            "hostnames": host.get("hostnames"),
        }
    except shodan.APIError as exc:
        return {"error": str(exc)}
