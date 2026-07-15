"""
Basic threat scoring.

Combines signals from VirusTotal and Shodan into a single 0-100 score
and a Low/Medium/High/Clean label. This is deliberately simple - a
starting point you can tune with weights that reflect what matters
most in your own environment (e.g. weighting Shodan CVEs higher for
externally-facing assets).
"""


def calculate_risk_score(results):
    score = 0

    vt = results.get("virustotal") or {}
    malicious = vt.get("malicious", 0) or 0
    suspicious = vt.get("suspicious", 0) or 0

    score += malicious * 10
    score += suspicious * 5

    shodan_data = results.get("shodan") or {}
    vulns = shodan_data.get("vulns") or []
    score += len(vulns) * 5

    score = min(score, 100)

    if score >= 60:
        label = "High"
    elif score >= 25:
        label = "Medium"
    elif score > 0:
        label = "Low"
    else:
        label = "Clean / No detections"

    return score, label
