"""
SOC Automation Dashboard
-------------------------
A lightweight Flask app for enriching security indicators (IPs, domains,
URLs, file hashes) using VirusTotal, WHOIS, and Shodan, then scoring them
so an analyst can quickly triage what needs attention.

Run locally:
    pip install -r requirements.txt
    cp .env.example .env      # then add your API keys
    python app.py
"""

import os
from flask import Flask, render_template, request
from dotenv import load_dotenv

from enrichment.virustotal import check_indicator as vt_check
from enrichment.whois_lookup import whois_lookup
from enrichment.shodan_lookup import shodan_lookup
from enrichment.scoring import calculate_risk_score

load_dotenv()

app = Flask(__name__)


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    indicator = request.form.get("indicator", "").strip()
    indicator_type = request.form.get("indicator_type", "auto")

    if not indicator:
        return render_template("index.html", error="Please enter an indicator to analyze.")

    results = {
        "indicator": indicator,
        "type": indicator_type,
        "virustotal": vt_check(indicator, indicator_type),
        "whois": whois_lookup(indicator) if indicator_type in ("domain", "ip", "auto") else None,
        "shodan": shodan_lookup(indicator) if indicator_type in ("ip", "auto") else None,
    }

    results["risk_score"], results["risk_label"] = calculate_risk_score(results)

    return render_template("results.html", results=results)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
