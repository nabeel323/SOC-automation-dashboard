# SOC Automation Dashboard

A lightweight Flask web app that automates the first pass of indicator
enrichment during SOC triage. Instead of manually checking an IP, domain,
URL, or file hash across three or four separate tools, this pulls the
same data into one view with a simple risk score.

## Why I built this

During alert triage, the slowest part is usually the manual pivoting -
copy an indicator, open VirusTotal, copy it again, open WHOIS, open
Shodan, repeat. This app automates that first pass so an analyst can
spend their time on judgment calls, not repetitive lookups.

## Features

- **Multi-source enrichment** - queries VirusTotal, WHOIS, and Shodan for
  a single indicator in one request
- **Indicator auto-detection** - accepts IPs, domains, URLs, or file
  hashes and infers the type if not specified
- **Basic risk scoring** - combines VirusTotal detection counts and
  Shodan-reported CVEs into a 0-100 score with a Low/Medium/High label
- **Simple, readable UI** - no dashboard clutter, just the data needed to
  make a triage decision

## Tech stack

- Python 3 / Flask
- VirusTotal API v3
- Shodan API
- `python-whois`

## Setup

```bash
git clone https://github.com/your-username/soc-automation-dashboard.git
cd soc-automation-dashboard
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env            # then add your VT_API_KEY and SHODAN_API_KEY
python app.py
```

Visit `http://localhost:5000`.

You'll need free API keys from [VirusTotal](https://www.virustotal.com/gui/join-us)
and [Shodan](https://account.shodan.io/register) to run enrichment.

## Project structure

```
soc-automation-dashboard/
├── app.py                     # Flask routes
├── enrichment/
│   ├── virustotal.py          # VirusTotal lookups + normalization
│   ├── whois_lookup.py        # WHOIS registration data
│   ├── shodan_lookup.py       # Shodan exposure/CVE data
│   └── scoring.py             # Combines signals into a risk score
├── templates/                 # Jinja2 HTML templates
├── static/style.css
└── requirements.txt
```

## Roadmap / ideas for extending this

- [ ] Add bulk indicator upload (CSV) for enriching multiple IOCs at once
- [ ] Cache lookups to avoid hitting API rate limits on repeat queries
- [ ] Add MITRE ATT&CK technique tagging based on VirusTotal behavior tags
- [ ] Auto-create a ticket in a case management system for high-risk results
- [ ] Add a `/api/analyze` JSON endpoint for use in other automation

## Disclaimer

Built as a personal SOC training/portfolio project. Scoring logic is
intentionally simple and meant as a starting point, not a production
detection engine.
