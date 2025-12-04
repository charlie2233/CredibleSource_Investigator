# CredibilityChecker

When ur english teacher asked if a url is credble or nah...

Simple Python app (CLI or Tkinter UI) that estimates the credibility of a website using lightweight signals (domain age, HTTPS, author/date, citations, ads/spam heuristics, etc.). It was built and tested with Cursor/Codex, but runs locally with standard Python 3.

## Setup
```bash
pip install requests beautifulsoup4 python-whois
```

## Run
- CLI: `python3 credibility_checker.py <url>` (or run without args to be prompted)
- UI: `python3 credibility_checker.py --ui`

## What it checks
- Domain type bonus for `.edu` / `.gov`
- Domain age via WHOIS
- HTTPS usage
- Author info + publication date tags
- References/citations to external credible domains
- Penalties for many ads or keyword stuffing
- Small reputable-domain whitelist for context

Outputs a 0–100 score, strengths/weaknesses, and a verdict (Credible / Mixed / Not Credible).
