# Phishing URL Analyzer

A simple web application built with Python and Streamlit to detect potentially malicious phishing URLs. It analyzes URL structure and common lexical patterns, calculates a weighted risk score from 0 to 100, and displays a breakdown of flagged rules.

## Features

- URL scheme normalization (adds http:// if missing)
- Checks for raw IP addresses used as hostnames
- Checks for HTTPS protocol usage
- Flags long URLs (> 75 characters) and excessive subdomains (> 2)
- Scans for common phishing keywords (e.g., login, verify, paypal)
- Flags suspicious patterns like '@' symbols, double slash redirects, hyphens, and high-risk TLDs
- Weighted risk score and classification (Low, Medium, High)
- Streamlit dashboard with preset test URLs, breakdown table, and scan history with CSV export

## Setup and Running

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Run the application:
   ```bash
   streamlit run app.py
   ```

## Git Branches

- `main`: Main integrated codebase
- `feature/url-analysis`: URL parsing and pattern detection (`analyzer.py`)
- `feature/risk-scoring`: Risk scoring engine (`scorer.py`)
- `feature/dashboard`: Streamlit frontend interface (`app.py`)
