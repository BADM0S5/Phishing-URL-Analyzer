def calculate_risk(features: dict) -> dict:
    raw_score = 0
    explanations = []
    triggered_count = 0

    if features.get("has_ip_address", False):
        raw_score += 30
        triggered_count += 1
        explanations.append("Host is an IP address instead of a domain name (+30 pts)")

    if not features.get("uses_https", False):
        raw_score += 15
        triggered_count += 1
        explanations.append("URL does not use HTTPS (+15 pts)")

    if features.get("has_at_symbol", False):
        raw_score += 20
        triggered_count += 1
        explanations.append("URL contains '@' symbol (+20 pts)")

    if features.get("excessive_subdomains", False):
        raw_score += 15
        triggered_count += 1
        sub_count = features.get("subdomain_count", 0)
        explanations.append(f"Excessive subdomains detected ({sub_count} subdomains) (+15 pts)")

    keywords = features.get("suspicious_keywords", [])
    if keywords:
        penalty = min(25, len(keywords) * 10)
        raw_score += penalty
        triggered_count += 1
        explanations.append(f"Suspicious keyword(s) found: {', '.join(keywords)} (+{penalty} pts)")

    if features.get("is_long_url", False):
        raw_score += 10
        triggered_count += 1
        url_len = features.get("url_length", 0)
        explanations.append(f"URL is longer than 75 characters ({url_len} chars) (+10 pts)")

    if features.get("has_double_slash_redirect", False):
        raw_score += 10
        triggered_count += 1
        explanations.append("Double slash '//' found in URL path (+10 pts)")

    if features.get("has_hyphen_in_domain", False):
        raw_score += 5
        triggered_count += 1
        explanations.append("Hyphen found in domain name (+5 pts)")

    if features.get("suspicious_tld", False):
        raw_score += 15
        triggered_count += 1
        explanations.append("Suspicious top-level domain (+15 pts)")

    # Score bounded between 0 and 100
    risk_score = max(0, min(100, raw_score))

    if risk_score >= 60:
        risk_level = "High"
    elif risk_score >= 30:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    if not explanations or risk_score == 0:
        explanations = ["No suspicious heuristics detected. URL looks safe."]

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "explanations": explanations,
        "triggered_count": triggered_count,
    }


if __name__ == "__main__":
    sample_features = {
        "uses_https": False,
        "has_ip_address": True,
        "is_long_url": True,
        "url_length": 82,
        "subdomain_count": 0,
        "excessive_subdomains": False,
        "suspicious_keywords": ["login", "verify", "password"],
        "has_at_symbol": True,
        "has_double_slash_redirect": True,
        "has_hyphen_in_domain": False,
        "suspicious_tld": False,
    }
    result = calculate_risk(sample_features)
    print(f"Risk Score: {result['risk_score']} ({result['risk_level']})")
    print(f"Triggered: {result['triggered_count']}")
    for exp in result["explanations"]:
        print(f"- {exp}")
