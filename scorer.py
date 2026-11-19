def calculate_risk(features: dict) -> dict:
    raw_score = 0

    if features.get("has_ip_address", False):
        raw_score += 30

    if not features.get("uses_https", False):
        raw_score += 15

    if features.get("has_at_symbol", False):
        raw_score += 20

    if features.get("excessive_subdomains", False):
        raw_score += 15

    keywords = features.get("suspicious_keywords", [])
    if keywords:
        raw_score += min(25, len(keywords) * 10)

    if features.get("is_long_url", False):
        raw_score += 10

    if features.get("has_double_slash_redirect", False):
        raw_score += 10

    if features.get("has_hyphen_in_domain", False):
        raw_score += 5

    if features.get("suspicious_tld", False):
        raw_score += 15

    # Score bounded between 0 and 100
    risk_score = max(0, min(100, raw_score))

    if risk_score >= 60:
        risk_level = "High"
    elif risk_score >= 30:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
    }
