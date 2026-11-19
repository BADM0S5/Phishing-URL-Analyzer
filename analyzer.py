import re
import urllib.parse

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "banking",
    "confirm", "signin", "paypal", "free", "urgent", "password", "wallet"
]

SUSPICIOUS_TLDS = (
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".zip", ".click"
)

# IPv4 regex pattern for hostname checks
IPV4_REGEX = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"


def analyze_url(url: str) -> dict:
    original_url = url
    trimmed_url = url.strip()

    # Prepend http if scheme is missing so urlsplit parses host correctly
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", trimmed_url):
        normalized_url = "http://" + trimmed_url
    else:
        normalized_url = trimmed_url

    parsed = urllib.parse.urlsplit(normalized_url)
    domain = parsed.hostname.lower() if parsed.hostname else ""

    uses_https = bool(parsed.scheme.lower() == "https")
    has_ip_address = bool(re.match(IPV4_REGEX, domain))
    url_length = len(original_url)
    is_long_url = bool(url_length > 75)

    # Subdomain count ignoring www and domain+tld
    if has_ip_address or not domain:
        subdomain_count = 0
    else:
        parts = [p for p in domain.split(".") if p and p != "www"]
        subdomain_count = max(0, len(parts) - 2)

    excessive_subdomains = bool(subdomain_count > 2)

    lower_url = normalized_url.lower()
    suspicious_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in lower_url]

    has_at_symbol = bool("@" in original_url)
    has_double_slash_redirect = bool("//" in parsed.path)
    has_hyphen_in_domain = bool("-" in domain)
    suspicious_tld = bool(any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS))

    return {
        "original_url": original_url,
        "normalized_url": normalized_url,
        "domain": domain,
        "uses_https": uses_https,
        "has_ip_address": has_ip_address,
        "url_length": url_length,
        "is_long_url": is_long_url,
        "subdomain_count": subdomain_count,
        "excessive_subdomains": excessive_subdomains,
        "suspicious_keywords": suspicious_keywords,
        "has_at_symbol": has_at_symbol,
        "has_double_slash_redirect": has_double_slash_redirect,
        "has_hyphen_in_domain": has_hyphen_in_domain,
        "suspicious_tld": suspicious_tld,
    }


if __name__ == "__main__":
    test_urls = [
        "https://www.google.com",
        "http://paypal-security-update.xyz/login/verify.php",
        "http://192.168.1.1//account//confirm@secure.com",
        "mybank.portal.verify.online.secure-login.top/account/password",
        "https://sub.domain.example.com/normal-path",
    ]

    for test_url in test_urls:
        data = analyze_url(test_url)
        print(f"URL: {data['original_url']}")
        print(f"Domain: {data['domain']} | HTTPS: {data['uses_https']} | IP: {data['has_ip_address']}")
        print(f"Subdomains: {data['subdomain_count']} | Keywords: {data['suspicious_keywords']}")
        print(f"Suspicious TLD: {data['suspicious_tld']} | Hyphen: {data['has_hyphen_in_domain']}")
        print("-" * 40)
