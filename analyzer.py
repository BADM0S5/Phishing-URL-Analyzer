import re
import urllib.parse

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

    return {
        "original_url": original_url,
        "normalized_url": normalized_url,
        "domain": domain,
        "uses_https": uses_https,
        "has_ip_address": has_ip_address,
        "url_length": url_length,
        "is_long_url": is_long_url,
    }
