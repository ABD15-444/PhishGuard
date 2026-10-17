
import math
import re
import ipaddress
from urllib.parse import urlparse


SUSPICIOUS_KEYWORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "password",
    "confirm",
    "secure",
    "update",
    "urgent",
    "bank",
    "wallet",
    "payment",
    "reset",
    "restore",
    "claim",
    "prize",
    "free",
    "support",
    "authenticate",
}


def extract_url_features(url):
    """Extract numerical features from a URL without contacting it."""

    parsed = urlparse(url if "://" in url else "//" + url)
    hostname = (parsed.hostname or "").lower()

    # Normalize the URL for consistent feature extraction.
    normalized_path = parsed.path.rstrip("/") or "/"
    path = normalized_path
    full_url = url.lower().rstrip("/")
    try:
        ipaddress.ip_address(hostname)
        is_ip_address = 1
    except ValueError:
        is_ip_address = 0

    try:
        import tldextract

        domain_parts = tldextract.extract(hostname)
        subdomain_count = (
            len([part for part in domain_parts.subdomain.split(".") if part])
        )
    except Exception:
        subdomain_count = hostname.count(".")

    keyword_count = sum(
        1 for keyword in SUSPICIOUS_KEYWORDS
        if keyword in full_url
    )

    digits = sum(character.isdigit() for character in full_url)
    special_characters = sum(
        not character.isalnum() for character in full_url
    )

    entropy = 0.0
    if full_url:
        for character in set(full_url):
            probability = full_url.count(character) / len(full_url)
            entropy -= probability * math.log2(probability)

    return {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "path_length": len(path),
        "dot_count": full_url.count("."),
        "hyphen_count": full_url.count("-"),
        "at_symbol": int("@" in url),
        "https": int(parsed.scheme.lower() == "https"),
        "ip_address": is_ip_address,
        "subdomain_count": subdomain_count,
        "keyword_count": keyword_count,
        "digit_count": digits,
        "special_character_count": special_characters,
        "has_punycode": int("xn--" in hostname),
        "has_port": int(parsed.port is not None),
        "has_query": int(bool(parsed.query)),
        "entropy": entropy,
        "encoded_character_count": len(
            re.findall(r"%[0-9a-fA-F]{2}", url)
        ),
    }
