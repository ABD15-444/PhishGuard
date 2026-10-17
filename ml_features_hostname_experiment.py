
from ml_features import extract_url_features


def extract_experimental_features(url):
    """
    Experimental feature extractor.

    Reduces sensitivity to the optional www prefix by
    removing it only for hostname-derived features.
    """
    features = extract_url_features(url)

    from urllib.parse import urlparse

    parsed = urlparse(url if "://" in url else "//" + url)
    hostname = (parsed.hostname or "").lower()

    # Treat www.example.com and example.com consistently
    # for these hostname-derived features.
    normalized_hostname = hostname
    if normalized_hostname.startswith("www."):
        normalized_hostname = normalized_hostname[4:]

    features["hostname_length"] = len(normalized_hostname)
    features["dot_count"] = (
        features["dot_count"]
        - int(hostname.startswith("www."))
    )

    return features
