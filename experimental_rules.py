
from urllib.parse import urlparse
import re

# Hosting platforms that can be used for legitimate sites
# as well as phishing pages. Hosting alone is NOT proof.
HOSTING_SUFFIXES = (
    ".firebaseapp.com",
    ".web.app",
    ".pages.dev",
    ".vercel.app",
    ".netlify.app",
    ".weebly.com",
    ".wixstudio.com",
    ".ukit.me",
    ".dweb.link",
)

SUSPICIOUS_TERMS = (
    "webmail",
    "emailverification",
    "verify-account",
    "secure-login",
    "account-verification",
    "password-reset",
)


def inspect_url(url):
    parsed = urlparse(url if "://" in url else "https://" + url)
    hostname = (parsed.hostname or "").lower()
    full_url = url.lower()
    findings = []
    score = 0
    path_lower = (parsed.path or "").lower()

    # A login-like path is a weak signal, not proof of phishing.
    sensitive_path_terms = (
        "sicher",
        "login",
        "signin",
        "verify",
        "webmail",
        "account",
        "password",
        "authentication",
    )

    matched_path_terms = [
        term for term in sensitive_path_terms
        if term in path_lower
    ]

    if matched_path_terms:
        score += min(5 * len(matched_path_terms), 10)
        findings.append(
            "Sensitive path terms: " + ", ".join(matched_path_terms)
        )


    

    # Keywords in the hostname or URL path
    matched_terms = [term for term in SUSPICIOUS_TERMS if term in full_url]
    if matched_terms:
        score += min(10 * len(matched_terms), 20)
        findings.append("Suspicious terms: " + ", ".join(matched_terms))

    # Hosting platform is context, not evidence by itself
    if any(hostname.endswith(suffix) for suffix in HOSTING_SUFFIXES):
        findings.append("Uses a shared hosting platform; investigate context")

    # Long, hyphen-heavy hostnames may deserve review
    labels = hostname.split(".")
    host_label = labels[0] if labels else ""

    if len(host_label) >= 25:
        score += 5
        findings.append("Unusually long first hostname label")

    if len(re.findall(r"\d", host_label)) >= 6:
        score += 5
        findings.append("Many digits in first hostname label")
    
    # Additional hostname features: weak signals only.
    if host_label.count("-") >= 3:
        score += 3
        findings.append("Hostname contains several hyphens")

    if re.search(r"\d{4,}", host_label):
        score += 3
        findings.append("Hostname contains a long digit sequence")

    if len(hostname) >= 40:
        score += 3
        findings.append("Hostname is unusually long")


    score = min(score, 100)

    if score >= 30:
        verdict = "SUSPICIOUS"
    elif score > 0:
        verdict = "REVIEW"
    else:
        verdict = "NO_ADDITIONAL_SIGNALS"

    return {
        "experimental_score": score,
        "experimental_verdict": verdict,
        "findings": findings,
    }


if __name__ == "__main__":
    samples = [
        "https://elsweb.app/sicher/pages/index.php",
        "https://universityoftennesseeemailverification.ukit.me/",
        "https://cpanel-webmail-n4117iri0d.pages.dev",
        "https://www.wikipedia.org/",
    ]

    for sample in samples:
        print("\nURL:", sample)
        print(inspect_url(sample))
