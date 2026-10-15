from flask import Flask, render_template, request, jsonify
from urllib.parse import urlparse, urljoin
import ipaddress
import tldextract
import dns.resolver
import json
import urllib.request
import ssl
import certifi
import socket 
import requests
import re
import os
from dotenv import load_dotenv
load_dotenv()
app = Flask(__name__)


# ========================================
# HOME PAGE
# ========================================
@app.route("/")
def home():
    return render_template("index.html")


# ========================================
# 1. URL LENGTH CHECK
# ========================================
def check_url_length(url):

    length = len(url)

    if length > 200:
        return 20, "URL is extremely long"

    elif length > 100:
        return 10, "URL is unusually long"

    else:
        return 0, "URL length appears normal"


# ========================================
# 2. IP ADDRESS CHECK
# ========================================
def check_ip_address(domain):

    try:

        ipaddress.ip_address(domain)

        return (
            25,
            True,
            "URL uses an IP address instead of a domain name"
        )

    except ValueError:

        return (
            0,
            False,
            "URL uses a domain name"
        )


# ========================================
# 3. @ SYMBOL CHECK
# ========================================
def check_at_symbol(url):

    if "@" in url:

        return (
            20,
            True,
            "URL contains an @ symbol, which may hide the actual destination"
        )

    return (
        0,
        False,
        "URL does not contain an @ symbol"
    )


# ========================================
# 4. SUBDOMAIN CHECK
# ========================================
def check_subdomains(domain):

    extracted = tldextract.extract(domain)

    subdomain = extracted.subdomain

    if not subdomain:

        return (
            0,
            0,
            "URL does not contain subdomains"
        )

    subdomain_parts = subdomain.split(".")

    subdomain_count = len(subdomain_parts)

    if subdomain_count >= 4:

        return (
            15,
            subdomain_count,
            "URL contains a very large number of subdomains"
        )

    elif subdomain_count == 3:

        return (
            10,
            subdomain_count,
            "URL contains multiple subdomains"
        )

    else:

        return (
            0,
            subdomain_count,
            "URL contains a normal number of subdomains"
        )


# ========================================
# 5. SUSPICIOUS TLD CHECK
# ========================================
def check_suspicious_tld(domain):

    suspicious_tlds = {
        "tk",
        "top",
        "xyz",
        "click",
        "gq",
        "ml",
        "cf"
    }

    extracted = tldextract.extract(domain)

    tld = extracted.suffix.lower()

    if tld in suspicious_tlds:

        return (
            10,
            True,
            f"Domain uses a potentially suspicious TLD: .{tld}"
        )

    return (
        0,
        False,
        "Domain uses a common TLD"
    )


# ========================================
# 6. SUSPICIOUS KEYWORD CHECK
# ========================================

def check_suspicious_keywords(url):
    suspicious_keywords = [
        "login",
        "signin",
        "verify",
        "verification",
        "account",
        "secure",
        "security",
        "password",
        "confirm",
        "update",
        "bank",
        "wallet",
        "payment",
        "urgent",
        "prize",
        "claim",
        "reward",
        "support",
        "webmail",
        "delivery",
        "restore",
        "access",
        "validate",
        "alert",
        "free",
        "reset",
        "session",
        "track",
        "details"
    ]

    url_lower = url.lower()

    found_keywords = [
        keyword
        for keyword in suspicious_keywords
        if keyword in url_lower
    ]

    if not found_keywords:
        return (
            0,
            [],
            "No suspicious keywords detected"
        )

    # Maximum 20 points from keyword detection.
    score = min(len(found_keywords) * 5, 20)

    return (
        score,
        found_keywords,
        f"Suspicious keywords detected: {', '.join(found_keywords)}"
    )

# ========================================
# 7. PUNYCODE CHECK
# ========================================
def check_punycode(domain):

    domain_lower = domain.lower()

    if "xn--" in domain_lower:

        return (
            15,
            True,
            "Domain contains Punycode, which may indicate a look-alike domain"
        )

    return (
        0,
        False,
        "Domain does not contain Punycode"
    )
# ========================================
# 8. HTTPS CHECK
# ========================================
def check_https(protocol):

    if protocol == "https":

        return (
            0,
            True,
            "URL uses HTTPS"
        )

    return (
        5,
        False,
        "URL does not use HTTPS"
    )

# ========================================
# DNS CHECK
# ========================================
def check_dns(domain):
    records = {}

    record_types = ["A", "AAAA", "MX", "NS", "CNAME"]

    for record_type in record_types:

        try:
            answers = dns.resolver.resolve(domain, record_type)

            records[record_type] = [
                str(answer) for answer in answers
            ]

        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.exception.Timeout
        ):
            records[record_type] = []

        except Exception:
            records[record_type] = []

    dns_resolves = any(
        len(records[record_type]) > 0
        for record_type in record_types
    )

    return dns_resolves, records


def check_dns(domain):
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["1.1.1.1"]
    resolver.timeout = 3
    resolver.lifetime = 5

    records = {}
    lookup_status = {}

    record_types = ["A", "AAAA", "MX", "NS", "CNAME"]

    for record_type in record_types:
        try:
            answers = resolver.resolve(
                domain,
                record_type,
                lifetime=5
            )

            records[record_type] = [
                str(answer) for answer in answers
            ]
            lookup_status[record_type] = "found"

        except dns.resolver.NoAnswer:
            records[record_type] = []
            lookup_status[record_type] = "no_record"

        except dns.resolver.NXDOMAIN:
            records[record_type] = []
            lookup_status[record_type] = "domain_not_found"

        except dns.resolver.NoNameservers:
            records[record_type] = []
            lookup_status[record_type] = "no_nameservers"

        except dns.exception.Timeout:
            records[record_type] = []
            lookup_status[record_type] = "timeout"

        except Exception:
            records[record_type] = []
            lookup_status[record_type] = "error"

    dns_resolves = (
        lookup_status["A"] == "found"
        or lookup_status["AAAA"] == "found"
    )

    security_checks = {
        "domain_resolves": dns_resolves,
        "has_ipv4": bool(records["A"]),
        "has_ipv6": bool(records["AAAA"]),
        "has_nameservers": bool(records["NS"]),
        "has_mail_servers": bool(records["MX"]),
        "lookup_status": lookup_status,
        "findings": []
    }

    if not dns_resolves:
        security_checks["findings"].append(
            "No IPv4 or IPv6 address record was resolved. "
            "Check the DNS lookup status before drawing conclusions."
        )

    if (
        lookup_status["A"] == "timeout"
        or lookup_status["AAAA"] == "timeout"
    ):
        security_checks["findings"].append(
            "An address lookup timed out; DNS may be "
            "temporarily unavailable."
        )

    if lookup_status["NS"] == "no_nameservers":
        security_checks["findings"].append(
            "DNS returned no usable nameservers for this query."
        )

    return dns_resolves, records, security_checks

def get_domain_information(domain):
    extracted = tldextract.extract(domain)

    return {
        "subdomain": extracted.subdomain,
        "registered_domain": extracted.top_domain_under_public_suffix,
        "tld": extracted.suffix
    }
def get_rdap_information(domain):
    import json
    import urllib.request
    from datetime import datetime, timezone

    result = {
        "available": False,
        "creation_date": None,
        "expiration_date": None,
        "domain_age_days": None,
        "registrar": None,
        "message": "Registration information unavailable"
    }

    try:
        # Extract the registered domain
        extracted = tldextract.extract(domain)
        registered_domain = extracted.top_domain_under_public_suffix

        if not registered_domain:
            result["message"] = "A registered domain could not be identified"
            return result

        # Query the RDAP service
        rdap_url = f"https://rdap.org/domain/{registered_domain}"

        request = urllib.request.Request(
            rdap_url,
            headers={"User-Agent": "PhishGuard/1.0"}
        )

        ssl_context = ssl.create_default_context(
            cafile=certifi.where())

        with urllib.request.urlopen(
            request,
            timeout=8,
            context=ssl_context
        ) as response:
            data = json.loads(response.read().decode("utf-8"))

            # Read registration events
            creation_date = None
            expiration_date = None

        for event in data.get("events", []):
            action = event.get("eventAction", "").lower()
            date_value = event.get("eventDate")

            if action == "registration":
                creation_date = date_value

            elif action == "expiration":
                expiration_date = date_value

        # Format dates and calculate age
        def parse_date(value):
            if not value:
                return None

            try:
                return datetime.fromisoformat(
                    value.replace("Z", "+00:00")
                )
            except (ValueError, TypeError):
                return None

        created = parse_date(creation_date)
        expires = parse_date(expiration_date)

        result["creation_date"] = (
            created.date().isoformat() if created else None
        )

        result["expiration_date"] = (
            expires.date().isoformat() if expires else None
        )

        if created:
            age = datetime.now(timezone.utc) - created
            result["domain_age_days"] = max(0, age.days)

        # Find registrar name
        for entity in data.get("entities", []):
            if "registrar" in entity.get("roles", []):
                for item in entity.get("vcardArray", [None, []])[1]:
                    if (
                        isinstance(item, list)
                        and len(item) >= 4
                        and item[0] == "fn"
                    ):
                        result["registrar"] = item[3]
                        break

                if result["registrar"]:
                    break

        result["available"] = True
        result["message"] = "Registration information retrieved"

    
    except Exception as error:
        print(
            f"RDAP lookup failed for {domain}: "
            f"{type(error).__name__}: {error}"
        )

        result["message"] = (
            "Registration data could not be retrieved. "
            "Check the Flask terminal for details."
        )

    return result


def check_ssl_certificate(domain):
    from datetime import datetime, timezone

    result = {
        "checked": False,
        "valid": False,
        "issuer": None,
        "subject": None,
        "valid_from": None,
        "valid_until": None,
        "days_until_expiry": None,
        "domain_matches": False,
        "message": "Certificate information unavailable"
    }

    try:
        # Remove a trailing dot, if present
        domain = domain.rstrip(".")

        # Connect using normal certificate verification
        context = ssl.create_default_context(cafile=certifi.where())
        print("SSL certificate bundle:", certifi.where())
        print("Checking hostname:", domain)

        with socket.create_connection(
            (domain, 443),
            timeout=5
        ) as connection:

            with context.wrap_socket(
                connection,
                server_hostname=domain
            ) as secure_socket:

                certificate = secure_socket.getpeercert()

        result["checked"] = True
        result["valid"] = True

        # Extract issuer
        issuer_parts = certificate.get("issuer", [])
        issuer_names = []

        for group in issuer_parts:
            for key, value in group:
                if key == "organizationName":
                    issuer_names.append(value)

        result["issuer"] = (
            ", ".join(issuer_names) if issuer_names else "Not provided"
        )

        # Extract subject
        subject_parts = certificate.get("subject", [])
        subject_names = []

        for group in subject_parts:
            for key, value in group:
                if key == "commonName":
                    subject_names.append(value)

        result["subject"] = (
            ", ".join(subject_names) if subject_names else "Not provided"
        )

        # Extract certificate validity dates
        valid_from = certificate.get("notBefore")
        valid_until = certificate.get("notAfter")

        if valid_from:
            start = datetime.fromtimestamp(
                ssl.cert_time_to_seconds(valid_from),
                tz=timezone.utc
            )
            result["valid_from"] = start.date().isoformat()

        if valid_until:
            expiry = datetime.fromtimestamp(
                ssl.cert_time_to_seconds(valid_until),
                tz=timezone.utc
            )

            result["valid_until"] = expiry.date().isoformat()

            days_left = (
                expiry - datetime.now(timezone.utc)
            ).days

            result["days_until_expiry"] = days_left

        # The verified TLS handshake validates hostname matching.
        result["domain_matches"] = True

        result["message"] = "TLS certificate verified successfully"

    except ssl.SSLCertVerificationError as error:
        print(
            f"SSL verification failed for {domain}: {error}"
        )
        result["message"] = (
            "Certificate verification failed. "
            "Check the Flask terminal for details."
        )

    except (socket.timeout, TimeoutError):
        result["message"] = "Connection timed out"

    except (socket.gaierror, ConnectionRefusedError, OSError) as error:
        result["message"] = (
            f"Could not establish a verified TLS connection: {error}"
        )

    except Exception as error:
        print(
        f"SSL analysis failed for {domain}: "
        f"{type(error).__name__}: {error}"
        )
        result["message"] = (
            f"Certificate analysis failed: {type(error).__name__}"
        )

    return result

def get_ip_intelligence(domain):
    """Retrieve IPv4 and IPv6 addresses for a domain."""
    result = {
        "domain": domain,
        "ipv4_addresses": [],
        "ipv6_addresses": [],
        "resolved": False,
        "message": ""
    }

    try:
        addresses = socket.getaddrinfo(
            domain,
            None,
            type=socket.SOCK_STREAM
        )

        for address in addresses:
            ip_version = address[0]
            ip_address = address[4][0]

            if ip_version == socket.AF_INET:
                if ip_address not in result["ipv4_addresses"]:
                    result["ipv4_addresses"].append(ip_address)

            elif ip_version == socket.AF_INET6:
                if ip_address not in result["ipv6_addresses"]:
                    result["ipv6_addresses"].append(ip_address)

        result["resolved"] = bool(
            result["ipv4_addresses"] or result["ipv6_addresses"]
        )

        if result["resolved"]:
            result["message"] = "IP addresses retrieved successfully."
        else:
            result["message"] = "No IP addresses were found."

    except socket.gaierror:
        result["message"] = "The domain could not be resolved."

    except (OSError, ValueError):
        result["message"] = "IP address lookup failed."

    return result

def get_ip_geolocation(ip_address):
    """Retrieve approximate location and network details for a public IP."""

    result = {
        "available": False,
        "ip": ip_address,
        "city": None,
        "region": None,
        "country": None,
        "country_code": None,
        "organization": None,
        "asn": None,
        "message": "Geolocation information unavailable"
    }

    try:
        # Only query public IP addresses
        ip = ipaddress.ip_address(ip_address)

        if not ip.is_global:
            result["message"] = (
                "Geolocation lookup skipped for a non-public IP address."
            )
            return result

        api_url = f"https://ipapi.co/{ip.compressed}/json/"

        response = requests.get(
            api_url,
            timeout=5,
            headers={"User-Agent": "PhishGuard/1.0"}
        )
        response.raise_for_status()

        data = response.json()

        if data.get("error"):
            result["message"] = data.get(
                "reason", "The geolocation service returned an error."
            )
            return result

        result.update({
            "city": data.get("city"),
            "region": data.get("region"),
            "country": data.get("country_name"),
            "country_code": data.get("country_code"),
            "organization": data.get("org"),
            "asn": data.get("asn"),
            "available": True,
            "message": "Geolocation and network information retrieved."
        })

    except (requests.RequestException, ValueError) as error:
        print(f"IP geolocation lookup failed: {error}")
        result["message"] = (
            "The geolocation service could not be reached or returned "
            "invalid data."
        )

    except Exception as error:
        print(f"Unexpected geolocation error: {error}")
        result["message"] = "Geolocation lookup failed."

    return result



# ========================================
# 10. RISK VERDICT
# ========================================
def get_risk_verdict(score):

    if score >= 60:

        return (
            "HIGH RISK",
            "The URL contains multiple suspicious characteristics."
        )

    elif score >= 30:

        return (
            "SUSPICIOUS",
            "The URL contains some characteristics commonly associated with phishing."
        )

    else:

        return (
            "SAFE",
            "No major suspicious characteristics were detected."
        )

def is_safe_public_host(hostname):
    """Reject hosts that resolve to non-public IP addresses."""
    try:
        ip_addresses = socket.getaddrinfo(
            hostname, None, type=socket.SOCK_STREAM
        )

        if not ip_addresses:
            return False

        for address in ip_addresses:
            ip = ipaddress.ip_address(address[4][0])

            if (
                not ip.is_global
                or ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_multicast
                or ip.is_reserved
            ):
                return False

        return True

    except (socket.gaierror, ValueError, OSError):
        return False


def analyze_redirects(url, max_redirects=5):
    """Follow redirects manually and inspect every destination."""
    current_url = url
    redirect_chain = []
    findings = []
    response = None

    result = {
        "checked": True,
        "redirect_count": 0,
        "redirect_chain": [],
        "final_url": url,
        "https_downgrade": False,
        "excessive_redirects": False,
        "error": None,
        "findings": []
    }

    try:
        for step in range(max_redirects + 1):
            parsed = urlparse(current_url)

            if parsed.scheme not in ("http", "https"):
                raise ValueError("Blocked an unsupported URL scheme.")

            if not parsed.hostname:
                raise ValueError("The URL has no valid hostname.")

            if parsed.username or parsed.password:
                raise ValueError("URLs containing embedded credentials are blocked.")

            if not is_safe_public_host(parsed.hostname):
                raise ValueError(
                    "Blocked a destination that is not a verified public host."
                )

            try:
                response = requests.get(
                    current_url,
                    allow_redirects=False,
                    stream=True,
                    timeout=(3, 5),
                    headers={"User-Agent": "PhishGuard/1.0"}
                )

                status_code = response.status_code
                location = response.headers.get("Location")

                if not (300 <= status_code < 400) or not location:
                    result["final_url"] = current_url
                    break

                if step == max_redirects:
                    result["excessive_redirects"] = True
                    findings.append(
                        f"Redirect limit of {max_redirects} reached."
                    )
                    result["final_url"] = current_url
                    break

                next_url = urljoin(current_url, location)
                next_parsed = urlparse(next_url)

                if next_parsed.scheme not in ("http", "https"):
                    raise ValueError(
                        "A redirect attempted to use an unsupported URL scheme."
                    )

                redirect_chain.append({
                    "from": current_url,
                    "to": next_url,
                    "status_code": status_code
                })

                if (
                    parsed.scheme == "https"
                    and next_parsed.scheme == "http"
                ):
                    result["https_downgrade"] = True
                    findings.append(
                        "A redirect downgraded the connection from HTTPS to HTTP."
                    )

                current_url = next_url

            finally:
                if response is not None:
                    response.close()
                    response = None

        result["redirect_count"] = len(redirect_chain)
        result["redirect_chain"] = redirect_chain

        if result["https_downgrade"] and not any(
            "downgraded" in finding for finding in findings
        ):
            findings.append("An HTTPS-to-HTTP downgrade was detected.")

        if not findings:
            findings.append("No suspicious redirect behavior was detected.")

        result["findings"] = findings

    except requests.RequestException as error:
        result["error"] = "Redirect request failed or timed out."
        result["findings"] = [
            "Redirect analysis could not be completed.",
            "The destination may be unreachable or the request may have timed out."
        ]

    except ValueError as error:
        result["error"] = str(error)
        result["findings"] = [str(error)]

    except Exception:
        result["error"] = "An unexpected error occurred during redirect analysis."
        result["findings"] = [
            "Redirect analysis could not be completed safely."
        ]

    finally:
        if response is not None:
            response.close()

    return result

def check_virustotal(url):
    api_key = os.getenv("VIRUSTOTAL_API_KEY")

    if not api_key:
        return {
            "available": False,
            "message": "VirusTotal API key is not configured."
        }

    headers = {
        "x-apikey": api_key
    }

    try:
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=15
        )

        if response.status_code != 200:
            return {
                "available": False,
                "message": f"VirusTotal submission failed (HTTP {response.status_code})."
            }

        analysis_id = response.json().get("data", {}).get("id")

        if not analysis_id:
            return {
                "available": False,
                "message": "VirusTotal did not return an analysis ID."
            }

        analysis_response = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers,
            timeout=15
        )

        if analysis_response.status_code != 200:
            return {
                "available": False,
                "message": "URL submitted, but its analysis could not be retrieved yet."
            }

        attributes = (
            analysis_response.json()
            .get("data", {})
            .get("attributes", {})
        )

        stats = attributes.get("stats", {})

        return {
            "available": True,
            "status": attributes.get("status", "unknown"),
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "message": "Analysis retrieved successfully."
        }

    except requests.RequestException:
        return {
            "available": False,
            "message": "VirusTotal could not be reached. Try again later."
        }
    except (ValueError, TypeError):
        return {
            "available": False,
            "message": "VirusTotal returned an unexpected response."
        }

# ========================================
# SCAN URL
# ========================================
@app.route("/api/scan", methods=["POST"])
def scan_url():

    # --------------------------------
    # GET REQUEST DATA
    # --------------------------------

    data = request.get_json()

    if not data or "url" not in data:

        return jsonify({
            "error": "URL is required"
        }), 400


    # --------------------------------
    # GET URL
    # --------------------------------

    url = data["url"].strip()


    # --------------------------------
    # CHECK EMPTY URL
    # --------------------------------

    if not url:

        return jsonify({
            "error": "Please enter a URL"
        }), 400


    # --------------------------------
    # ADD HTTPS IF PROTOCOL MISSING
    # --------------------------------

   # Normalize and validate the URL
    url = url.strip()

    if not url:
        return jsonify({"error": "URL is required."}), 400

    parsed_input = urlparse(url)

    if parsed_input.scheme:
        if parsed_input.scheme not in ("http", "https"):
            return jsonify({
                "error": "Unsupported URL scheme. Use HTTP or HTTPS."
            }), 400
    else:
        url = "https://" + url

    parsed_input = urlparse(url)

# Validate hostname and port
    try:
        hostname = parsed_input.hostname
        parsed_input.port  # Raises ValueError for an invalid port
    except ValueError:
        return jsonify({"error": "Invalid hostname or port."}), 400

    if not hostname:
        return jsonify({"error": "URL must contain a hostname."}), 400

# Reject whitespace in the hostname
    if any(character.isspace() for character in hostname):
        return jsonify({"error": "Invalid hostname."}), 400

# Accept valid IP addresses or validate a domain name
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        try:
            ascii_hostname = hostname.rstrip(".").encode("idna").decode("ascii")
        except UnicodeError:
            return jsonify({"error": "Invalid hostname."}), 400

        if len(ascii_hostname) > 253:
            return jsonify({"error": "Invalid hostname."}), 400

        labels = ascii_hostname.split(".")

        if any(
            not label
            or len(label) > 63
            or not re.fullmatch(
                r"[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?",
                label
            )
            for label in labels
        ):
            return jsonify({"error": "Invalid hostname."}), 400

    # --------------------------------
    # PARSE URL
    # --------------------------------

    parsed = urlparse(url)
    domain = parsed.hostname


    # --------------------------------
    # CHECK HOSTNAME
    # --------------------------------

    if not parsed.hostname:

        return jsonify({
            "error": "Invalid URL"
        }), 400

    domain = parsed.hostname
    ip_info = get_ip_intelligence(domain)
    geo_info = None

    if ip_info["ipv4_addresses"]:
        geo_info = get_ip_geolocation(
            ip_info["ipv4_addresses"][0]
        )
    elif ip_info["ipv6_addresses"]:
        geo_info = get_ip_geolocation(
            ip_info["ipv6_addresses"][0]
        )

    # ========================================
    # RUN ALL DETECTION METHODS
    # ========================================

    # --------------------------------
    # URL LENGTH
    # --------------------------------

    length_score, length_reason = \
        check_url_length(url)


    # --------------------------------
    # IP ADDRESS
    # --------------------------------

    ip_score, is_ip, ip_reason = \
        check_ip_address(
            parsed.hostname
        )


    # --------------------------------
    # @ SYMBOL
    # --------------------------------

    at_score, has_at_symbol, at_reason = \
        check_at_symbol(url)


    # --------------------------------
    # SUBDOMAIN
    # --------------------------------

    subdomain_score, subdomain_count, subdomain_reason = \
        check_subdomains(
            parsed.hostname
        )


    # --------------------------------
    # SUSPICIOUS TLD
    # --------------------------------

    tld_score, suspicious_tld, tld_reason = \
        check_suspicious_tld(
            parsed.hostname
        )


    # --------------------------------
    # SUSPICIOUS KEYWORDS
    # --------------------------------

    keyword_score, found_keywords, keyword_reason = \
        check_suspicious_keywords(url)


    # --------------------------------
    # PUNYCODE
    # --------------------------------

    punycode_score, has_punycode, punycode_reason = \
        check_punycode(
            parsed.hostname
        )
    # --------------------------------
    # HTTPS CHECK
    # --------------------------------

    https_score, is_https, https_reason = \
        check_https(parsed.scheme)

    # --------------------------------
    # DNS CHECK
    # --------------------------------
    dns_resolves, dns_records, dns_security = check_dns(
    parsed.hostname)

    domain_info = get_domain_information(parsed.hostname)
    rdap_info = get_rdap_information(parsed.hostname)
    ssl_info = check_ssl_certificate(parsed.hostname)

    redirect_info = analyze_redirects(url)


    # ========================================
    # COMBINE RISK SCORES
    # ========================================

    risk_factors = []

    if length_score > 0:
        risk_factors.append({
            "feature": "URL Length",
            "score": length_score,
            "reason": length_reason
        })

    if ip_score > 0:
        risk_factors.append({
            "feature": "IP Address",
            "score": ip_score,
            "reason": ip_reason
        })

    if at_score > 0:
        risk_factors.append({
            "feature": "@ Symbol",
            "score": at_score,
            "reason": at_reason
        })

    if subdomain_score > 0:
        risk_factors.append({
            "feature": "Subdomains",
            "score": subdomain_score,
            "reason": subdomain_reason
        })

    if tld_score > 0:
        risk_factors.append({
            "feature": "Suspicious TLD",
            "score": tld_score,
            "reason": tld_reason
        })

    if keyword_score > 0:
        risk_factors.append({
            "feature": "Suspicious Keywords",
            "score": keyword_score,
            "reason": keyword_reason
        })
            # Additional risk for combinations of suspicious keywords
    if len(found_keywords) >= 3:
        combination_score = 15

        risk_factors.append({
            "feature": "Phishing Language Combination",
            "score": combination_score,
            "reason": (
                "Multiple suspicious keywords appear together "
                "in the URL."
            )
        })

    if punycode_score > 0:
        risk_factors.append({
            "feature": "Punycode",
            "score": punycode_score,
            "reason": punycode_reason
        })

    if https_score > 0:
        risk_factors.append({
            "feature": "HTTPS",
            "score": https_score,
            "reason": https_reason
        })

    # Calculate the original heuristic score before adding threat intelligence.
    score = min(sum(factor["score"] for factor in risk_factors), 100)
    heuristic_score = score

    # Build explanations before adding VirusTotal findings.
    reasons = [length_reason]

    if is_ip:
        reasons.append(ip_reason)
    if has_at_symbol:
        reasons.append(at_reason)
    if subdomain_count > 0:
        reasons.append(subdomain_reason)
    if suspicious_tld:
        reasons.append(tld_reason)
    if found_keywords:
        reasons.append(keyword_reason)
    if has_punycode:
        reasons.append(punycode_reason)
    if not is_https:
        reasons.append(https_reason)

    # ========================================
    # ENHANCED RISK ENGINE
    # ========================================

    virustotal_info = check_virustotal(url)

    if (
        virustotal_info.get("available")
        and virustotal_info.get("status") == "completed"
    ):
        malicious_count = int(virustotal_info.get("malicious", 0) or 0)
        suspicious_count = int(virustotal_info.get("suspicious", 0) or 0)

        if malicious_count >= 3:
            score = max(score, 85)
            reasons.append(
                f"VirusTotal reported {malicious_count} malicious detections."
            )
            risk_factors.append({
                "feature": "VirusTotal Threat Intelligence",
                "score": max(0, 85 - heuristic_score),
                "reason": (
                    f"VirusTotal reported {malicious_count} "
                    "malicious detections."
                )
            })
        elif malicious_count > 0:
            score = max(score, 60)
            reasons.append(
                f"VirusTotal reported {malicious_count} malicious detection(s)."
            )
            risk_factors.append({
                "feature": "VirusTotal Threat Intelligence",
                "score": max(0, 60 - heuristic_score),
                "reason": (
                    f"VirusTotal reported {malicious_count} "
                    "malicious detection(s)."
                )
            })
        elif suspicious_count > 0:
            score = max(score, 30)
            reasons.append(
                f"VirusTotal reported {suspicious_count} suspicious detection(s)."
            )
            risk_factors.append({
                "feature": "VirusTotal Threat Intelligence",
                "score": max(0, 30 - heuristic_score),
                "reason": (
                    f"VirusTotal reported {suspicious_count} "
                    "suspicious detection(s)."
                )
            })

    score = min(max(score, 0), 100)
    verdict, verdict_message = get_risk_verdict(score)

    if score > heuristic_score:
        verdict_message += (
            " The final score also incorporates VirusTotal threat intelligence."
        )

    # ========================================
    # RETURN RESULT
    # ========================================

    return jsonify({
        "message": "URL analyzed successfully",
        "url": url,
        "domain": parsed.hostname,
        "domain_info": domain_info,
        "rdap_info": rdap_info,
        "ssl_info": ssl_info,
        "protocol": parsed.scheme,
        "path": parsed.path,
        "url_length": len(url),
        "risk_score": score,
        "dns_resolves": dns_resolves,
        "dns_records": dns_records,
        "dns_security": dns_security,
        "redirect_info": redirect_info,
        "reasons": reasons,
        "is_ip_address": is_ip,
        "ip_info": ip_info,
        "geo_info": geo_info,
        "has_at_symbol": has_at_symbol,
        "subdomain_count": subdomain_count,
        "suspicious_tld": suspicious_tld,
        "found_keywords": found_keywords,
        "has_punycode": has_punycode,
        "is_https": is_https,
        "risk_factors": risk_factors,
        "verdict": verdict,
        "verdict_message": verdict_message,
        "virustotal_info": virustotal_info,
    })


# ========================================
# START SERVER
# ========================================
if __name__ == "__main__":

    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )