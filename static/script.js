// PhishGuard Frontend Controller — Modern Real-Time Analysis Interface

const scanButton = document.getElementById("scanButton");
const urlInput = document.getElementById("urlInput");
const errorMessage = document.getElementById("errorMessage");
const resultSection = document.getElementById("resultSection");
const scanningLoader = document.getElementById("scanningLoader");
const scanTimestamp = document.getElementById("scanTimestamp");

// Target details
const resultUrl = document.getElementById("resultUrl");
const resultDomain = document.getElementById("resultDomain");
const resultProtocol = document.getElementById("resultProtocol");
const resultPath = document.getElementById("resultPath");
const resultLength = document.getElementById("resultLength");

// Verdict elements
const resultScore = document.getElementById("resultScore");
const resultVerdict = document.getElementById("resultVerdict");
const resultVerdictMessage = document.getElementById("resultVerdictMessage");
const verdictPill = document.getElementById("verdictPill");
const verdictIcon = document.getElementById("verdictIcon");
const riskBar = document.getElementById("riskBar");

// Findings and factors
const resultReason = document.getElementById("resultReason");
const riskFactors = document.getElementById("riskFactors");

// DNS elements
const dnsStatus = document.getElementById("dnsStatus");
const dnsA = document.getElementById("dnsA");
const dnsAAAA = document.getElementById("dnsAAAA");
const dnsMX = document.getElementById("dnsMX");
const dnsNS = document.getElementById("dnsNS");
const dnsCNAME = document.getElementById("dnsCNAME");

// Domain & RDAP elements
const registeredDomain = document.getElementById("registeredDomain");
const domainSubdomain = document.getElementById("domainSubdomain");
const domainTLD = document.getElementById("domainTLD");
const domainAge = document.getElementById("domainAge");
const creationDate = document.getElementById("creationDate");
const expirationDate = document.getElementById("expirationDate");
const registrar = document.getElementById("registrar");

// SSL elements
const sslStatus = document.getElementById("sslStatus");
const sslDomainMatch = document.getElementById("sslDomainMatch");
const sslIssuer = document.getElementById("sslIssuer");
const sslSubject = document.getElementById("sslSubject");
const sslValidFrom = document.getElementById("sslValidFrom");
const sslValidUntil = document.getElementById("sslValidUntil");
const sslDaysRemaining = document.getElementById("sslDaysRemaining");
const sslMessage = document.getElementById("sslMessage");

// Event Listeners
if (scanButton) {
    scanButton.addEventListener("click", scanURL);
}

if (urlInput) {
    urlInput.addEventListener("keypress", function (event) {
        if (event.key === "Enter") {
            scanURL();
        }
    });
}

// Preset Pills Demo Buttons
document.querySelectorAll(".preset-pill").forEach((button) => {
    button.addEventListener("click", () => {
        const targetUrl = button.getAttribute("data-url");
        if (targetUrl && urlInput) {
            urlInput.value = targetUrl;
            scanURL();
        }
    });
});

async function scanURL() {
    const rawUrl = urlInput ? urlInput.value.trim() : "";

    // Clear previous errors
    if (errorMessage) {
        errorMessage.textContent = "";
    }

    if (!rawUrl) {
        if (errorMessage) {
            errorMessage.textContent = "Please enter a URL to scan.";
        }
        return;
    }

    // Update UI for loading state
    if (scanButton) {
        scanButton.disabled = true;
        scanButton.querySelector(".btn-text").textContent = "Analyzing...";
    }

    if (scanningLoader) {
        scanningLoader.classList.remove("hidden");
    }

    if (resultSection) {
        resultSection.classList.add("hidden");
    }

    try {
        const response = await fetch("/api/scan", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url: rawUrl })
        });

        const responseText = await response.text();
        let data;

        try {
            data = JSON.parse(responseText);
        } catch (jsonErr) {
            throw new Error("Invalid server response format. Check server logs.");
        }

        if (!response.ok) {
            throw new Error(data.error || `Scan request failed with HTTP ${response.status}.`);
        }

        displayResult(data);

    } catch (error) {
        if (errorMessage) {
            errorMessage.textContent = error.message;
        }
    } finally {
        if (scanButton) {
            scanButton.disabled = false;
            scanButton.querySelector(".btn-text").textContent = "Analyze URL";
        }
        if (scanningLoader) {
            scanningLoader.classList.add("hidden");
        }
    }
}

function displayResult(data) {
    if (!resultSection) return;

    // Show result section
    resultSection.classList.remove("hidden");

    if (scanTimestamp) {
        scanTimestamp.textContent = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    }

    // URL information
    if (resultUrl) resultUrl.textContent = data.url || "-";
    if (resultDomain) resultDomain.textContent = data.domain || "-";
    if (resultProtocol) resultProtocol.textContent = (data.protocol || "").toUpperCase();
    if (resultPath) resultPath.textContent = data.path || "/";
    if (resultLength) resultLength.textContent = `${data.url_length} characters`;

    // Domain Info
    const dInfo = data.domain_info || {};
    if (registeredDomain) registeredDomain.textContent = dInfo.registered_domain || "-";
    if (domainSubdomain) domainSubdomain.textContent = dInfo.subdomain || "None";
    if (domainTLD) domainTLD.textContent = dInfo.tld ? `.${dInfo.tld}` : "-";

    // Domain Registration (RDAP)
    const rdap = data.rdap_info;
    if (rdap && rdap.available) {
        if (rdap.domain_age_days !== null && rdap.domain_age_days !== undefined) {
            const days = rdap.domain_age_days;
            const years = Math.floor(days / 365);
            if (domainAge) {
                domainAge.textContent = years >= 1 ? `${years} years (${days} days)` : `${days} days`;
            }
        } else {
            if (domainAge) domainAge.textContent = "Unavailable";
        }

        if (creationDate) creationDate.textContent = rdap.creation_date || "Unavailable";
        if (expirationDate) expirationDate.textContent = rdap.expiration_date || "Unavailable";
        if (registrar) registrar.textContent = rdap.registrar || "Unavailable";
    } else {
        if (domainAge) domainAge.textContent = "Unavailable";
        if (creationDate) creationDate.textContent = "Unavailable";
        if (expirationDate) expirationDate.textContent = "Unavailable";
        if (registrar) registrar.textContent = "Unavailable";
    }

    // IP & Network Intelligence
    const ipInfo = data.ip_info || {};
    const ipDomainElem = document.getElementById("ipDomain");
    if (ipDomainElem) ipDomainElem.textContent = ipInfo.domain || data.domain || "Unavailable";

    const ipResStatus = document.getElementById("ipResolutionStatus");
    if (ipResStatus) ipResStatus.textContent = ipInfo.resolved ? "Resolved" : "Unresolved / DNS Failed";

    const ipv4List = document.getElementById("ipv4Addresses");
    if (ipv4List) {
        ipv4List.replaceChildren();
        const v4 = ipInfo.ipv4_addresses || [];
        if (v4.length === 0) {
            const li = document.createElement("li");
            li.textContent = "None discovered";
            ipv4List.appendChild(li);
        } else {
            v4.forEach(ip => {
                const li = document.createElement("li");
                li.textContent = ip;
                ipv4List.appendChild(li);
            });
        }
    }

    const ipv6List = document.getElementById("ipv6Addresses");
    if (ipv6List) {
        ipv6List.replaceChildren();
        const v6 = ipInfo.ipv6_addresses || [];
        if (v6.length === 0) {
            const li = document.createElement("li");
            li.textContent = "None discovered";
            ipv6List.appendChild(li);
        } else {
            v6.forEach(ip => {
                const li = document.createElement("li");
                li.textContent = ip;
                ipv6List.appendChild(li);
            });
        }
    }

    const ipMsg = document.getElementById("ipMessage");
    if (ipMsg) ipMsg.textContent = ipInfo.message || "IP network analysis completed.";

    // Geolocation
    const geo = data.geo_info;
    const geoCity = document.getElementById("geoCity");
    const geoRegion = document.getElementById("geoRegion");
    const geoCountry = document.getElementById("geoCountry");
    const geoCountryCode = document.getElementById("geoCountryCode");
    const geoOrg = document.getElementById("geoOrganization");
    const geoASN = document.getElementById("geoASN");

    if (geoCity) geoCity.textContent = geo?.city || "Unavailable";
    if (geoRegion) geoRegion.textContent = geo?.region || "Unavailable";
    if (geoCountry) geoCountry.textContent = geo?.country || "Unavailable";
    if (geoCountryCode) geoCountryCode.textContent = geo?.country_code || "Unavailable";
    if (geoOrg) geoOrg.textContent = geo?.organization || "Unavailable";
    if (geoASN) geoASN.textContent = geo?.asn || "Unavailable";

    // Redirect Analysis
    const redirect = data.redirect_info || {};
    const rCount = document.getElementById("redirectCount");
    const rFinal = document.getElementById("redirectFinalUrl");
    const rDown = document.getElementById("redirectDowngrade");
    const rExcess = document.getElementById("redirectExcessive");
    const rStatus = document.getElementById("redirectStatus");

    if (rCount) rCount.textContent = redirect.redirect_count ?? 0;
    if (rFinal) rFinal.textContent = redirect.final_url || data.url || "Unavailable";
    if (rDown) rDown.textContent = redirect.https_downgrade ? "Yes (Downgrade Detected)" : "No";
    if (rExcess) rExcess.textContent = redirect.excessive_redirects ? "Yes (Limit Reached)" : "No";
    if (rStatus) rStatus.textContent = redirect.error ? "Incomplete / Blocked" : "Completed";

    const findingsList = document.getElementById("redirectFindings");
    if (findingsList) {
        findingsList.replaceChildren();
        (redirect.findings || []).forEach(f => {
            const li = document.createElement("li");
            li.textContent = f;
            findingsList.appendChild(li);
        });
        if (!redirect.findings || redirect.findings.length === 0) {
            const li = document.createElement("li");
            li.textContent = "No redirect anomalies detected.";
            findingsList.appendChild(li);
        }
    }

    const chainList = document.getElementById("redirectChain");
    if (chainList) {
        chainList.replaceChildren();
        const chain = redirect.redirect_chain || [];
        if (chain.length === 0) {
            const li = document.createElement("li");
            li.textContent = "Direct destination reached without hops.";
            chainList.appendChild(li);
        } else {
            chain.forEach(hop => {
                const li = document.createElement("li");
                li.textContent = `[HTTP ${hop.status_code}] ${hop.from} → ${hop.to}`;
                chainList.appendChild(li);
            });
        }
    }

    // SSL / TLS Analysis
    const ssl = data.ssl_info;
    if (ssl && ssl.checked) {
        if (sslStatus) {
            sslStatus.textContent = ssl.valid ? "Valid" : "Invalid / Untrusted";
            sslStatus.style.color = ssl.valid ? "var(--color-safe)" : "var(--color-risk)";
        }
        if (sslDomainMatch) sslDomainMatch.textContent = ssl.domain_matches ? "Yes" : "No";
        if (sslIssuer) sslIssuer.textContent = ssl.issuer || "Unavailable";
        if (sslSubject) sslSubject.textContent = ssl.subject || "Unavailable";
        if (sslValidFrom) sslValidFrom.textContent = ssl.valid_from || "Unavailable";
        if (sslValidUntil) sslValidUntil.textContent = ssl.valid_until || "Unavailable";
        if (sslDaysRemaining) {
            sslDaysRemaining.textContent = (ssl.days_until_expiry !== null && ssl.days_until_expiry !== undefined)
                ? `${ssl.days_until_expiry} days`
                : "Unavailable";
        }
        if (sslMessage) sslMessage.textContent = ssl.message || "TLS certificate verified successfully.";
    } else {
        if (sslStatus) {
            sslStatus.textContent = "Unavailable / Skipped";
            sslStatus.style.color = "var(--text-muted)";
        }
        if (sslDomainMatch) sslDomainMatch.textContent = "Unavailable";
        if (sslIssuer) sslIssuer.textContent = "Unavailable";
        if (sslSubject) sslSubject.textContent = "Unavailable";
        if (sslValidFrom) sslValidFrom.textContent = "Unavailable";
        if (sslValidUntil) sslValidUntil.textContent = "Unavailable";
        if (sslDaysRemaining) sslDaysRemaining.textContent = "Unavailable";
        if (sslMessage) sslMessage.textContent = ssl?.message || "Certificate details could not be retrieved.";
    }

    // Verdict, Score & Risk Bar styling
    const score = Number(data.risk_score) || 0;
    if (resultScore) resultScore.textContent = score;
    if (resultVerdict) resultVerdict.textContent = data.verdict;
    if (resultVerdictMessage) resultVerdictMessage.textContent = data.verdict_message;

    if (riskBar) {
        riskBar.style.width = `${Math.min(Math.max(score, 0), 100)}%`;
    }

    if (verdictPill) {
        verdictPill.classList.remove("verdict-safe", "verdict-suspicious", "verdict-high-risk");
    }

    if (data.verdict === "HIGH RISK") {
        if (verdictIcon) verdictIcon.textContent = "🚨";
        if (verdictPill) verdictPill.classList.add("verdict-high-risk");
        if (riskBar) riskBar.style.backgroundColor = "var(--color-risk)";
    } else if (data.verdict === "SUSPICIOUS") {
        if (verdictIcon) verdictIcon.textContent = "⚠️";
        if (verdictPill) verdictPill.classList.add("verdict-suspicious");
        if (riskBar) riskBar.style.backgroundColor = "var(--color-suspicious)";
    } else {
        if (verdictIcon) verdictIcon.textContent = "🛡️";
        if (verdictPill) verdictPill.classList.add("verdict-safe");
        if (riskBar) riskBar.style.backgroundColor = "var(--color-safe)";
    }

    // Risk Factors breakdown
    if (riskFactors) {
        riskFactors.innerHTML = "";
        const factors = data.risk_factors || [];

        if (factors.length === 0) {
            riskFactors.innerHTML = `
                <div class="no-risk">
                    ✓ No suspicious risk factors detected by active heuristics.
                </div>
            `;
        } else {
            factors.forEach(factor => {
                const el = document.createElement("div");
                el.className = "risk-factor";
                el.innerHTML = `
                    <div class="risk-factor-left">
                        <strong>${escapeHTML(factor.feature)}</strong>
                        <span>${escapeHTML(factor.reason)}</span>
                    </div>
                    <div class="risk-factor-score">
                        +${factor.score}
                    </div>
                `;
                riskFactors.appendChild(el);
            });
        }
    }

    // Heuristic Analysis Reasons
    if (resultReason) {
        resultReason.innerHTML = "";
        (data.reasons || []).forEach(reason => {
            const el = document.createElement("div");
            el.className = "analysis-item";
            el.textContent = `• ${reason}`;
            resultReason.appendChild(el);
        });
    }

    // DNS Analysis
    if (dnsStatus) {
        if (data.dns_resolves) {
            dnsStatus.textContent = "✓ Resolves Successfully";
            dnsStatus.style.color = "var(--color-safe)";
        } else {
            dnsStatus.textContent = "✗ Domain Does Not Resolve";
            dnsStatus.style.color = "var(--color-risk)";
        }
    }

    const records = data.dns_records || {};
    displayDNSRecords(dnsA, records.A);
    displayDNSRecords(dnsAAAA, records.AAAA);
    displayDNSRecords(dnsMX, records.MX);
    displayDNSRecords(dnsNS, records.NS);
    displayDNSRecords(dnsCNAME, records.CNAME);

    // DNS Security Checks
    const dnsSec = data.dns_security || {};
    const dResolves = document.getElementById("dnsSecurityResolves");
    const dIPv4 = document.getElementById("dnsSecurityIPv4");
    const dIPv6 = document.getElementById("dnsSecurityIPv6");
    const dNS = document.getElementById("dnsSecurityNameservers");
    const dMX = document.getElementById("dnsSecurityMail");

    if (dResolves) dResolves.textContent = dnsSec.domain_resolves ? "Yes" : "No";
    if (dIPv4) dIPv4.textContent = dnsSec.has_ipv4 ? "Found" : "None";
    if (dIPv6) dIPv6.textContent = dnsSec.has_ipv6 ? "Found" : "None";
    if (dNS) dNS.textContent = dnsSec.has_nameservers ? "Found" : "None";
    if (dMX) dMX.textContent = dnsSec.has_mail_servers ? "Found" : "None";

    const dnsFindingsList = document.getElementById("dnsSecurityFindings");
    if (dnsFindingsList) {
        dnsFindingsList.replaceChildren();
        const findings = dnsSec.findings || [];
        if (findings.length === 0) {
            const li = document.createElement("li");
            li.textContent = "No DNS configuration anomalies flagged.";
            dnsFindingsList.appendChild(li);
        } else {
            findings.forEach(f => {
                const li = document.createElement("li");
                li.textContent = f;
                dnsFindingsList.appendChild(li);
            });
        }
    }

    // VirusTotal Threat Intelligence
    const vt = data.virustotal_info || {};
    const vtStatus = document.getElementById("vtStatus");
    const vtMessage = document.getElementById("vtMessage");
    const vtStatusStr = String(vt.status || "").toLowerCase();

    if (vtStatus) {
        vtStatus.textContent = (vtStatusStr === "queued" || vtStatusStr === "in-progress")
            ? "Processing"
            : (vtStatusStr === "completed")
                ? "Completed"
                : vtStatusStr || (vt.available ? "Available" : "Unavailable");
    }

    const vtHarmless = document.getElementById("vtHarmless");
    const vtMalicious = document.getElementById("vtMalicious");
    const vtSuspicious = document.getElementById("vtSuspicious");
    const vtUndetected = document.getElementById("vtUndetected");

    if (vtHarmless) vtHarmless.textContent = vt.harmless ?? "-";
    if (vtMalicious) vtMalicious.textContent = vt.malicious ?? "-";
    if (vtSuspicious) vtSuspicious.textContent = vt.suspicious ?? "-";
    if (vtUndetected) vtUndetected.textContent = vt.undetected ?? "-";

    if (vtMessage) {
        if (vtStatusStr === "queued" || vtStatusStr === "in-progress") {
            vtMessage.textContent = "VirusTotal scan is currently processing in queue. Provisional zero detection counts must not be treated as clean results.";
        } else if (vtStatusStr === "completed") {
            vtMessage.textContent = vt.message || "Threat intelligence scan completed.";
        } else {
            vtMessage.textContent = vt.message || "Threat intelligence service unavailable.";
        }
    }

    // Smooth scroll to results
    resultSection.scrollIntoView({ behavior: "smooth", block: "start" });
}

function displayDNSRecords(element, records) {
    if (!element) return;
    element.innerHTML = "";

    if (!records || records.length === 0) {
        element.textContent = "No records found";
        return;
    }

    records.forEach(rec => {
        const div = document.createElement("div");
        div.className = "dns-value";
        div.textContent = rec;
        element.appendChild(div);
    });
}

function escapeHTML(str) {
    if (!str) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}