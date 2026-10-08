const scanButton = document.getElementById("scanButton");
const urlInput = document.getElementById("urlInput");

const errorMessage = document.getElementById("errorMessage");
const resultSection = document.getElementById("resultSection");

const resultUrl = document.getElementById("resultUrl");
const resultDomain = document.getElementById("resultDomain");
const resultProtocol = document.getElementById("resultProtocol");
const resultPath = document.getElementById("resultPath");
const resultLength = document.getElementById("resultLength");

const resultScore = document.getElementById("resultScore");
const resultVerdict = document.getElementById("resultVerdict");
const resultVerdictMessage = document.getElementById("resultVerdictMessage");

const resultReason = document.getElementById("resultReason");
const riskFactors = document.getElementById("riskFactors");

const riskBar = document.getElementById("riskBar");
const verdictIcon = document.getElementById("verdictIcon");

const dnsStatus = document.getElementById("dnsStatus");

const dnsA = document.getElementById("dnsA");
const dnsAAAA = document.getElementById("dnsAAAA");
const dnsMX = document.getElementById("dnsMX");
const dnsNS = document.getElementById("dnsNS");
const dnsCNAME = document.getElementById("dnsCNAME");

const registeredDomain =
    document.getElementById("registeredDomain");

const domainSubdomain =
    document.getElementById("domainSubdomain");

const domainTLD =
    document.getElementById("domainTLD");


// Scan button
scanButton.addEventListener("click", scanURL);


// Allow pressing Enter
urlInput.addEventListener("keypress", function (event) {

    if (event.key === "Enter") {
        scanURL();
    }

});


async function scanURL() {

    const url = urlInput.value.trim();

    // Clear previous error
    errorMessage.textContent = "";

    // Validate input
    if (!url) {

        errorMessage.textContent = "Please enter a URL.";

        return;
    }


    // Disable button while scanning
    scanButton.disabled = true;
    scanButton.textContent = "Scanning...";


    try {

        const response = await fetch("/api/scan", {

            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                url: url
            })

        });


        const data = await response.json();


        if (!response.ok) {

            throw new Error(data.error || "Something went wrong.");

        }


        displayResult(data);


    } catch (error) {

        errorMessage.textContent = error.message;

    }


    scanButton.disabled = false;
    scanButton.textContent = "Scan URL";

}



function displayResult(data) {

    // Show result section
    resultSection.classList.remove("hidden");


    // URL information
    resultUrl.textContent = data.url;

    resultDomain.textContent = data.domain;

    resultProtocol.textContent = data.protocol;

    resultPath.textContent = data.path || "/";

    resultLength.textContent = data.url_length + " characters";

    // Domain Information
    registeredDomain.textContent =data.domain_info.registered_domain || "-";

    domainSubdomain.textContent =data.domain_info.subdomain || "None";

    domainTLD.textContent =
    data.domain_info.tld
        ? "." + data.domain_info.tld
        : "-";


    // Risk score
    resultScore.textContent = data.risk_score + "/100";


    // Verdict
    resultVerdict.textContent = data.verdict;

    resultVerdictMessage.textContent = data.verdict_message;


    // Risk bar
    riskBar.style.width = data.risk_score + "%";


    // Verdict icon
    if (data.verdict === "HIGH RISK") {

        verdictIcon.textContent = "🚨";

    } else if (data.verdict === "SUSPICIOUS") {

        verdictIcon.textContent = "⚠️";

    } else {

        verdictIcon.textContent = "🛡️";

    }


    // Risk factors
    riskFactors.innerHTML = "";


    if (data.risk_factors.length === 0) {

        riskFactors.innerHTML = `
            <div class="no-risk">
                ✓ No suspicious risk factors detected
            </div>
        `;

    } else {

        data.risk_factors.forEach(function (factor) {

            const factorElement = document.createElement("div");

            factorElement.className = "risk-factor";

            factorElement.innerHTML = `

                <div class="risk-factor-left">

                    <strong>
                        ${factor.feature}
                    </strong>

                    <span>
                        ${factor.reason}
                    </span>

                </div>

                <div class="risk-factor-score">
                    +${factor.score}
                </div>

            `;

            riskFactors.appendChild(factorElement);

        });

    }


    // Analysis reasons
    resultReason.innerHTML = "";


    data.reasons.forEach(function (reason) {

        const reasonElement = document.createElement("div");

        reasonElement.className = "analysis-item";

        reasonElement.textContent = "• " + reason;

        resultReason.appendChild(reasonElement);

    });


    // Scroll to result
    resultSection.scrollIntoView({
        behavior: "smooth"
    });

        // DNS Analysis
    if (data.dns_resolves) {

        dnsStatus.textContent = "✓ Resolves";
        dnsStatus.style.color = "#047857";

    } else {

        dnsStatus.textContent = "✗ Does not resolve";
        dnsStatus.style.color = "#dc2626";

    }


    displayDNSRecords(dnsA, data.dns_records.A);
    displayDNSRecords(dnsAAAA, data.dns_records.AAAA);
    displayDNSRecords(dnsMX, data.dns_records.MX);
    displayDNSRecords(dnsNS, data.dns_records.NS);
    displayDNSRecords(dnsCNAME, data.dns_records.CNAME);

}
function displayDNSRecords(element, records) {

    if (!records || records.length === 0) {

        element.textContent = "No records found";

        return;
    }


    element.innerHTML = "";


    records.forEach(function (record) {

        const recordElement = document.createElement("div");

        recordElement.className = "dns-value";

        recordElement.textContent = record;

        element.appendChild(recordElement);

    });

}