const scanButton =
    document.getElementById("scanButton");


const urlInput =
    document.getElementById("urlInput");


const errorMessage =
    document.getElementById("errorMessage");


const resultSection =
    document.getElementById("resultSection");


const resultUrl =
    document.getElementById("resultUrl");


const resultDomain =
    document.getElementById("resultDomain");


const resultProtocol =
    document.getElementById("resultProtocol");


const resultPath =
    document.getElementById("resultPath");


const resultLength =
    document.getElementById("resultLength");


const resultScore =
    document.getElementById("resultScore");


const resultVerdict =
    document.getElementById("resultVerdict");


const resultVerdictMessage =
    document.getElementById("resultVerdictMessage");


const resultReason =
    document.getElementById("resultReason");



/* --------------------------------
   SCAN BUTTON
-------------------------------- */

scanButton.addEventListener(
    "click",
    scanURL
);



/* --------------------------------
   SCAN URL
-------------------------------- */

async function scanURL() {

    const url =
        urlInput.value.trim();


    errorMessage.textContent = "";


    if (!url) {

        errorMessage.textContent =
            "Please enter a URL.";

        return;
    }


    scanButton.disabled = true;

    scanButton.textContent =
        "Scanning...";


    try {

        const response =
            await fetch(
                "/api/scan",
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({
                        url: url
                    })
                }
            );


        const data =
            await response.json();


        if (!response.ok) {

            throw new Error(
                data.error ||
                "Unable to scan URL."
            );
        }


        displayResult(data);

    }


    catch (error) {

        errorMessage.textContent =
            error.message;

    }


    finally {

        scanButton.disabled = false;

        scanButton.textContent =
            "Scan URL";
    }
}



/* --------------------------------
   DISPLAY RESULT
-------------------------------- */

function displayResult(data) {

    resultSection.classList.remove(
        "hidden"
    );


    resultUrl.textContent =
        data.url;


    resultDomain.textContent =
        data.domain;


    resultProtocol.textContent =
        data.protocol;


    resultPath.textContent =
        data.path || "/";


    resultLength.textContent =
        data.url_length;


    resultScore.textContent =
        data.risk_score + "/100";


    /* NEW: VERDICT */

    resultVerdict.textContent =
        data.verdict;


    /* NEW: VERDICT MESSAGE */

    resultVerdictMessage.textContent =
        data.verdict_message;


    resultReason.textContent =
        data.reasons.join(" | ");
}