# Phishing Email Detection Platform

A cybersecurity class project for assessing phishing risk in fictional emails. The planned web app checks sender claims, message content, links, and attachments. It explains which indicators were found and how they contributed to the score.

**Project status:** Planning. The features and test results below describe the intended implementation and expected behavior.

## How it works

1. Enter a sender address, subject, and message body. Optionally add a URL or upload a sample attachment.
2. Select **Analyze Email** to see the risk score, classification, findings, and recommended next steps.
3. Select **Clear** to reset the form and results.

## Planned implementation

The project uses HTML for the form and results, CSS for the responsive layout, and JavaScript for browser-side analysis. The planned entry point is `index.html`, with styles in `style.css` and detection logic in `app.js`. Once those files are in place, serve the project folder locally and open it in your browser.

| Check | What the results will show |
| --- | --- |
| Sender and message | Urgency, threats, requests for credentials, unusual payment instructions, and mismatches between a claimed organization and the sender domain. |
| Links | Scheme, hostname, domain, and an explanation for each flagged link. Checks cover IP-address hosts, misleading hostnames, unusual structures, and mismatches between a displayed link address and its destination. Links are extracted from plain text, pasted HTML, and the optional URL field. |
| Attachments | Filename, extension, size, SHA-256 hash, and a signature comparison for supported formats. Findings explain risks associated with double extensions, unexpected scripts, and executables. The planned upload limit is 5 MB. |

## Risk scoring

Each triggered category adds points once per email. The results can list multiple findings within a category. The total is capped at 100.

| Indicator | Points |
| --- | ---: |
| Urgency or threats | 15 |
| Request for sensitive information | 20 |
| Sender identity mismatch | 20 |
| Unusual payment request | 15 |
| Suspicious URL characteristics | 15 |
| Misleading link destination | 15 |
| Potentially dangerous attachment | 15 |

| Score | Assessment |
| --- | --- |
| 0–29 | Low risk. Review any findings shown. |
| 30–59 | Medium risk. Review the message and verify the sender. |
| 60–100 | High risk. Avoid interacting with the message and verify it through a separate, trusted channel. |

The score reflects the rules triggered and their assigned weights. A low score leaves the email's legitimacy unverified.

## Test plan

Use fictional messages and harmless sample files. Record the actual findings and scores alongside these expectations and save screenshots for the project report.

| Sample | Expected findings | Expected score |
| --- | --- | --- |
| Routine university announcement | No indicators detected | 0 · Low |
| Urgent password verification | Urgency and credential request | 35 · Medium |
| Fictional bank impersonation with an IP-address link | Sender mismatch and suspicious URL | 35 · Medium |
| Message with a harmless test file named `report.pdf.exe` | Potentially dangerous attachment | 15 · Low |
| Routine message with a sample PDF | PDF signature matches and no indicators are detected | 0 · Low |
| Urgent HTML message with different displayed and destination domains | Urgency and misleading link destination | 30 · Medium |

For the demo, combine an urgent password request, an IP-address URL, and a harmless file named `report.pdf.exe`. The expected score is **65/100 (High)** if only those four categories fire.

## Safety and limitations

The design keeps analysis in the browser. It inspects links as text without visiting them or following redirects, and reads attachments as bytes without executing them, enabling macros, or rendering active content. Use fictional data for testing and keep real email contents and credentials out of the repository.

An ordinary deadline can trigger the urgency rule, while a carefully worded phishing email can evade it. A dangerous-looking attachment can also produce a low overall score on its own, so the individual finding should stay visible. HTTPS and matching file signatures describe properties of a URL or file. They leave its safety unverified.
