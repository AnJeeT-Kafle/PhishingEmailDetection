# Phishing Email Detection Platform

A cybersecurity class project that evaluates potential phishing indicators in fictional email samples and explains the risk assessment. Analysis runs locally in the browser using JavaScript.

**Project status:** Implemented and integrated into `main`. The browser interface and detection engine are functional.

## Getting started

Requirements: Node.js 20 or newer and Python 3.

```bash
git clone https://github.com/AnJeeT-Kafle/PhishingEmailDetection.git
cd PhishingEmailDetection
npm test
python3 -m http.server 8000 --bind 127.0.0.1
```

Open [http://localhost:8000](http://localhost:8000) in your browser. No npm packages or external API keys are needed.

## How it works

1. Enter the sender address, subject, and message body.
2. Optionally add a URL or select a harmless sample attachment.
3. Select **Analyze Email** to view the risk score, classification, findings, and recommendations.
4. Select **Clear** to reset the form and results.

| Check | What the application evaluates |
| --- | --- |
| Sender and message | Urgency, threats, sensitive information requests, unusual payment requests, and sender identity mismatches. |
| Links | URLs extracted from text or HTML, scheme, hostname, and structural or displayed-destination concerns. |
| Attachments | Filename, extension, size, supported file signature, and SHA-256 hash. Files above 5 MB are reported but skipped for inspection. |

## Project structure

| File | Purpose |
| --- | --- |
| `index.html`, `style.css` | Form, responsive layout, and results display |
| `app.js` | Input validation, form handling, and safe results rendering |
| `analyzer.js` | Coordinates rules and calculates risk |
| `rules/content.js` | Sender and content analysis |
| `rules/links.js` | Static link analysis |
| `rules/attachments.js` | Static file inspection |
| `recommendations.js` | Risk-specific guidance |
| `tests/` | Automated regression and UI safety tests |

## Risk scoring

Each triggered category adds its points once per email, even if several findings belong to that category. The total is capped at 100.

| Indicator | Points |
| --- | ---: |
| Urgency or threats | 15 |
| Sensitive information request | 20 |
| Sender identity mismatch | 20 |
| Unusual payment request | 15 |
| Suspicious URL characteristics | 15 |
| Misleading link destination | 15 |
| Potentially dangerous attachment | 15 |

| Score | Assessment |
| --- | --- |
| 0–29 | Low risk |
| 30–59 | Medium risk |
| 60–100 | High risk |

The score represents the rule weights for the observed indicators. Review individual findings regardless of the overall classification.

## Testing

The UI review version associated with PR #11 passed **112 automated tests**, with zero failures. The six required fictional browser scenarios and an additional combined demonstration matched their expected scores and classifications.

| Scenario | Expected | Observed |
| --- | --- | --- |
| Routine university announcement | 0 · Low | 0 · Low |
| Urgency and credential request | 35 · Medium | 35 · Medium |
| Sender mismatch and suspicious URL | 35 · Medium | 35 · Medium |
| Harmless double-extension file | 15 · Low | 15 · Low |
| Routine PDF attachment | 0 · Low | 0 · Low |
| Urgency and misleading link | 30 · Medium | 30 · Medium |
| Combined link and attachment demo | 65 · High | 65 · High |

Run `npm test` anytime to repeat the automated suite. GitHub Actions runs the tests on pull requests, and branch protection on `main` requires a pull request and passing `test` status check.

## Security and limitations

The application processes submitted text and file bytes locally. It displays links as text and does not automatically open them. Files are inspected without execution or macro activation. Use fictional messages and harmless fixtures.

The application uses heuristic rules and does not verify SPF, DKIM, or DMARC, perform antivirus scanning, or query live reputation services. A matching file signature or HTTPS connection does not establish safety. A low score does not establish legitimacy, and the evaluation scenarios do not measure real-world detection accuracy.
