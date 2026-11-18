// Content rules: look for phishing phrases in the subject and body.
// DOM-free so Node can test it. Each rule takes { sender, subject, body }
// and returns findings [{ category, rule, message }], one per matched phrase.

export const URGENCY_PHRASES = [
  "act now",
  "act immediately",
  "urgent",
  "immediately",
  "within 24 hours",
  "as soon as possible",
  "final notice",
  "expires today",
];

export const THREAT_PHRASES = [
  "will be suspended",
  "will be closed",
  "will be locked",
  "legal action",
  "unauthorized activity",
  "account terminated",
];

export const CREDENTIAL_PHRASES = [
  "password",
  "verify your account",
  "login credentials",
  "social security number",
  "SSN",
  "PIN",
  "credit card number",
  "bank account number",
];

export const PAYMENT_PHRASES = [
  "wire transfer",
  "gift card",
  "bitcoin",
  "cryptocurrency",
  "update your bank details",
  "send payment",
  "overdue invoice",
];

const asText = (value) => (typeof value === "string" ? value : "");

const escapeRegex = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

// Whole-word, case-insensitive match. Words in a phrase may be separated by any whitespace.
function phraseRegex(phrase) {
  const pattern = phrase.trim().split(/\s+/).map(escapeRegex).join("\\s+");
  return new RegExp(`\\b${pattern}\\b`, "i");
}

const LOCATIONS = ["subject", "body"];

// Returns one finding per phrase that appears in the subject and/or body.
function matchPhrases(input, phrases, category, rule, description) {
  const fields = {
    subject: asText(input?.subject),
    body: asText(input?.body),
  };
  const findings = [];

  for (const phrase of phrases) {
    const regex = phraseRegex(phrase);
    let matchedText = null;
    const foundIn = [];

    for (const location of LOCATIONS) {
      const match = fields[location].match(regex);
      if (match) {
        matchedText ??= match[0];
        foundIn.push(location);
      }
    }

    if (matchedText !== null) {
      findings.push({
        category,
        rule,
        message: `${description}: "${matchedText}" found in the ${foundIn.join(" and ")}.`,
      });
    }
  }

  return findings;
}

export function urgencyRule(input) {
  return matchPhrases(input, URGENCY_PHRASES, "urgency_threat", "urgency", "Urgent language");
}

export function threatRule(input) {
  return matchPhrases(input, THREAT_PHRASES, "urgency_threat", "threat", "Threat or pressure");
}

export function credentialRule(input) {
  return matchPhrases(
    input,
    CREDENTIAL_PHRASES,
    "sensitive_info",
    "credential_request",
    "Request for sensitive information"
  );
}

export function paymentRule(input) {
  return matchPhrases(
    input,
    PAYMENT_PHRASES,
    "payment_request",
    "payment_request",
    "Unusual payment request"
  );
}
