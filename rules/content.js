// Content rules: look for phishing phrases in the subject and body.
// DOM-free so Node can test it. Each rule takes { sender, subject, body }
// and returns findings [{ category, rule, message }], one per matched phrase.
//
// The keyword rules are a block list (zyBook 8.7): they flag known-bad phrases.
// A block list is easy to explain and edit, but phishing that avoids every listed
// phrase is not flagged (false negative), and harmless text that happens to use a
// listed phrase is flagged (false positive).

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
// note (optional) is appended to each message to explain why the phrase matters.
function matchPhrases(input, phrases, category, rule, description, note = "") {
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
        message:
          `${description}: "${matchedText}" found in the ${foundIn.join(" and ")}.` +
          (note ? ` ${note}` : ""),
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

// Payment requests map to business email compromise (BEC): an attacker impersonates
// a trusted person or company to get a fraudulent payment (fake invoice, wire request).
export function paymentRule(input) {
  return matchPhrases(
    input,
    PAYMENT_PHRASES,
    "payment_request",
    "payment_request",
    "Unusual payment request",
    "This may be business email compromise (BEC). Verify the request through a separate, trusted channel before paying."
  );
}

// ---------------------------------------------------------------------------
// Sender impersonation and lookalike domains (zyBook 1.5 typosquatting, 1.6 phishing).
// We compare the claimed organization with the sender's domain as written.
// No DNS lookups are made, so SPF/DKIM/DMARC (zyBook 8.5) are not checked, and a
// spoofed From address that uses the real domain is not detected here.

// Organizations commonly impersonated in phishing. Only official sending domains are
// listed (not free-mail domains like gmail.com or outlook.com, which anyone can use).
export const KNOWN_ORGS = [
  { name: "PayPal", aliases: ["PayPal"], domains: ["paypal.com"] },
  {
    name: "Microsoft",
    aliases: ["Microsoft", "Office 365", "Microsoft 365"],
    domains: ["microsoft.com", "office.com", "microsoftonline.com"],
  },
  { name: "Amazon", aliases: ["Amazon"], domains: ["amazon.com"] },
  { name: "Apple", aliases: ["Apple", "Apple ID", "iCloud"], domains: ["apple.com"] },
  { name: "Google", aliases: ["Google"], domains: ["google.com"] },
  { name: "Netflix", aliases: ["Netflix"], domains: ["netflix.com"] },
  {
    name: "Chase",
    aliases: ["Chase", "JPMorgan Chase"],
    domains: ["chase.com", "jpmorganchase.com"],
  },
  {
    name: "Bank of America",
    aliases: ["Bank of America", "BofA"],
    domains: ["bankofamerica.com", "bofa.com"],
  },
  { name: "IRS", aliases: ["IRS", "Internal Revenue Service"], domains: ["irs.gov"] },
  {
    name: "University of Louisiana at Monroe",
    aliases: ["University of Louisiana at Monroe", "ULM"],
    domains: ["ulm.edu"],
  },
  // Fictional organization for test samples.
  { name: "Example Bank", aliases: ["Example Bank"], domains: ["examplebank.com"] },
];

// Shorter labels (irs, ulm, bofa) are skipped for lookalike checks: one edit away from
// a 3–4 letter label matches many unrelated real domains (e.g. "sofa" vs "bofa").
const MIN_LOOKALIKE_LABEL_LENGTH = 5;

const ADDRESS_REGEX = /^[^\s@<>"]+@((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,})$/i;

// Accepts "Name <addr@domain>" or "addr@domain". Returns null if invalid. Never throws.
export function parseSender(sender) {
  if (typeof sender !== "string") return null;
  const text = sender.trim();
  if (!text) return null;

  let displayName = "";
  let address = text;
  const angled = text.match(/^(.*?)\s*<([^<>]*)>$/);
  if (angled) {
    displayName = angled[1].trim().replace(/^"(.*)"$/, "$1").trim();
    address = angled[2].trim();
  }

  const match = address.match(ADDRESS_REGEX);
  if (!match) return null;
  return { displayName, address, domain: match[1].toLowerCase() };
}

// True if domain equals one of the org's domains or is a subdomain of one.
export function belongsTo(domain, orgDomains) {
  return orgDomains.some((d) => domain === d || domain.endsWith(`.${d}`));
}

// Common second-level parts of country domains, e.g. "co" in example.co.uk.
const SECOND_LEVEL = new Set(["co", "com", "net", "org", "gov", "edu", "ac"]);

// The registrable domain: "paypal.com" for "mail.paypal.com", "paypal.co.uk" for
// "www.paypal.co.uk". Uses a small list of country second-level parts, not the full
// public suffix list.
export function registrableDomain(domain) {
  const labels = domain.split(".").filter(Boolean);
  if (labels.length >= 3 && SECOND_LEVEL.has(labels[labels.length - 2])) {
    return labels.slice(-3).join(".");
  }
  return labels.slice(-2).join(".");
}

// The registrable name of a domain: "paypal" for "mail.paypal.com" or "paypal.co.uk".
export function mainLabel(domain) {
  return registrableDomain(domain).split(".")[0];
}

// Levenshtein distance, with an early exit once it exceeds max.
function editDistance(a, b, max = 1) {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  let prev = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    const curr = [i];
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost);
    }
    if (Math.min(...curr) > max) return max + 1;
    prev = curr;
  }
  return prev[b.length];
}

export function senderRule(input) {
  const parsed = parseSender(input?.sender);
  if (!parsed) return [];
  const { displayName, domain } = parsed;

  const fields = {
    "display name": displayName,
    subject: asText(input?.subject),
    body: asText(input?.body),
  };
  const findings = [];

  // (a) The email claims to be from an organization, but the domain isn't theirs.
  for (const org of KNOWN_ORGS) {
    if (belongsTo(domain, org.domains)) continue;
    const regexes = org.aliases.map(phraseRegex);
    const claimedIn = Object.keys(fields).filter((location) =>
      regexes.some((regex) => regex.test(fields[location]))
    );
    if (claimedIn.length > 0) {
      findings.push({
        category: "sender_mismatch",
        rule: "sender_impersonation",
        message:
          `Sender impersonation: the ${claimedIn.join(" and ")} mention${claimedIn.length > 1 ? "" : "s"} ` +
          `${org.name}, but the sender domain is ${domain}, not ${org.domains.join(" or ")}.`,
      });
    }
  }

  // (b) The sender domain is one character away from a known domain (typosquatting).
  const isKnownDomain = KNOWN_ORGS.some((org) => belongsTo(domain, org.domains));
  if (!isKnownDomain) {
    const label = mainLabel(domain);
    for (const org of KNOWN_ORGS) {
      const lookalikeOf = org.domains.find((known) => {
        const knownLabel = mainLabel(known);
        return (
          knownLabel.length >= MIN_LOOKALIKE_LABEL_LENGTH &&
          editDistance(label, knownLabel) <= 1
        );
      });
      if (lookalikeOf) {
        findings.push({
          category: "sender_mismatch",
          rule: "sender_impersonation",
          message:
            `Sender domain ${domain} looks like ${lookalikeOf} (${org.name}): ` +
            `lookalike domain (possible typosquatting).`,
        });
      }
    }
  }

  return findings;
}
