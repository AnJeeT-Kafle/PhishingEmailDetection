// Recommendations for the results panel.
// The analyzer scores an email but returns no advice, so the page builds it here from the
// classification, the triggered categories, and any warnings.
// DOM-free (no document/window) so Node can test it in tests/recommendations.test.js.

import { CATEGORIES, classify } from "./analyzer.js";

// One message per level. Low never says the email is safe or legitimate: a low score only
// means no strong indicators were found.
export const LEVEL_RECOMMENDATIONS = {
  Low: [
    "No strong phishing indicators were found. This does not confirm the email is legitimate: stay cautious and review any findings shown.",
  ],
  Medium: [
    "Treat this email with caution. Verify the sender through a separate, trusted channel before you act on it.",
  ],
  High: [
    "Avoid interacting with this email: do not click its links, reply, or open its attachments. Verify it independently through a separate, trusted channel.",
    "Report the email to your IT or security team.",
  ],
};

// Added for Medium and High. Content analysis can't check sender authentication.
export const AUTH_CHECK_RECOMMENDATION =
  "Check whether the message passed SPF/DKIM/DMARC (your mail provider or IT can confirm).";

const LINK_RECOMMENDATION =
  "Do not click the links. If you need the site, type its official address into your browser yourself.";

// One recommendation per category. suspicious_url and misleading_link share one message,
// so it is shown once when both are triggered.
export const CATEGORY_RECOMMENDATIONS = {
  urgency_threat:
    "Slow down. Pressure and threats are common tactics to make you act before you think.",
  sensitive_info:
    "Never send passwords, PINs, or Social Security numbers by email. Sign in by typing the organization's known address yourself.",
  sender_mismatch:
    "Check the sender's real domain. Contact the organization through its official website or a phone number you already know.",
  payment_request:
    "Confirm any payment or bank-detail change by phone with a known contact before paying (possible business email compromise).",
  suspicious_url: LINK_RECOMMENDATION,
  misleading_link: LINK_RECOMMENDATION,
  dangerous_attachment:
    "Do not open the attachment or enable macros. Scan it with up-to-date antivirus or ask IT to check it.",
};

export const WARNINGS_RECOMMENDATION =
  "Some items could not be checked (see Warnings), so the score may be incomplete.";

const LEVELS = new Set(["Low", "Medium", "High"]);

// result: the object returned by analyzeEmail/analyzeEmailAsync.
// Returns a list of recommendation strings with no duplicates, in this order:
// level advice, SPF/DKIM/DMARC check (Medium/High), category advice, warnings note.
export function buildRecommendations(result) {
  const score = Number.isFinite(result?.score) ? result.score : 0;
  const level = LEVELS.has(result?.classification) ? result.classification : classify(score);
  const breakdown = Array.isArray(result?.breakdown) ? result.breakdown : [];
  const warnings = Array.isArray(result?.warnings) ? result.warnings : [];

  const list = [...LEVEL_RECOMMENDATIONS[level]];
  if (level !== "Low") list.push(AUTH_CHECK_RECOMMENDATION);

  // Category advice in the analyzer's category order, so output is stable.
  const triggered = new Set(breakdown.map((item) => item?.category));
  for (const category of Object.keys(CATEGORIES)) {
    if (triggered.has(category)) list.push(CATEGORY_RECOMMENDATIONS[category]);
  }

  if (warnings.length > 0) list.push(WARNINGS_RECOMMENDATION);

  return [...new Set(list)];
}
