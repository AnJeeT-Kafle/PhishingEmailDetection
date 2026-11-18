// Phishing email analyzer: scoring core.
// This file must stay DOM-free (no document/window) so it can be tested in Node.

// Each category adds its points once, no matter how many findings it has.
export const CATEGORIES = {
  urgency_threat: { label: "Urgent or threatening language", points: 15 },
  sensitive_info: { label: "Request for sensitive information", points: 20 },
  sender_mismatch: { label: "Sender identity mismatch", points: 20 },
  payment_request: { label: "Unusual payment request", points: 15 },
  suspicious_url: { label: "Suspicious URL characteristics", points: 15 },
  misleading_link: { label: "Misleading link destination", points: 15 },
  dangerous_attachment: { label: "Potentially dangerous attachment", points: 15 },
};

const MAX_SCORE = 100;

export function classify(score) {
  if (score >= 60) return "High";
  if (score >= 30) return "Medium";
  return "Low";
}

// findings: [{ category, message }]
export function scoreFindings(findings) {
  const breakdown = [];
  const warnings = [];
  const seen = new Set();
  const unknownSeen = new Set();

  for (const finding of findings) {
    const category = finding?.category;
    if (seen.has(category) || unknownSeen.has(category)) continue;

    if (!Object.hasOwn(CATEGORIES, category)) {
      unknownSeen.add(category);
      warnings.push(
        `Unknown finding category "${category}" was not scored. Check the rule that produced it.`
      );
      continue;
    }

    seen.add(category);
    const { label, points } = CATEGORIES[category];
    breakdown.push({ category, label, points });
  }

  const total = breakdown.reduce((sum, item) => sum + item.points, 0);
  const score = Math.min(total, MAX_SCORE);
  return { score, classification: classify(score), breakdown, warnings };
}

// Rule functions take the input and return findings [{ category, message }].
// Rules get added in later steps (content, URL, attachment checks).
const RULES = [];

export function analyzeEmail(input) {
  const findings = RULES.flatMap((rule) => rule(input));
  return { ...scoreFindings(findings), findings };
}
