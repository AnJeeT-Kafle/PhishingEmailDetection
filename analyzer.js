// Phishing email analyzer: scoring core.
// This file must stay DOM-free (no document/window) so it can be tested in Node.

import {
  urgencyRule,
  threatRule,
  credentialRule,
  paymentRule,
  senderRule,
} from "./rules/content.js";
import { analyzeLinks, linkRule } from "./rules/links.js";
import { attachmentRule, inspectAttachments } from "./rules/attachments.js";

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
const RULES = [
  urgencyRule,
  threatRule,
  credentialRule,
  paymentRule,
  senderRule,
  linkRule,
  attachmentRule,
];

// A report from inspectAttachments has these fields. Raw files ({ name, size, bytes })
// don't, and would be skipped by attachmentRule without a warning.
const isInspectedReport = (item) =>
  item !== null && typeof item === "object" && "extension" in item && "sha256" in item;

// Warnings for attachments that were not (or could not be) checked. Never silent.
function attachmentWarnings(attachments) {
  if (attachments === undefined) return [];
  if (!Array.isArray(attachments)) {
    return ["Attachments were ignored: expected a list of reports from inspectAttachments."];
  }
  const warnings = [];
  for (const item of attachments) {
    const name = (item && typeof item.name === "string" && item.name) || "Unnamed attachment";
    if (!isInspectedReport(item)) {
      warnings.push(
        `${name} was not inspected: pass raw files as input.files to analyzeEmailAsync, ` +
          "or run inspectAttachments first. It was not scored."
      );
    } else if (item.overLimit) {
      warnings.push(`${name} was not inspected: larger than 5 MB`);
    }
  }
  return warnings;
}

// Synchronous analysis. input: { sender, subject, body, url, attachments }, where
// attachments are reports from inspectAttachments (see analyzeEmailAsync).
export function analyzeEmail(input) {
  const findings = RULES.flatMap((rule) => rule(input));
  const scored = scoreFindings(findings);
  const attachments = Array.isArray(input?.attachments) ? input.attachments : [];
  return {
    ...scored,
    warnings: [...scored.warnings, ...attachmentWarnings(input?.attachments)],
    findings,
    // Per-link and per-attachment details and explanations for the results panel.
    links: analyzeLinks(input),
    attachments,
  };
}

// Same as analyzeEmail, but accepts raw files as input.files ([{ name, size, bytes }]).
// Hashing (SHA-256 via Web Crypto) is asynchronous, so files are inspected here first.
export async function analyzeEmailAsync(input) {
  if (Array.isArray(input?.files)) {
    const reports = await inspectAttachments(input.files);
    return analyzeEmail({ ...input, attachments: reports });
  }
  return analyzeEmail(input);
}
