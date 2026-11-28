import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeEmail, analyzeEmailAsync, CATEGORIES } from "../analyzer.js";
import {
  buildRecommendations,
  LEVEL_RECOMMENDATIONS,
  CATEGORY_RECOMMENDATIONS,
  AUTH_CHECK_RECOMMENDATION,
  WARNINGS_RECOMMENDATION,
} from "../recommendations.js";

// All senders and messages below are fictional.

// A minimal result with the given classification and triggered categories.
const result = (classification, categories = [], warnings = []) => ({
  score: { Low: 0, Medium: 35, High: 65 }[classification],
  classification,
  breakdown: categories.map((category) => ({ category, ...CATEGORIES[category] })),
  warnings,
  findings: [],
  links: [],
  attachments: [],
});

test("Low: says no strong indicators and does not confirm legitimacy", () => {
  const recs = buildRecommendations(result("Low"));
  assert.deepEqual(recs, LEVEL_RECOMMENDATIONS.Low);
  const text = recs.join(" ");
  assert.match(text, /No strong phishing indicators were found/);
  assert.match(text, /does not confirm the email is legitimate/);
  // Never claims the email is safe.
  assert.doesNotMatch(text, /\bsafe\b/i);
  assert.doesNotMatch(text, /\b(looks|appears|seems) legitimate\b/i);
});

test("Low has no SPF/DKIM/DMARC recommendation", () => {
  assert.ok(!buildRecommendations(result("Low")).includes(AUTH_CHECK_RECOMMENDATION));
});

test("Medium: caution + verify sender + SPF/DKIM/DMARC check", () => {
  const recs = buildRecommendations(result("Medium"));
  assert.equal(recs[0], LEVEL_RECOMMENDATIONS.Medium[0]);
  assert.match(recs[0], /caution/i);
  assert.match(recs[0], /separate, trusted channel/);
  assert.ok(recs.includes(AUTH_CHECK_RECOMMENDATION));
  assert.match(AUTH_CHECK_RECOMMENDATION, /SPF\/DKIM\/DMARC/);
});

test("High: avoid interacting, verify independently, report, SPF/DKIM/DMARC check", () => {
  const recs = buildRecommendations(result("High"));
  const text = recs.join(" ");
  assert.match(text, /Avoid interacting/);
  assert.match(text, /Verify it independently/);
  assert.match(text, /Report the email/);
  assert.ok(recs.includes(AUTH_CHECK_RECOMMENDATION));
});

test("each category adds its own recommendation", () => {
  for (const category of Object.keys(CATEGORIES)) {
    const recs = buildRecommendations(result("Low", [category]));
    assert.ok(
      recs.includes(CATEGORY_RECOMMENDATIONS[category]),
      `missing recommendation for ${category}`
    );
    assert.equal(recs.length, LEVEL_RECOMMENDATIONS.Low.length + 1, category);
  }
});

test("every category has a non-empty recommendation", () => {
  for (const category of Object.keys(CATEGORIES)) {
    assert.equal(typeof CATEGORY_RECOMMENDATIONS[category], "string", category);
    assert.ok(CATEGORY_RECOMMENDATIONS[category].length > 0, category);
  }
});

test("suspicious_url + misleading_link share one recommendation, shown once", () => {
  const recs = buildRecommendations(result("Medium", ["suspicious_url", "misleading_link"]));
  const linkRec = CATEGORY_RECOMMENDATIONS.suspicious_url;
  assert.equal(linkRec, CATEGORY_RECOMMENDATIONS.misleading_link);
  assert.equal(recs.filter((r) => r === linkRec).length, 1);
  assert.equal(new Set(recs).size, recs.length);
});

test("all categories at High: no duplicates, stable order", () => {
  const all = Object.keys(CATEGORIES);
  const recs = buildRecommendations(result("High", all));
  assert.equal(new Set(recs).size, recs.length);
  // 2 High + SPF/DKIM/DMARC + 6 distinct category messages (links share one).
  assert.equal(recs.length, 2 + 1 + 6);
  assert.deepEqual(recs, buildRecommendations(result("High", [...all].reverse())));
});

test("warnings add a note that the score may be incomplete", () => {
  const recs = buildRecommendations(result("Low", [], ["big.pdf.exe was not inspected: larger than 5 MB"]));
  assert.equal(recs.at(-1), WARNINGS_RECOMMENDATION);
  assert.match(WARNINGS_RECOMMENDATION, /may be incomplete/);
  assert.ok(!buildRecommendations(result("Low")).includes(WARNINGS_RECOMMENDATION));
});

test("missing or malformed result falls back to Low without throwing", () => {
  assert.deepEqual(buildRecommendations(undefined), LEVEL_RECOMMENDATIONS.Low);
  assert.deepEqual(buildRecommendations({ breakdown: "nope", warnings: null }), LEVEL_RECOMMENDATIONS.Low);
  // Unknown category ids are ignored.
  assert.deepEqual(
    buildRecommendations({ classification: "Low", breakdown: [{ category: "made_up" }, null] }),
    LEVEL_RECOMMENDATIONS.Low
  );
});

test("unknown classification is derived from the score", () => {
  const recs = buildRecommendations({ score: 70, classification: "???", breakdown: [] });
  assert.deepEqual(recs.slice(0, 2), LEVEL_RECOMMENDATIONS.High);
});

test("works on real analyzer output: routine email -> Low wording only", () => {
  const recs = buildRecommendations(
    analyzeEmail({
      sender: "registrar@northfield-university.example",
      subject: "Spring course schedule",
      body: "Hello students, the spring course schedule is posted. See you next term.",
    })
  );
  assert.deepEqual(recs, LEVEL_RECOMMENDATIONS.Low);
});

test("works on real analyzer output: README demo -> High with category advice", async () => {
  const analysis = await analyzeEmailAsync({
    sender: "it-support@northfield-university.example",
    subject: "Urgent: password verification required",
    body: "Reply with your current password at http://192.0.2.15/verify.",
    files: [{ name: "report.pdf.exe", bytes: new TextEncoder().encode("harmless test file") }],
  });
  const recs = buildRecommendations(analysis);
  assert.equal(analysis.classification, "High");
  for (const category of ["urgency_threat", "sensitive_info", "suspicious_url", "dangerous_attachment"]) {
    assert.ok(recs.includes(CATEGORY_RECOMMENDATIONS[category]), category);
  }
  assert.ok(recs.includes(AUTH_CHECK_RECOMMENDATION));
});
