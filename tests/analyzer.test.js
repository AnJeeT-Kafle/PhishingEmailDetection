import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeEmail, scoreFindings, classify, CATEGORIES } from "../analyzer.js";

// Builds one finding per category id.
const f = (...categories) =>
  categories.map((category) => ({ category, message: `test ${category}` }));

test("analyzeEmail returns score, classification, and findings", () => {
  const result = analyzeEmail({});
  assert.equal(typeof result.score, "number");
  assert.equal(typeof result.classification, "string");
  assert.ok(Array.isArray(result.findings));
});

test("empty findings -> 0 Low", () => {
  const result = scoreFindings([]);
  assert.equal(result.score, 0);
  assert.equal(result.classification, "Low");
  assert.deepEqual(result.breakdown, []);
  assert.deepEqual(result.warnings, []);
});

test("a category with two findings is counted once", () => {
  const result = scoreFindings(f("urgency_threat", "urgency_threat"));
  assert.equal(result.score, 15);
  assert.equal(result.breakdown.length, 1);
  assert.deepEqual(result.breakdown[0], {
    category: "urgency_threat",
    label: "Urgent or threatening language",
    points: 15,
  });
});

test("urgency_threat + sensitive_info -> 35 Medium", () => {
  const result = scoreFindings(f("urgency_threat", "sensitive_info"));
  assert.equal(result.score, 35);
  assert.equal(result.classification, "Medium");
});

test("sender_mismatch + suspicious_url -> 35 Medium", () => {
  const result = scoreFindings(f("sender_mismatch", "suspicious_url"));
  assert.equal(result.score, 35);
  assert.equal(result.classification, "Medium");
});

test("dangerous_attachment alone -> 15 Low", () => {
  const result = scoreFindings(f("dangerous_attachment"));
  assert.equal(result.score, 15);
  assert.equal(result.classification, "Low");
});

test("urgency_threat + misleading_link -> 30 Medium", () => {
  const result = scoreFindings(f("urgency_threat", "misleading_link"));
  assert.equal(result.score, 30);
  assert.equal(result.classification, "Medium");
});

test("demo: urgency_threat + sensitive_info + suspicious_url + dangerous_attachment -> 65 High", () => {
  const result = scoreFindings(
    f("urgency_threat", "sensitive_info", "suspicious_url", "dangerous_attachment")
  );
  assert.equal(result.score, 65);
  assert.equal(result.classification, "High");
});

test("all 7 categories -> capped at 100 High", () => {
  const result = scoreFindings(f(...Object.keys(CATEGORIES)));
  assert.equal(result.score, 100);
  assert.equal(result.classification, "High");
  assert.equal(result.breakdown.length, 7);
});

test("unknown category is not scored and produces a warning", () => {
  const result = scoreFindings(f("urgency_threat", "made_up", "made_up"));
  assert.equal(result.score, 15);
  assert.equal(result.breakdown.length, 1);
  assert.equal(result.warnings.length, 1);
  assert.match(result.warnings[0], /made_up/);
});

test("classify boundaries", () => {
  assert.equal(classify(0), "Low");
  assert.equal(classify(29), "Low");
  assert.equal(classify(30), "Medium");
  assert.equal(classify(59), "Medium");
  assert.equal(classify(60), "High");
  assert.equal(classify(100), "High");
});
