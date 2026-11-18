import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeEmail } from "../analyzer.js";

test("analyzeEmail returns score, classification, and findings", () => {
  const result = analyzeEmail({});
  assert.equal(typeof result.score, "number");
  assert.equal(typeof result.classification, "string");
  assert.ok(Array.isArray(result.findings));
});
