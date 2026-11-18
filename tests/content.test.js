import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeEmail } from "../analyzer.js";
import { urgencyRule, threatRule, credentialRule, paymentRule } from "../rules/content.js";

// All senders, names, and domains below are fictional.

test("urgencyRule fires and quotes the phrase", () => {
  const findings = urgencyRule({ subject: "Final notice", body: "Please reply." });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].category, "urgency_threat");
  assert.equal(findings[0].rule, "urgency");
  assert.match(findings[0].message, /"Final notice"/);
  assert.match(findings[0].message, /subject/);
});

test("threatRule fires and quotes the phrase", () => {
  const findings = threatRule({ body: "Your mailbox will be suspended tonight." });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].category, "urgency_threat");
  assert.equal(findings[0].rule, "threat");
  assert.match(findings[0].message, /"will be suspended"/);
  assert.match(findings[0].message, /body/);
});

test("credentialRule fires and quotes the phrase", () => {
  const findings = credentialRule({ body: "Reply with your login credentials." });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].category, "sensitive_info");
  assert.equal(findings[0].rule, "credential_request");
  assert.match(findings[0].message, /"login credentials"/);
});

test("paymentRule fires and quotes the phrase", () => {
  const findings = paymentRule({ body: "Buy a gift card and send me the code." });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].category, "payment_request");
  assert.equal(findings[0].rule, "payment_request");
  assert.match(findings[0].message, /"gift card"/);
  assert.match(findings[0].message, /business email compromise \(BEC\)/);
});

test("one finding per matched phrase, and both locations are reported", () => {
  const findings = paymentRule({
    subject: "Wire transfer needed",
    body: "Complete the wire transfer, then buy bitcoin.",
  });
  assert.equal(findings.length, 2);
  assert.match(findings[0].message, /"Wire transfer" found in the subject and body/);
  assert.match(findings[1].message, /"bitcoin" found in the body/);
});

test("matching is case-insensitive", () => {
  assert.equal(urgencyRule({ body: "ACT NOW" }).length, 1);
  assert.equal(credentialRule({ body: "Confirm Your PassWord" }).length, 1);
  assert.match(urgencyRule({ body: "ACT NOW" })[0].message, /"ACT NOW"/);
});

test("matching uses word boundaries", () => {
  // "pin" inside "spinning" and "urgent" inside "urgently" are not whole words.
  assert.equal(credentialRule({ body: "The spinning class is full." }).length, 0);
  assert.equal(urgencyRule({ body: "We urgently need volunteers." }).length, 0);
});

test("routine university announcement -> no findings, 0 Low", () => {
  const result = analyzeEmail({
    sender: "events@northfield-university.example",
    subject: "Library hours for the winter break",
    body:
      "Hello students, the main library will close at 6 pm from December 20 to January 3. " +
      "Online resources remain available. Enjoy the break!",
  });
  assert.deepEqual(result.findings, []);
  assert.equal(result.score, 0);
  assert.equal(result.classification, "Low");
});

test("urgent password verification -> 35 Medium", () => {
  const result = analyzeEmail({
    sender: "it-support@northfield-university.example",
    subject: "Urgent: password verification required",
    body: "Reply with your current password within 24 hours to keep your email access.",
  });
  assert.equal(result.score, 35);
  assert.equal(result.classification, "Medium");
  assert.deepEqual(
    result.breakdown.map((item) => item.category),
    ["urgency_threat", "sensitive_info"]
  );
});

test("missing or invalid fields don't crash", () => {
  for (const rule of [urgencyRule, threatRule, credentialRule, paymentRule]) {
    assert.deepEqual(rule({}), []);
    assert.deepEqual(rule(undefined), []);
    assert.deepEqual(rule({ subject: null, body: 42 }), []);
  }
  const result = analyzeEmail({});
  assert.equal(result.score, 0);
  assert.equal(result.classification, "Low");
});
