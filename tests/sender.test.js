import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeEmail } from "../analyzer.js";
import { parseSender, senderRule } from "../rules/content.js";

// All senders and messages below are fictional.

test("parseSender: 'Name <addr@domain>' format", () => {
  assert.deepEqual(parseSender('"PayPal Support" <service@PayPal.com>'), {
    displayName: "PayPal Support",
    address: "service@PayPal.com",
    domain: "paypal.com",
  });
});

test("parseSender: bare 'addr@domain' format", () => {
  assert.deepEqual(parseSender("alerts@examplebank.com"), {
    displayName: "",
    address: "alerts@examplebank.com",
    domain: "examplebank.com",
  });
});

test("parseSender: invalid input returns null and never throws", () => {
  for (const value of [undefined, null, 42, "", "   ", "not an email", "a@b", "x@@y.com", "Name <>", "Name <bad>"]) {
    assert.equal(parseSender(value), null, `expected null for ${JSON.stringify(value)}`);
  }
});

test("real domain -> no finding", () => {
  const findings = senderRule({
    sender: "PayPal <service@paypal.com>",
    subject: "Your PayPal receipt",
    body: "Thanks for using PayPal.",
  });
  assert.deepEqual(findings, []);
});

test("subdomain of the real domain -> no finding", () => {
  const findings = senderRule({
    sender: "Microsoft <account-security@accountprotection.microsoft.com>",
    body: "A new sign-in to your Microsoft account was detected.",
  });
  assert.deepEqual(findings, []);
});

test("display-name claim with wrong domain -> finding", () => {
  const findings = senderRule({ sender: "PayPal Support <help@pay-secure-alerts.example>" });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].category, "sender_mismatch");
  assert.equal(findings[0].rule, "sender_impersonation");
  assert.match(findings[0].message, /display name/);
  assert.match(findings[0].message, /PayPal/);
  assert.match(findings[0].message, /pay-secure-alerts\.example/);
});

test("body claim from gmail.com -> finding", () => {
  const findings = senderRule({
    sender: "jordan.reyes.irs@gmail.com",
    body: "This is the Internal Revenue Service. Your refund is on hold.",
  });
  assert.equal(findings.length, 1);
  assert.match(findings[0].message, /body mentions IRS/);
  assert.match(findings[0].message, /gmail\.com/);
});

test("paypa1.com -> lookalike finding", () => {
  const findings = senderRule({ sender: "service@paypa1.com" });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].category, "sender_mismatch");
  assert.match(findings[0].message, /lookalike domain \(possible typosquatting\)/);
  assert.match(findings[0].message, /paypal\.com/);
});

test("invalid or missing sender -> no findings, no crash", () => {
  assert.deepEqual(senderRule({}), []);
  assert.deepEqual(senderRule(undefined), []);
  assert.deepEqual(senderRule({ sender: "not an email", body: "PayPal" }), []);
});

test("routine ULM email from ulm.edu -> 0 Low", () => {
  const result = analyzeEmail({
    sender: "ULM Student Life <studentlife@ulm.edu>",
    subject: "ULM fall festival this Friday",
    body: "Join us on the quad for food trucks and live music. All University of Louisiana at Monroe students are welcome.",
  });
  assert.deepEqual(result.findings, []);
  assert.equal(result.score, 0);
  assert.equal(result.classification, "Low");
});

test("Example Bank claim from wrong domain -> 20 via analyzeEmail", () => {
  const result = analyzeEmail({
    sender: "Example Bank <notices@eb-customer-care.example>",
    subject: "Your monthly statement",
    body: "Your Example Bank statement is ready to view.",
  });
  assert.equal(result.score, 20);
  assert.equal(result.classification, "Low");
  assert.deepEqual(result.breakdown.map((item) => item.category), ["sender_mismatch"]);
});
