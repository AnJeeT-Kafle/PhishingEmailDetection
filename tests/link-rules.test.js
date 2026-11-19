import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeEmail } from "../analyzer.js";
import { linkRule, analyzeLinks } from "../rules/links.js";

// All links below are fictional. Nothing is fetched; links are only read as text.

const HTTPS_NOTE =
  "Uses HTTPS: the connection is encrypted, but HTTPS does not prove the site is trustworthy.";
const HTTP_NOTE = "Uses HTTP: the connection is not encrypted.";

// Runs linkRule on a single URL in the URL field and returns its findings.
const findingsFor = (url) => linkRule({ url });

function assertOneSuspicious(url, pattern) {
  const findings = findingsFor(url);
  assert.equal(findings.length, 1, `${url}: ${JSON.stringify(findings)}`);
  assert.equal(findings[0].category, "suspicious_url");
  assert.equal(findings[0].rule, "suspicious_url");
  assert.ok(findings[0].message.includes(url), "message names the link");
  assert.match(findings[0].message, pattern);
}

test("IP-address host -> suspicious_url", () => {
  assertOneSuspicious("http://192.0.2.15/login", /IP address \(192\.0\.2\.15\)/);
});

test('"@" userinfo -> suspicious_url naming the real host', () => {
  assertOneSuspicious("https://examplebank.com@login-check.example/", /"@".*login-check\.example/);
});

test("misleading hostname: org domain as a prefix of another domain", () => {
  assertOneSuspicious(
    "https://paypal.com.secure-login.xyz/",
    /contains "paypal".*paypal\.com.*secure-login\.xyz/
  );
});

test("misleading hostname: org name joined with a hyphen", () => {
  assertOneSuspicious("https://paypal-login.example/", /contains "paypal".*paypal-login\.example/);
});

test("real org domain and subdomain are not misleading", () => {
  assert.deepEqual(findingsFor("https://www.paypal.com/signin"), []);
  assert.deepEqual(findingsFor("https://accountprotection.microsoft.com/"), []);
  // "chase" inside "purchase" is not a whole label, so it isn't flagged.
  assert.deepEqual(findingsFor("https://purchase-orders.example/"), []);
});

test("punycode hostname -> suspicious_url", () => {
  assertOneSuspicious("https://xn--exmple-cua.com/", /punycode/);
});

test("excessive complexity: long URL", () => {
  const url = `https://examplebank.com/${"a".repeat(90)}`;
  assertOneSuspicious(url, /unusually complex: it is \d+ characters long/);
});

test("excessive complexity: many hostname labels", () => {
  assertOneSuspicious("https://a.b.c.examplebank.com/", /hostname has 5 parts/);
});

test("excessive complexity: percent-encoded characters", () => {
  assertOneSuspicious("https://examplebank.com/%6C%6F%67%69%6E", /5 percent-encoded characters/);
});

test("excessive complexity: non-default port", () => {
  assertOneSuspicious("https://examplebank.com:8443/", /non-standard port \(8443\)/);
  // Default ports are dropped by the URL constructor and aren't flagged.
  assert.deepEqual(findingsFor("https://examplebank.com:443/"), []);
});

test("excessive complexity: several reasons give one finding", () => {
  const findings = findingsFor("http://a.b.c.examplebank.com:8080/");
  assert.equal(findings.length, 1);
  assert.match(findings[0].message, /hostname has 5 parts, it uses a non-standard port \(8080\)/);
});

test("javascript: and data: schemes -> suspicious_url", () => {
  const js = linkRule({ body: '<a href="javascript:alert(1)">View statement</a>' });
  assert.equal(js.length, 1);
  assert.equal(js[0].category, "suspicious_url");
  assert.match(js[0].message, /javascript: scheme/);

  const data = linkRule({ body: '<a href="data:text/html,hello">Open</a>' });
  assert.equal(data.length, 1);
  assert.match(data[0].message, /data: scheme/);
});

test("misleading_link: anchor text domain differs from the href", () => {
  const findings = linkRule({
    body: '<a href="https://review-portal.example/login">https://www.examplebank.com/login</a>',
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].category, "misleading_link");
  assert.equal(findings[0].rule, "misleading_link");
  assert.match(findings[0].message, /https:\/\/review-portal\.example\/login/);
  assert.match(findings[0].message, /examplebank\.com.*review-portal\.example/);
});

test("misleading_link does not fire for matching or non-URL text", () => {
  // Same registrable domain (www. and path differ).
  assert.deepEqual(
    linkRule({ body: '<a href="https://examplebank.com/login">www.examplebank.com</a>' }),
    []
  );
  // Ordinary words and file names are not treated as domains.
  assert.deepEqual(linkRule({ body: '<a href="https://examplebank.com/x">Click here</a>' }), []);
  assert.deepEqual(linkRule({ body: '<a href="https://examplebank.com/x">statement.pdf</a>' }), []);
});

test("anchor text www.examplebank.com -> IP href gives suspicious_url and misleading_link", () => {
  const findings = linkRule({ body: '<a href="http://192.168.10.5/">www.examplebank.com</a>' });
  assert.deepEqual(findings.map((f) => f.category).sort(), ["misleading_link", "suspicious_url"]);
});

test("invalid link -> no findings", () => {
  assert.deepEqual(linkRule({ url: "not a url", body: '<a href="http://exa mple.com">x.com</a>' }), []);
});

test("normal https link -> no findings, HTTPS note only", () => {
  assert.deepEqual(findingsFor("https://examplebank.com"), []);
  const [link] = analyzeLinks({ url: "https://examplebank.com" });
  assert.deepEqual(link.explanations, [HTTPS_NOTE]);
});

test("explanations list every issue, then one scheme note", () => {
  const [link] = analyzeLinks({ body: '<a href="http://192.168.10.5/">www.examplebank.com</a>' });
  assert.equal(link.explanations.length, 3);
  assert.match(link.explanations[0], /IP address/);
  assert.match(link.explanations[1], /link text shows/);
  assert.equal(link.explanations[2], HTTP_NOTE);

  const [invalid] = analyzeLinks({ url: "not a url" });
  assert.deepEqual(invalid.explanations, ["Could not be parsed as a valid link."]);
});

test("README sample: bank impersonation with an IP-address link -> 35 Medium", () => {
  const result = analyzeEmail({
    sender: "Example Bank <alerts@eb-customer-care.example>",
    subject: "Your monthly statement",
    body: "Your Example Bank statement is ready: http://192.0.2.15/statement",
  });
  assert.equal(result.score, 35);
  assert.equal(result.classification, "Medium");
  assert.deepEqual(
    result.breakdown.map((item) => item.category),
    ["sender_mismatch", "suspicious_url"]
  );
});

test("README sample: urgent HTML with mismatched displayed domain -> 30 Medium", () => {
  const result = analyzeEmail({
    sender: "notices@northfield-university.example",
    subject: "Urgent: review your statement",
    body: '<p>Please review your statement at <a href="https://review-portal.example/login">www.examplebank.com</a>.</p>',
  });
  assert.equal(result.score, 30);
  assert.equal(result.classification, "Medium");
  assert.deepEqual(
    result.breakdown.map((item) => item.category),
    ["urgency_threat", "misleading_link"]
  );
});
