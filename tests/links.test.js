import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeEmail } from "../analyzer.js";
import { parseLink, extractLinks, analyzeLinks } from "../rules/links.js";

// All links below are fictional. Nothing is fetched; links are only parsed as text.

test("plain-text https link is extracted and parsed", () => {
  const links = analyzeLinks({ body: "Visit https://portal.northfield-university.example/login today" });
  assert.equal(links.length, 1);
  assert.deepEqual(links[0], {
    href: "https://portal.northfield-university.example/login",
    scheme: "https",
    hostname: "portal.northfield-university.example",
    domain: "northfield-university.example",
    isIp: false,
    text: null,
    source: "body",
    invalid: false,
  });
});

test("www. link without a scheme is treated as http", () => {
  const links = analyzeLinks({ body: "See www.examplebank.com for details" });
  assert.equal(links.length, 1);
  assert.equal(links[0].href, "www.examplebank.com");
  assert.equal(links[0].scheme, "http");
  assert.equal(links[0].hostname, "www.examplebank.com");
  assert.equal(links[0].domain, "examplebank.com");
});

test("HTML anchor keeps its visible text", () => {
  const links = extractLinks({
    body: `<p>Please <A HREF='https://login.example-verify.test/x'>Sign in to <b>Example Bank</b></A></p>`,
  });
  assert.deepEqual(links, [
    { href: "https://login.example-verify.test/x", text: "Sign in to Example Bank", source: "html" },
  ]);
});

test("same URL in an anchor isn't double-counted as plain text", () => {
  const links = extractLinks({
    body: '<a href="https://examplebank.com/statements">https://examplebank.com/statements</a>',
  });
  assert.equal(links.length, 1);
  assert.equal(links[0].source, "html");
  assert.equal(links[0].text, "https://examplebank.com/statements");
});

test("manual URL field is included", () => {
  const links = analyzeLinks({ body: "", url: "  https://examplebank.com/help  " });
  assert.equal(links.length, 1);
  assert.equal(links[0].source, "url_field");
  assert.equal(links[0].href, "https://examplebank.com/help");
  assert.equal(links[0].hostname, "examplebank.com");
});

test("IP host sets isIp (IPv4 and IPv6)", () => {
  const v4 = parseLink("http://192.0.2.15/secure/login");
  assert.equal(v4.isIp, true);
  assert.equal(v4.hostname, "192.0.2.15");
  assert.equal(v4.domain, "192.0.2.15");

  const v6 = parseLink("http://[2001:db8::1]/login");
  assert.equal(v6.isIp, true);

  assert.equal(parseLink("https://examplebank.com").isIp, false);
});

test("trailing punctuation is stripped", () => {
  const links = extractLinks({
    body: "Go to https://examplebank.com/a. Or (https://examplebank.com/b), or https://examplebank.com/c; " +
      "or https://wiki.example/Page_(info).",
  });
  assert.deepEqual(
    links.map((link) => link.href),
    [
      "https://examplebank.com/a",
      "https://examplebank.com/b",
      "https://examplebank.com/c",
      "https://wiki.example/Page_(info)",
    ]
  );
});

test("identical href + text is deduplicated", () => {
  const links = extractLinks({
    body: "https://examplebank.com and again https://examplebank.com",
    url: "https://examplebank.com",
  });
  // The two body copies collapse into one; the URL field has the same href and text,
  // so it is also deduplicated.
  assert.equal(links.length, 1);
});

test("invalid href is flagged, no crash", () => {
  const links = analyzeLinks({ body: '<a href="http://exa mple.com">Click</a>', url: "not a url" });
  assert.equal(links.length, 2);
  assert.deepEqual(links[0], { href: "http://exa mple.com", text: "Click", source: "html", invalid: true });
  assert.deepEqual(links[1], { href: "not a url", text: null, source: "url_field", invalid: true });
  assert.equal(parseLink(""), null);
  assert.equal(parseLink(undefined), null);
});

test("missing body -> []", () => {
  assert.deepEqual(extractLinks({}), []);
  assert.deepEqual(extractLinks(undefined), []);
  assert.deepEqual(analyzeLinks({ body: null, url: 42 }), []);
});

test("analyzeEmail returns links without changing scores", () => {
  const result = analyzeEmail({
    sender: "it-support@northfield-university.example",
    subject: "Urgent: password verification required",
    body: "Reply with your current password at http://192.0.2.15/verify within 24 hours.",
  });
  assert.equal(result.score, 35);
  assert.equal(result.classification, "Medium");
  assert.deepEqual(result.breakdown.map((item) => item.category), ["urgency_threat", "sensitive_info"]);
  assert.equal(result.links.length, 1);
  assert.equal(result.links[0].isIp, true);

  const empty = analyzeEmail({});
  assert.equal(empty.score, 0);
  assert.deepEqual(empty.links, []);
});
