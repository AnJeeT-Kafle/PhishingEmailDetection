// Static safety checks for the page code. These read the files as text (nothing is run)
// and fail if a dangerous API appears, so CI catches it before review.
// The rules: email and analyzer text is only set with textContent (XSS), links are never
// fetched or opened, nothing is stored or logged, and the page loads nothing external.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const read = (file) => readFileSync(new URL(`../${file}`, import.meta.url), "utf8");

const PAGE_SCRIPTS = ["app.js", "recommendations.js"];

// [description, pattern]
const FORBIDDEN = [
  ["innerHTML", /\binnerHTML\b/],
  ["outerHTML", /\bouterHTML\b/],
  ["insertAdjacentHTML", /\binsertAdjacentHTML\b/],
  ["document.write", /\bdocument\s*\.\s*write(ln)?\b/],
  ["eval(", /\beval\s*\(/],
  ["new Function", /\bnew\s+Function\b/],
  ["fetch(", /\bfetch\s*\(/],
  ["XMLHttpRequest", /\bXMLHttpRequest\b/],
  ['createElement("a")', /createElement\s*\(\s*["'`]a["'`]\s*\)/i],
  // Addendum rule 3: nothing persists and nothing is logged.
  ["localStorage", /\blocalStorage\b/],
  ["sessionStorage", /\bsessionStorage\b/],
  ["indexedDB", /\bindexedDB\b/],
  ["document.cookie", /\bdocument\s*\.\s*cookie\b/],
  ["console.*", /\bconsole\s*\.\s*[a-z]/i],
  // Links are never opened.
  ["window.open", /\bwindow\s*\.\s*open\s*\(/],
];

// Returns "line N: text" for every forbidden pattern found in source.
function violations(source) {
  const found = [];
  source.split(/\r?\n/).forEach((line, i) => {
    for (const [name, pattern] of FORBIDDEN) {
      if (pattern.test(line)) found.push(`${name} on line ${i + 1}: ${line.trim()}`);
    }
  });
  return found;
}

test("the checker catches each forbidden pattern (self-test)", () => {
  const samples = [
    "node.innerHTML = text;",
    "node.outerHTML = text;",
    'node.insertAdjacentHTML("beforeend", text);',
    "document.write(text);",
    "eval(text);",
    "const f = new Function(text);",
    "fetch(url);",
    "const x = new XMLHttpRequest();",
    'document.createElement("a");',
    "document.createElement('A');",
    'localStorage.setItem("k", v);',
    "sessionStorage.clear();",
    "indexedDB.open('db');",
    "document.cookie = 'a=b';",
    "console.log(result);",
    "window.open(url);",
  ];
  for (const sample of samples) {
    assert.equal(violations(sample).length, 1, `not caught: ${sample}`);
  }
  // Safe code and prose are not flagged.
  assert.deepEqual(violations('node.textContent = text; document.createElement("abbr");'), []);
  assert.deepEqual(violations("// nothing is logged to the console."), []);
});

for (const file of PAGE_SCRIPTS) {
  test(`${file} uses no forbidden APIs`, () => {
    assert.deepEqual(violations(read(file)), []);
  });
}

test("index.html keeps the Content Security Policy", () => {
  const html = read("index.html");
  const csp = html.match(/http-equiv="Content-Security-Policy"\s+content="([^"]+)"/)?.[1];
  assert.ok(csp, "CSP meta tag is missing");
  for (const directive of [
    "default-src 'none'",
    "script-src 'self'",
    "style-src 'self'",
    "connect-src 'none'",
    "object-src 'none'",
    "form-action 'none'",
  ]) {
    assert.ok(csp.includes(directive), `CSP is missing ${directive}`);
  }
  assert.doesNotMatch(csp, /unsafe-inline|unsafe-eval/);
});

test("index.html has no inline scripts, styles, or event handlers", () => {
  const html = read("index.html");
  // Every <script> must load a local file.
  for (const tag of html.match(/<script\b[^>]*>/gi) ?? []) {
    assert.match(tag, /\bsrc="[^"]+"/, `inline script: ${tag}`);
  }
  assert.doesNotMatch(html, /<script\b[^>]*>[^<\s]/i, "script tag has inline content");
  assert.doesNotMatch(html, /<style\b/i, "inline <style> block");
  assert.doesNotMatch(html, /\sstyle\s*=/i, 'style="" attribute');
  assert.doesNotMatch(html, /\son[a-z]+\s*=/i, "inline event handler");
});

test("index.html loads nothing from another origin", () => {
  const html = read("index.html");
  for (const [, attr, value] of html.matchAll(/\b(src|href)="([^"]*)"/gi)) {
    assert.doesNotMatch(value, /^(https?:)?\/\//i, `external ${attr}: ${value}`);
  }
  assert.doesNotMatch(read("style.css"), /@import|url\(\s*["']?(https?:)?\/\//i, "external CSS resource");
});

test("index.html creates no <a> elements", () => {
  assert.doesNotMatch(read("index.html"), /<a\b/i);
});
