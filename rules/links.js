// Link extraction and parsing.
// DOM-free so Node can test it. Links are only parsed as text with the built-in URL
// constructor: this module never fetches, visits, or follows any link (no network calls).
// Pasted HTML is read with regular expressions and is never rendered or executed.

import { KNOWN_ORGS, belongsTo, registrableDomain, mainLabel } from "./content.js";

const asText = (value) => (typeof value === "string" ? value : "");

const IPV4_REGEX = /^\d{1,3}(?:\.\d{1,3}){3}$/;

// Allow list (zyBook 8.7) for hostnames: letters, digits, and hyphens in dot-separated
// labels. The URL constructor alone is too permissive: it accepts hostnames like
// "a(b).com", "a_b.com", or "a!b.com". Internationalized names are already converted
// to punycode (xn--...) by the URL constructor, so they pass.
const HOSTNAME_REGEX = /^[a-z0-9-]+(?:\.[a-z0-9-]+)*\.?$/;

// Minimal entity decoding for href values and link text in pasted HTML.
function decodeEntities(text) {
  return text
    .replace(/&#x([0-9a-f]+);/gi, (_, hex) => safeFromCodePoint(parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_, dec) => safeFromCodePoint(parseInt(dec, 10)))
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&");
}

function safeFromCodePoint(code) {
  try {
    return String.fromCodePoint(code);
  } catch {
    return "";
  }
}

// Parses a link without visiting it. Returns null if it isn't a valid URL. Never throws.
// "www.example.com" (no scheme) is treated as http://www.example.com.
export function parseLink(href) {
  return parseWithUrl(href)?.parsed ?? null;
}

// Same as parseLink, but also returns the URL object for the link checks below.
function parseWithUrl(href) {
  if (typeof href !== "string") return null;
  const raw = href.trim();
  if (!raw) return null;

  const withScheme = /^www\./i.test(raw) ? `http://${raw}` : raw;
  let url;
  try {
    url = new URL(withScheme);
  } catch {
    return null;
  }

  const scheme = url.protocol.replace(/:$/, "").toLowerCase();
  const hostname = url.hostname.toLowerCase();
  const isIpv6 = hostname.startsWith("[") && hostname.endsWith("]");
  const isIp = isIpv6 || IPV4_REGEX.test(hostname);

  // Web links need a hostname. Non-web schemes such as mailto: or javascript: have none
  // and are kept so later checks can flag them. Any hostname that is present must be a
  // valid IP or pass the allow list.
  if (!hostname && (scheme === "http" || scheme === "https")) return null;
  if (hostname && !isIp && !HOSTNAME_REGEX.test(hostname)) return null;

  // Naive: last two labels (mail.example.co.uk -> co.uk). IP hosts use the full host.
  const labels = hostname.split(".").filter(Boolean);
  const domain = isIp || labels.length <= 2 ? hostname : labels.slice(-2).join(".");

  return { parsed: { href: raw, scheme, hostname, domain, isIp }, url };
}

const TRAILING_PUNCTUATION = new Set([".", ",", ";", ":", "!", "?", ")", "]", "}", "'", '"']);

// Removes punctuation that ends a sentence rather than the URL. A closing ")" is kept
// when it balances an opening "(" inside the URL, e.g. https://example.com/page_(info).
function stripTrailingPunctuation(url) {
  let result = url;
  while (result.length > 0 && TRAILING_PUNCTUATION.has(result.at(-1))) {
    const last = result.at(-1);
    if (last === ")") {
      const opens = (result.match(/\(/g) || []).length;
      const closes = (result.match(/\)/g) || []).length;
      if (closes <= opens) break;
    }
    result = result.slice(0, -1);
  }
  return result;
}

// <a ... href="..." ...>text</a>, single or double quotes, case-insensitive.
const ANCHOR_REGEX = /<a\b[^>]*?\bhref\s*=\s*(["'])([\s\S]*?)\1[^>]*>([\s\S]*?)<\/a\s*>/gi;

// http://, https://, or www. up to whitespace, a quote, or an angle bracket.
const PLAIN_URL_REGEX = /\b(?:https?:\/\/|www\.)[^\s<>"']+/gi;

// Finds links in pasted HTML anchors, plain text, and the optional URL field.
// Returns [{ href, text, source }]. Missing fields -> []. Never throws.
export function extractLinks(input) {
  const body = asText(input?.body);
  const urlField = asText(input?.url).trim();
  const links = [];
  const seen = new Set();

  const add = (href, text, source) => {
    if (!href) return;
    const key = `${href}\u0000${text ?? ""}`;
    if (seen.has(key)) return;
    seen.add(key);
    links.push({ href, text, source });
  };

  // (a) HTML anchors. Visible text has inner tags removed and whitespace collapsed.
  for (const match of body.matchAll(ANCHOR_REGEX)) {
    const href = decodeEntities(match[2]).trim();
    const text = decodeEntities(match[3].replace(/<[^>]*>/g, " ")).replace(/\s+/g, " ").trim();
    add(href, text, "html");
  }

  // (b) Plain-text URLs, with anchor tags blanked out so their URLs aren't counted twice.
  const bodyWithoutAnchors = body.replace(ANCHOR_REGEX, " ");
  for (const match of bodyWithoutAnchors.matchAll(PLAIN_URL_REGEX)) {
    add(stripTrailingPunctuation(match[0]), null, "body");
  }

  // (c) The optional URL field.
  if (urlField) add(urlField, null, "url_field");

  return links;
}

// ---------------------------------------------------------------------------
// Link checks. Every check reads the link as text; no link is ever visited.

const MAX_URL_LENGTH = 100;
const MAX_HOSTNAME_LABELS = 4;
const MIN_PERCENT_ENCODED = 5;

// Words that identify a known organization inside a hostname: each official domain's
// main label ("paypal", "examplebank") and each name or alias with spaces removed
// ("bankofamerica", "office365").
const ORG_TOKENS = KNOWN_ORGS.map((org) => ({
  org,
  tokens: new Set([
    ...org.domains.map(mainLabel),
    ...[org.name, ...org.aliases].map((n) => n.toLowerCase().replace(/[^a-z0-9]/g, "")),
  ]),
}));

// Misleading hostname (zyBook 1.5 typosquatting): the hostname contains an
// organization's name as a whole label or hyphen-separated part, but the host is not
// that organization's domain or a subdomain of it. Examples: paypal.com.secure-login.xyz,
// paypal-login.example.
function misleadingHostname(hostname) {
  const parts = new Set(hostname.split(/[.-]/));
  for (const { org, tokens } of ORG_TOKENS) {
    if (belongsTo(hostname, org.domains)) continue;
    const token = [...tokens].find((t) => parts.has(t));
    if (token) return { org, token };
  }
  return null;
}

// File names such as "invoice.pdf" look like domains but are not links.
const FILE_EXTENSIONS = new Set([
  "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "csv", "jpg", "jpeg",
  "png", "gif", "html", "htm", "exe", "js",
]);

// If the visible link text looks like a URL or a bare domain, returns its hostname.
function hostnameFromText(text) {
  if (!text || /\s/.test(text)) return null;
  const candidate = /^[a-z][a-z0-9+.-]*:\/\//i.test(text) ? text : `http://${text}`;
  const parsed = parseLink(candidate);
  if (!parsed || !parsed.hostname) return null;
  if (!parsed.isIp) {
    const labels = parsed.hostname.split(".");
    const tld = labels.at(-1);
    if (labels.length < 2 || !/^[a-z]{2,}$/.test(tld) || FILE_EXTENSIONS.has(tld)) return null;
  }
  return parsed.hostname;
}

const siteOf = (hostname, isIp) => (isIp ? hostname : registrableDomain(hostname));

// Returns { parsed, issues, schemeNote } for one extracted link. Each issue is
// { category, explanation }; explanations are plain words for the results panel.
function inspectLink({ href, text }) {
  const result = parseWithUrl(href);
  if (!result) {
    return { parsed: null, issues: [], schemeNote: "Could not be parsed as a valid link." };
  }
  const { parsed, url } = result;
  const { scheme, hostname, isIp } = parsed;
  const issues = [];
  const suspicious = (explanation) => issues.push({ category: "suspicious_url", explanation });

  if (scheme === "javascript") {
    suspicious("Uses the javascript: scheme, which runs code instead of opening a web page.");
  } else if (scheme === "data") {
    suspicious("Uses the data: scheme, which embeds content directly instead of opening a web page.");
  }

  if (isIp) {
    suspicious(
      `Points to an IP address (${hostname}) instead of a domain name. Legitimate organizations rarely link to raw IP addresses.`
    );
  }

  if (url.username || url.password) {
    suspicious(
      `Contains "@" before the host. Browsers ignore everything before "@", so the real destination is ${hostname}.`
    );
  }

  if (hostname && !isIp) {
    const misleading = misleadingHostname(hostname);
    if (misleading) {
      suspicious(
        `Hostname contains "${misleading.token}" but is not on ${misleading.org.name}'s domain ` +
          `(${misleading.org.domains.join(" or ")}). It actually belongs to ${registrableDomain(hostname)}. ` +
          `This is a common way to imitate a trusted site.`
      );
    }

    if (hostname.split(".").some((label) => label.startsWith("xn--"))) {
      suspicious(
        "Hostname uses punycode (xn--), which can hide lookalike characters from other alphabets."
      );
    }
  }

  const complexity = [];
  if (href.length > MAX_URL_LENGTH) complexity.push(`it is ${href.length} characters long`);
  const labelCount = hostname.split(".").filter(Boolean).length;
  if (!isIp && labelCount > MAX_HOSTNAME_LABELS) {
    complexity.push(`the hostname has ${labelCount} parts`);
  }
  const encoded = (href.match(/%[0-9a-f]{2}/gi) || []).length;
  if (encoded >= MIN_PERCENT_ENCODED) complexity.push(`it has ${encoded} percent-encoded characters`);
  // The URL constructor drops default ports (80 for http, 443 for https).
  if (url.port) complexity.push(`it uses a non-standard port (${url.port})`);
  if (complexity.length > 0) {
    suspicious(`Is unusually complex: ${complexity.join(", ")}. Complex links can hide the real destination.`);
  }

  const textHost = hostnameFromText(text);
  if (textHost && hostname) {
    const shown = siteOf(textHost, IPV4_REGEX.test(textHost) || textHost.startsWith("["));
    const actual = siteOf(hostname, isIp);
    if (shown !== actual) {
      issues.push({
        category: "misleading_link",
        explanation: `The link text shows "${text}" (${shown}), but the link actually goes to ${actual}.`,
      });
    }
  }

  let schemeNote;
  if (scheme === "https") {
    schemeNote = "Uses HTTPS: the connection is encrypted, but HTTPS does not prove the site is trustworthy.";
  } else if (scheme === "http") {
    schemeNote = "Uses HTTP: the connection is not encrypted.";
  } else {
    schemeNote = `Uses the ${scheme}: scheme, which is not a normal web link.`;
  }

  return { parsed, issues, schemeNote };
}

// Extracts, parses, and explains every link. Invalid links are kept with invalid: true
// so the UI can show them; valid links have invalid: false plus the parsed fields.
// Every link gets an explanations array: one entry per issue, then one scheme note.
export function analyzeLinks(input) {
  return extractLinks(input).map((link) => {
    const { href, text, source } = link;
    const { parsed, issues, schemeNote } = inspectLink(link);
    const explanations = [...issues.map((issue) => issue.explanation), schemeNote];
    if (!parsed) return { href, text, source, invalid: true, explanations };
    return { ...parsed, text, source, invalid: false, explanations };
  });
}

// Findings for scoring: one per issue per link, naming the link. Invalid links give none.
export function linkRule(input) {
  return extractLinks(input).flatMap((link) =>
    inspectLink(link).issues.map(({ category, explanation }) => ({
      category,
      rule: category,
      message: `Link ${link.href}: ${explanation}`,
    }))
  );
}
