// Link extraction and parsing.
// DOM-free so Node can test it. Links are only parsed as text with the built-in URL
// constructor: this module never fetches, visits, or follows any link (no network calls).
// Pasted HTML is read with regular expressions and is never rendered or executed.

const asText = (value) => (typeof value === "string" ? value : "");

const IPV4_REGEX = /^\d{1,3}(?:\.\d{1,3}){3}$/;

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

  // Naive: last two labels (mail.example.co.uk -> co.uk). IP hosts use the full host.
  const labels = hostname.split(".").filter(Boolean);
  const domain = isIp || labels.length <= 2 ? hostname : labels.slice(-2).join(".");

  return { href: raw, scheme, hostname, domain, isIp };
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

// Extracts and parses every link. Invalid links are kept with invalid: true so the
// UI can show them; valid links have invalid: false plus the parsed fields.
export function analyzeLinks(input) {
  return extractLinks(input).map(({ href, text, source }) => {
    const parsed = parseLink(href);
    if (!parsed) return { href, text, source, invalid: true };
    return { ...parsed, text, source, invalid: false };
  });
}
