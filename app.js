// Phishing Email Detection Platform: page logic.
//
// Security rules for this file (checked by tests/ui-safety.test.js):
// - Text from the email or the analyzer is only ever set with textContent on elements
//   made with createElement. No HTML strings are parsed.
// - No link is ever fetched, opened, or previewed, and no <a> elements are created for
//   email links. Links are shown as plain text.
// - Uploaded files are only read as bytes for the analyzer. They are never rendered or run.
//   Files over the size limit are never read at all.
// - Nothing is stored (no cookies or web storage) and nothing is logged to the console.

import { analyzeEmailAsync } from "./analyzer.js";
import { parseSender } from "./rules/content.js";
import { extractLinks, parseLink } from "./rules/links.js";
import { MAX_ATTACHMENT_BYTES, SIGNATURES } from "./rules/attachments.js";
import { buildRecommendations } from "./recommendations.js";

// Resource limits (also set as maxlength in index.html). This file is the authority.
const LIMITS = { sender: 320, subject: 500, body: 100000, url: 2048 };
const MAX_FILES = 10;
const MAX_DETECTED_SHOWN = 50;

// Text fields: element id -> limit key and a name for error messages.
const TEXT_FIELDS = {
  sender: { limit: LIMITS.sender, name: "Sender" },
  subject: { limit: LIMITS.subject, name: "Subject" },
  body: { limit: LIMITS.body, name: "Message body" },
  "manual-url": { limit: LIMITS.url, name: "URL" },
};

// Field id -> id of its inline error element.
const ERROR_IDS = {
  sender: "sender-error",
  subject: "subject-error",
  body: "body-error",
  "manual-url": "manual-url-error",
  files: "files-error",
};

const $ = (id) => document.getElementById(id);

// Creates an element. Text is set with textContent only, and string children are added
// as text nodes by append(), so nothing here is ever parsed as HTML.
function el(tag, { className, text } = {}, ...children) {
  if (String(tag).toLowerCase() === "a") {
    throw new Error("Links are shown as plain text; <a> elements are not allowed.");
  }
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  for (const child of children) {
    if (child !== undefined && child !== null && child !== false) node.append(child);
  }
  return node;
}

function formatBytes(bytes) {
  if (!Number.isFinite(bytes)) return "unknown size";
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes} bytes`;
}

const LIMIT_MB = MAX_ATTACHMENT_BYTES / (1024 * 1024);
const formatCount = (n) => n.toLocaleString("en-US");

// ---------------------------------------------------------------------------
// Form input

function readForm() {
  return {
    sender: $("sender").value,
    subject: $("subject").value,
    body: $("body").value,
    url: $("manual-url").value.trim(),
    fileList: Array.from($("files").files ?? []),
  };
}

// Returns { fieldId: message } for every problem. Empty object means valid.
// The HTML5 attributes (required, maxlength, type) help the browser and assistive tech,
// but these checks are the authority and run on every submit.
function validateInput(input) {
  const errors = {};
  const tooLong = (field, value) => {
    const { limit, name } = TEXT_FIELDS[field];
    if (value.length > limit) {
      errors[field] = `${name} is too long: ${formatCount(value.length)} characters (limit ${formatCount(limit)}).`;
      return true;
    }
    return false;
  };

  const sender = input.sender.trim();
  if (!sender) {
    errors.sender = "Enter the sender's email address.";
  } else if (!tooLong("sender", input.sender) && parseSender(sender) === null) {
    errors.sender =
      "Enter a valid sender, either name@domain.example or Name <name@domain.example>.";
  }

  tooLong("subject", input.subject);

  if (!input.body.trim()) {
    errors.body = "Enter the message body.";
  } else {
    tooLong("body", input.body);
  }

  if (input.url && !tooLong("manual-url", input.url) && parseLink(input.url) === null) {
    errors["manual-url"] =
      "This is not a valid URL. Include the scheme, for example http://192.0.2.10/login. It will not be visited.";
  }

  if (input.fileList.length > MAX_FILES) {
    errors.files = `Too many files: ${input.fileList.length} selected (limit ${MAX_FILES}).`;
  }

  return errors;
}

function setFieldError(fieldId, message) {
  const errorEl = $(ERROR_IDS[fieldId]);
  const field = $(fieldId);
  if (message) {
    errorEl.textContent = message;
    errorEl.hidden = false;
    field.setAttribute("aria-invalid", "true");
  } else {
    errorEl.textContent = "";
    errorEl.hidden = true;
    field.removeAttribute("aria-invalid");
  }
}

function showErrors(errors) {
  for (const fieldId of Object.keys(ERROR_IDS)) setFieldError(fieldId, errors[fieldId]);
  const ids = Object.keys(ERROR_IDS).filter((id) => errors[id]);
  if (ids.length > 0) {
    setStatus(
      ids.length === 1 ? "Please fix the problem shown above." : `Please fix the ${ids.length} problems shown above.`,
      true
    );
    $(ids[0]).focus();
  } else {
    setStatus("");
  }
}

function setStatus(message, isError = false) {
  const status = $("form-status");
  status.textContent = message;
  status.classList.toggle("is-error", isError);
}

// ---------------------------------------------------------------------------
// Live list of links found in the body (plain text, using the engine's extraction).

let detectTimer = null;

function updateDetectedUrls() {
  const list = $("detected-urls");
  const links = extractLinks({ body: $("body").value });
  list.replaceChildren();

  for (const link of links.slice(0, MAX_DETECTED_SHOWN)) {
    const item = el("li", { text: link.href });
    if (link.text && link.text !== link.href) {
      item.append(el("span", { className: "file-note", text: `Shown as: ${link.text}` }));
    }
    list.append(item);
  }
  if (links.length > MAX_DETECTED_SHOWN) {
    list.append(el("li", { text: `…and ${links.length - MAX_DETECTED_SHOWN} more.` }));
  }

  list.hidden = links.length === 0;
  $("detected-empty").hidden = links.length > 0;
}

function scheduleDetectedUrls() {
  clearTimeout(detectTimer);
  detectTimer = setTimeout(updateDetectedUrls, 200);
}

// ---------------------------------------------------------------------------
// Attachments

// Lists selected files by name and size. Nothing is read here.
function renderFileList() {
  const files = Array.from($("files").files ?? []);
  const list = $("file-list");
  list.replaceChildren();

  for (const file of files) {
    const over = file.size > MAX_ATTACHMENT_BYTES;
    const item = el("li", { className: over ? "not-inspected" : "" });
    item.append(el("span", { className: "mono", text: file.name || "Unnamed file" }));
    item.append(el("span", { className: "file-note", text: formatBytes(file.size) }));
    if (over) {
      item.append(
        el("span", {
          className: "file-note",
          text: `Over ${LIMIT_MB} MB: this file will not be read or inspected, so the score may be incomplete.`,
        })
      );
    }
    list.append(item);
  }

  list.hidden = files.length === 0;
  setFieldError(
    "files",
    files.length > MAX_FILES ? `Too many files: ${files.length} selected (limit ${MAX_FILES}).` : ""
  );
}

// Converts selected files to the analyzer's input: [{ name, size, bytes }].
// The size is checked BEFORE reading: a file over the limit is passed as { name, size }
// with no bytes and is never read. The analyzer then reports it as not inspected.
async function prepareFiles(fileList) {
  const files = [];
  const notes = [];
  for (const file of fileList) {
    const name = file.name || "Unnamed file";
    if (file.size > MAX_ATTACHMENT_BYTES) {
      files.push({ name, size: file.size });
      continue;
    }
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      files.push({ name, size: file.size, bytes });
    } catch {
      files.push({ name, size: file.size });
      notes.push(`${name} could not be read, so its content was not inspected.`);
    }
  }
  return { files, notes };
}

// ---------------------------------------------------------------------------
// Results. Every value from the analyzer (which may quote the email) goes through el(),
// so it is set as text and never parsed as HTML.

const ASSESSMENTS = {
  Low: "Low risk (0–29). No strong phishing indicators were found. This does not confirm the email is legitimate.",
  // Low, but some categories were triggered (e.g. a dangerous attachment alone is 15).
  LowWithFindings:
    "Low risk (0–29). Some indicators were found (see Findings), but not enough for a higher rating. This does not confirm the email is legitimate.",
  Medium:
    "Medium risk (30–59). Some phishing indicators were found. Review the message carefully and verify the sender before acting on it.",
  High:
    "High risk (60–100). Avoid interacting with this email and verify it independently through a separate, trusted channel.",
};

const SOURCE_LABELS = {
  html: "HTML link in the body",
  body: "Text in the body",
  url_field: "Additional URL field",
};

const typeLabel = (type) => SIGNATURES.find((s) => s.type === type)?.label ?? type;

// A <dl> of [term, value] pairs. Values are text; a value of null is skipped.
function facts(pairs) {
  const list = el("dl", { className: "facts" });
  for (const [term, value, valueClass] of pairs) {
    if (value === null || value === undefined) continue;
    list.append(el("dt", { text: term }), el("dd", { className: valueClass, text: value }));
  }
  return list;
}

function bulletList(items, className = "bullets") {
  const list = el("ul", { className });
  for (const item of items) list.append(el("li", { text: item }));
  return list;
}

function renderSummary(result) {
  const level = ["Low", "Medium", "High"].includes(result.classification) ? result.classification : "Low";
  const badge = $("score-badge");
  badge.className = `badge badge-${level.toLowerCase()}`;
  $("score-value").textContent = `${result.score}/100`;
  $("score-class").textContent = `${level} risk`;
  $("assessment").textContent =
    level === "Low" && result.breakdown.length > 0 ? ASSESSMENTS.LowWithFindings : ASSESSMENTS[level];
}

function renderRecommendations(result) {
  const list = $("recommendations");
  list.replaceChildren();
  for (const text of buildRecommendations(result)) list.append(el("li", { text }));
}

function renderBreakdown(result) {
  const body = $("breakdown-body");
  body.replaceChildren();
  let rawTotal = 0;

  for (const { label, points } of result.breakdown) {
    rawTotal += points;
    body.append(el("tr", {}, el("td", { text: label }), el("td", { className: "num", text: `+${points}` })));
  }
  if (result.breakdown.length === 0) {
    body.append(el("tr", {}, el("td", { text: "No categories triggered" }), el("td", { className: "num", text: "0" })));
  }

  $("breakdown-total").textContent = String(result.score);
  $("cap-note").textContent =
    rawTotal > 100
      ? `The categories add up to ${rawTotal} points; the score is capped at 100.`
      : "Each category adds its points once, however many findings it has. The score is capped at 100.";
}

// Findings grouped under their category label, in breakdown order.
function renderFindings(result) {
  const container = $("findings");
  container.replaceChildren();
  if (result.findings.length === 0) {
    container.append(el("p", { className: "empty", text: "No phishing indicators were found." }));
    return;
  }

  const groups = new Map(result.breakdown.map((item) => [item.category, { label: item.label, messages: [] }]));
  for (const finding of result.findings) {
    if (!groups.has(finding.category)) {
      groups.set(finding.category, { label: "Other (not scored)", messages: [] });
    }
    groups.get(finding.category).messages.push(finding.message);
  }

  for (const { label, messages } of groups.values()) {
    if (messages.length === 0) continue;
    container.append(el("div", { className: "finding-group" }, el("h4", { text: label }), bulletList(messages)));
  }
}

function renderLinks(result) {
  const container = $("links");
  container.replaceChildren();
  if (result.links.length === 0) {
    container.append(el("p", { className: "empty", text: "No links were found." }));
    return;
  }

  for (const link of result.links) {
    // Every link ends with one scheme note; anything before it is an issue.
    // Invalid links have a single "could not be parsed" explanation.
    const flagged = link.invalid || link.explanations.length > 1;
    const card = el("article", { className: flagged ? "card flagged" : "card" });
    card.append(el("p", { className: "card-title mono", text: link.href }));
    card.append(
      facts([
        // hostname, not domain: the analyzer's domain field is a simple last-two-labels guess.
        ["Hostname", link.invalid ? null : link.hostname || "(none)", "mono"],
        ["Scheme", link.invalid ? null : link.scheme],
        ["Shown as", link.text || null, "mono"],
        ["Found in", SOURCE_LABELS[link.source] ?? link.source],
        ["Status", link.invalid ? "Not a valid link" : null],
      ])
    );
    card.append(bulletList(link.explanations));
    container.append(card);
  }
}

// The content was not inspected if the file was over the limit (never read) or could
// not be read (the analyzer then says no content was provided).
const contentInspected = (report) =>
  !report.overLimit && !report.explanations.some((e) => e.startsWith("No file content was provided"));

function signatureText(report) {
  if (!contentInspected(report)) return "Not checked (file content was not inspected)";
  if (report.signatureMatch === true) return "Matches extension";
  if (report.signatureMatch === false) return "Does not match extension";
  return "Not a supported type for signature check";
}

function renderAttachments(result) {
  const container = $("attachments");
  container.replaceChildren();
  if (result.attachments.length === 0) {
    container.append(el("p", { className: "empty", text: "No attachments were added." }));
    return;
  }

  const flaggedNames = new Set(
    result.findings
      .filter((f) => f.category === "dangerous_attachment")
      .map((f) => f.message.match(/^Attachment "(.*)": /s)?.[1])
  );

  for (const report of result.attachments) {
    const name = report.name || "Unnamed attachment";
    const flagged = flaggedNames.has(name) || report.overLimit;
    const card = el("article", { className: flagged ? "card flagged" : "card" });
    card.append(el("p", { className: "card-title mono", text: name }));
    if (report.overLimit) {
      card.append(
        el("p", {
          className: "error",
          text: `Not inspected: over ${LIMIT_MB} MB. This file was not read, so the score may be incomplete.`,
        })
      );
    }
    card.append(
      facts([
        ["Size", formatBytes(report.size)],
        [
          "Detected type",
          report.detectedType
            ? typeLabel(report.detectedType)
            : contentInspected(report)
              ? "Not recognized"
              : "Not checked",
        ],
        ["Signature", signatureText(report)],
        ["SHA-256", report.sha256 ?? "Not calculated", "mono"],
      ])
    );
    card.append(bulletList(report.explanations));
    container.append(card);
  }
}

// Analyzer warnings plus the page's own notes (e.g. a file that could not be read).
function renderWarnings(result, notes) {
  const all = [...result.warnings, ...notes];
  const list = $("warnings");
  list.replaceChildren();
  for (const text of all) list.append(el("li", { text }));
  $("warnings-block").hidden = all.length === 0;
}

function renderResults(result, notes = []) {
  // The page's own notes also count as warnings for the recommendations.
  const withNotes = { ...result, warnings: [...result.warnings, ...notes] };
  renderSummary(result);
  renderRecommendations(withNotes);
  renderBreakdown(result);
  renderFindings(result);
  renderLinks(result);
  renderAttachments(result);
  renderWarnings(result, notes);

  showView("results");
  revealResults();
  // Move keyboard and screen reader focus to the results (and scroll them into view).
  $("results-heading").focus();
}

// Reveal each group when it enters the viewport. Content remains readable without
// animation, including when reduced motion is enabled or observers are unavailable.
let revealObserver;

function revealResults() {
  revealObserver?.disconnect();
  const sections = $("results").querySelectorAll(".result-section");
  for (const section of sections) section.classList.remove("revealed");

  if (!("IntersectionObserver" in window) ||
      window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

  revealObserver = new IntersectionObserver((entries, observer) => {
    for (const entry of entries) {
      if (!entry.isIntersecting) continue;
      entry.target.classList.add("revealed");
      observer.unobserve(entry.target);
    }
  }, { threshold: 0 });
  for (const section of sections) revealObserver.observe(section);
}

function clearResults() {
  revealObserver?.disconnect();
  for (const id of ["recommendations", "breakdown-body", "findings", "links", "attachments", "warnings"]) {
    $(id).replaceChildren();
  }
  for (const id of ["score-value", "score-class", "assessment", "breakdown-total", "cap-note"]) {
    $(id).textContent = "";
  }
  $("score-badge").className = "badge";
  $("warnings-block").hidden = true;
  $("results").hidden = true;
}

// ---------------------------------------------------------------------------
// Clear and submit

// Incremented on Clear so an analysis that finishes afterwards is discarded.
let generation = 0;

function showView(view) {
  const editing = view === "form";
  $("input-panel").hidden = !editing;
  $("awaiting-panel").hidden = !editing;
  $("analyzing-panel").hidden = view !== "analyzing";
  $("results").hidden = view !== "results";
  $("analysis-layout").classList.toggle("single-view", !editing);
}

function resetAnalyzeButton() {
  $("analyze-btn").disabled = false;
  $("analyze-btn").textContent = "Analyze Email";
  $("results").removeAttribute("aria-busy");
}

function onClear() {
  generation += 1;
  clearTimeout(detectTimer);
  $("email-form").reset(); // also empties the file input
  showErrors({});
  setStatus("");
  updateDetectedUrls();
  renderFileList();
  clearResults();
  resetAnalyzeButton();
  showView("form");
  $("sender").focus();
}

async function onAnalyze(event) {
  event.preventDefault();
  const button = $("analyze-btn");
  if (button.disabled) return;

  const input = readForm();
  const errors = validateInput(input);
  showErrors(errors);
  if (Object.keys(errors).length > 0) return;

  const run = ++generation;
  button.disabled = true;
  button.textContent = "Analyzing…";
  $("results").setAttribute("aria-busy", "true");
  showView("analyzing");
  $("analyzing-heading").focus();

  // Keep the transition visible for fast analyses while file inspection runs.
  const minimumDisplay = new Promise((resolve) => setTimeout(resolve, 1000));

  try {
    const { files, notes } = await prepareFiles(input.fileList);
    if (run !== generation) return;
    const result = await analyzeEmailAsync({
      sender: input.sender.trim(),
      subject: input.subject,
      body: input.body,
      url: input.url,
      files,
    });
    await minimumDisplay;
    if (run !== generation) return; // Cleared while analyzing.
    renderResults(result, notes);
  } catch {
    if (run !== generation) return;
    // Nothing about the email is logged; the user just sees a friendly message.
    clearResults();
    showView("form");
    setStatus("Something went wrong while analyzing this email. Please check the input and try again.", true);
    $("sender").focus();
  } finally {
    if (run === generation) resetAnalyzeButton();
  }
}

// Blocks a paste that would go over a field's limit, instead of letting maxlength cut
// the text silently, and explains why inline.
function onPaste(event) {
  const field = event.target;
  const config = TEXT_FIELDS[field.id];
  if (!config) return;
  const pasted = event.clipboardData?.getData("text") ?? "";
  const selected = (field.selectionEnd ?? 0) - (field.selectionStart ?? 0);
  const newLength = field.value.length - selected + pasted.length;
  if (newLength > config.limit) {
    event.preventDefault();
    setFieldError(
      field.id,
      `Not pasted: the result would be ${formatCount(newLength)} characters (limit ${formatCount(config.limit)}).`
    );
  }
}

function init() {
  const form = $("email-form");
  // Start empty, even if the browser tried to restore earlier input.
  form.reset();

  form.addEventListener("submit", onAnalyze);
  $("clear-btn").addEventListener("click", onClear);
  $("another-email-btn").addEventListener("click", onClear);
  $("cancel-analysis-btn").addEventListener("click", onClear);
  $("files").addEventListener("change", renderFileList);

  for (const id of Object.keys(TEXT_FIELDS)) {
    const field = $(id);
    field.addEventListener("paste", onPaste);
    field.addEventListener("input", () => setFieldError(id, ""));
  }
  $("body").addEventListener("input", scheduleDetectedUrls);

  // Returning to the page from the back/forward cache: clear everything.
  window.addEventListener("pageshow", (event) => {
    if (event.persisted) onClear();
  });

  updateDetectedUrls();
  renderFileList();
}

init();
