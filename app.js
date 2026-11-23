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

import { parseSender } from "./rules/content.js";
import { extractLinks, parseLink } from "./rules/links.js";
import { MAX_ATTACHMENT_BYTES } from "./rules/attachments.js";

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
// Clear and submit

// Incremented on Clear so an analysis that finishes afterwards is discarded.
let generation = 0;

function onClear() {
  generation += 1;
  clearTimeout(detectTimer);
  $("email-form").reset(); // also empties the file input
  showErrors({});
  setStatus("");
  updateDetectedUrls();
  renderFileList();
  $("results").hidden = true;
  $("sender").focus();
}

function onSubmit(event) {
  event.preventDefault();
  const input = readForm();
  const errors = validateInput(input);
  showErrors(errors);
  if (Object.keys(errors).length > 0) return;
  setStatus("Input is valid.");
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

  form.addEventListener("submit", onSubmit);
  $("clear-btn").addEventListener("click", onClear);
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
