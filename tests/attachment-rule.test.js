import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeEmail, analyzeEmailAsync } from "../analyzer.js";
import { attachmentRule, inspectAttachment, MAX_ATTACHMENT_BYTES } from "../rules/attachments.js";

// All senders, messages, and "files" below are fictional. File contents are small,
// harmless byte arrays; nothing is executed or opened.

const ascii = (text) => new TextEncoder().encode(text);
const HARMLESS = ascii("This is a harmless test file for the phishing project.\n");
const PDF = ascii("%PDF-1.7\n% fictional sample\n");
const MZ = Uint8Array.from([0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00]);
const PK = Uint8Array.from([0x50, 0x4b, 0x03, 0x04, 0x14, 0x00]);

const ROUTINE = {
  sender: "registrar@northfield-university.example",
  subject: "Spring course schedule",
  body: "Hello students, the spring course schedule is attached. See you next term.",
};

const categories = (result) => result.breakdown.map((item) => item.category);

test("README sample: harmless report.pdf.exe -> 15 Low", async () => {
  const result = await analyzeEmailAsync({
    ...ROUTINE,
    files: [{ name: "report.pdf.exe", bytes: HARMLESS }],
  });
  assert.equal(result.score, 15);
  assert.equal(result.classification, "Low");
  assert.deepEqual(categories(result), ["dangerous_attachment"]);
  // Dangerous extension, double extension, and content that isn't an executable.
  const messages = result.findings.map((f) => f.message);
  assert.equal(messages.length, 3);
  assert.ok(messages.every((m) => m.startsWith('Attachment "report.pdf.exe":')));
  assert.equal(result.attachments.length, 1);
  assert.equal(result.attachments[0].doubleExtension, true);
});

test("README sample: routine message with a real PDF -> 0 Low, 'does not mean the file is safe'", async () => {
  const result = await analyzeEmailAsync({
    ...ROUTINE,
    files: [{ name: "schedule.pdf", bytes: PDF }],
  });
  assert.equal(result.score, 0);
  assert.equal(result.classification, "Low");
  assert.deepEqual(result.findings, []);
  assert.deepEqual(result.warnings, []);
  const [report] = result.attachments;
  assert.equal(report.signatureMatch, true);
  assert.match(report.explanations.join(" "), /does not mean the file is safe/);
  assert.match(report.sha256, /^[0-9a-f]{64}$/);
});

test("README demo: urgent password request + IP URL + report.pdf.exe -> 65 High", async () => {
  const result = await analyzeEmailAsync({
    sender: "it-support@northfield-university.example",
    subject: "Urgent: password verification required",
    body: "Reply with your current password at http://192.0.2.15/verify.",
    files: [{ name: "report.pdf.exe", bytes: HARMLESS }],
  });
  assert.equal(result.score, 65);
  assert.equal(result.classification, "High");
  assert.deepEqual(categories(result), [
    "urgency_threat",
    "sensitive_info",
    "suspicious_url",
    "dangerous_attachment",
  ]);
});

test(".docm -> macro finding", async () => {
  const result = await analyzeEmailAsync({ files: [{ name: "Budget.docm", bytes: PK }] });
  assert.equal(result.score, 15);
  assert.equal(result.findings.length, 1);
  assert.match(result.findings[0].message, /"Budget\.docm": \.docm is a macro-enabled Office file/);
  assert.match(result.attachments[0].explanations.join(" "), /macro-enabled/);
});

test(".exe with MZ (matching signature) -> still a finding", async () => {
  const result = await analyzeEmailAsync({ files: [{ name: "setup.exe", bytes: MZ }] });
  assert.equal(result.attachments[0].signatureMatch, true);
  assert.equal(result.score, 15);
  assert.equal(result.findings.length, 1);
  assert.match(result.findings[0].message, /\.exe files can run programs/);
  assert.match(result.attachments[0].explanations.join(" "), /does not mean the file is safe/);
});

test("signature mismatch alone -> finding naming the detected type", async () => {
  const result = await analyzeEmailAsync({ files: [{ name: "invoice.pdf", bytes: MZ }] });
  assert.equal(result.findings.length, 1);
  assert.match(
    result.findings[0].message,
    /"invoice\.pdf": the content looks like a Windows executable program, but the name says \.pdf/
  );
});

test("over 5 MB -> warning, 0 points", async () => {
  const result = await analyzeEmailAsync({
    ...ROUTINE,
    files: [{ name: "lecture.exe", size: MAX_ATTACHMENT_BYTES + 1, bytes: MZ }],
  });
  assert.equal(result.score, 0);
  assert.deepEqual(result.findings, []);
  assert.deepEqual(result.warnings, ["lecture.exe was not inspected: larger than 5 MB"]);
  assert.equal(result.attachments[0].sha256, null);
});

test("raw files passed to analyzeEmail are not scored silently", () => {
  const result = analyzeEmail({ attachments: [{ name: "report.pdf.exe", bytes: MZ }] });
  assert.equal(result.score, 0);
  assert.equal(result.warnings.length, 1);
  assert.match(result.warnings[0], /report\.pdf\.exe was not inspected: pass raw files as input\.files/);
});

test("analyzeEmail stays synchronous and accepts inspected reports", async () => {
  const report = await inspectAttachment({ name: "setup.exe", bytes: MZ });
  const result = analyzeEmail({ attachments: [report] });
  assert.ok(!(result instanceof Promise));
  assert.equal(result.score, 15);
});

test("no attachments -> empty list, no warnings", async () => {
  const sync = analyzeEmail({});
  assert.deepEqual(sync.attachments, []);
  assert.deepEqual(sync.warnings, []);
  const viaAsync = await analyzeEmailAsync({ ...ROUTINE });
  assert.deepEqual(viaAsync.attachments, []);
  assert.equal(viaAsync.score, 0);
  assert.deepEqual(attachmentRule({}), []);
  assert.deepEqual(attachmentRule({ attachments: "nope" }), []);
});
