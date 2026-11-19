import { test } from "node:test";
import assert from "node:assert/strict";
import {
  MAX_ATTACHMENT_BYTES,
  detectSignature,
  inspectAttachment,
  inspectAttachments,
} from "../rules/attachments.js";

// All "files" below are small fictional byte arrays. Nothing is executed or opened.

const bytesOf = (...values) => Uint8Array.from(values);
const ascii = (text) => new TextEncoder().encode(text);

const PDF = ascii("%PDF-1.7\n% fictional sample\n");
const MZ = bytesOf(0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00);
const PK = bytesOf(0x50, 0x4b, 0x03, 0x04, 0x14, 0x00);

test("SHA-256 of empty bytes", async () => {
  const report = await inspectAttachment({ name: "empty.txt", bytes: new Uint8Array(0) });
  assert.equal(report.sha256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
});

test('SHA-256 of "abc"', async () => {
  const report = await inspectAttachment({ name: "abc.txt", bytes: ascii("abc") });
  assert.equal(report.sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
});

test("PDF bytes named file.pdf -> signatureMatch true", async () => {
  const report = await inspectAttachment({ name: "file.pdf", bytes: PDF });
  assert.equal(report.extension, "pdf");
  assert.equal(report.detectedType, "pdf");
  assert.equal(report.signatureMatch, true);
  assert.equal(report.doubleExtension, false);
  assert.equal(report.size, PDF.length);
  assert.equal(report.overLimit, false);
  assert.match(report.explanations.join(" "), /matches its \.pdf extension/);
});

test("MZ bytes named invoice.pdf -> detectedType exe, signatureMatch false", async () => {
  const report = await inspectAttachment({ name: "invoice.pdf", bytes: MZ });
  assert.equal(report.detectedType, "exe");
  assert.equal(report.signatureMatch, false);
  assert.match(report.explanations.join(" "), /Windows executable.*does not match/);
});

test("report.pdf.exe -> doubleExtension true", async () => {
  const report = await inspectAttachment({ name: "report.pdf.exe", bytes: MZ });
  assert.deepEqual(report.allExtensions, ["pdf", "exe"]);
  assert.equal(report.extension, "exe");
  assert.equal(report.doubleExtension, true);
  assert.equal(report.signatureMatch, true);
  assert.match(report.explanations.join(" "), /double extension \(\.pdf\.exe\)/);
});

test("trailing dots and spaces don't hide the real extension", async () => {
  const report = await inspectAttachment({ name: "report.pdf.exe. . ", bytes: MZ });
  assert.equal(report.extension, "exe");
  assert.equal(report.doubleExtension, true);
});

test("dotted names that aren't disguises are not double extensions", async () => {
  const report = await inspectAttachment({ name: "notes.v2.final.txt", bytes: ascii("hi") });
  assert.deepEqual(report.allExtensions, ["v2", "final", "txt"]);
  assert.equal(report.doubleExtension, false);
});

test("docx with PK header -> match", async () => {
  const report = await inspectAttachment({ name: "Syllabus.DOCX", bytes: PK });
  assert.equal(report.extension, "docx");
  assert.equal(report.detectedType, "zip");
  assert.equal(report.signatureMatch, true);
});

test("detectSignature recognizes each supported type", () => {
  assert.equal(detectSignature(PDF), "pdf");
  assert.equal(detectSignature(bytesOf(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a)), "png");
  assert.equal(detectSignature(bytesOf(0xff, 0xd8, 0xff, 0xe0)), "jpeg");
  assert.equal(detectSignature(ascii("GIF89a")), "gif");
  assert.equal(detectSignature(PK), "zip");
  assert.equal(detectSignature(bytesOf(0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1)), "ole");
  assert.equal(detectSignature(MZ), "exe");
  assert.equal(detectSignature(ascii("plain text")), null);
  assert.equal(detectSignature(PDF.buffer), "pdf");
  assert.equal(detectSignature([0x4d, 0x5a]), "exe");
  assert.equal(detectSignature(undefined), null);
});

test("unknown type -> signatureMatch null", async () => {
  const report = await inspectAttachment({ name: "notes.txt", bytes: ascii("hello") });
  assert.equal(report.detectedType, null);
  assert.equal(report.signatureMatch, null);
  assert.match(report.explanations.join(" "), /isn't supported for \.txt/);
});

test("unsupported extension with executable content is still explained", async () => {
  const report = await inspectAttachment({ name: "readme.txt", bytes: MZ });
  assert.equal(report.signatureMatch, null);
  assert.equal(report.detectedType, "exe");
  assert.match(report.explanations.join(" "), /looks like a Windows executable/);
});

test("over 5 MB -> overLimit true, sha256 null, not inspected", async () => {
  const report = await inspectAttachment({
    name: "big.pdf",
    size: MAX_ATTACHMENT_BYTES + 1,
    bytes: PDF,
  });
  assert.equal(report.overLimit, true);
  assert.equal(report.sha256, null);
  assert.equal(report.detectedType, null);
  assert.equal(report.signatureMatch, null);
  assert.match(report.explanations.join(" "), /\(5242881 bytes\), over the 5 MB limit.*not inspected/);
});

test("exactly 5 MB is within the limit", async () => {
  const report = await inspectAttachment({ name: "edge.pdf", size: MAX_ATTACHMENT_BYTES, bytes: PDF });
  assert.equal(report.overLimit, false);
});

test("missing fields don't crash", async () => {
  const empty = await inspectAttachment({});
  assert.equal(empty.name, "");
  assert.equal(empty.extension, "");
  assert.deepEqual(empty.allExtensions, []);
  assert.equal(empty.size, 0);
  assert.equal(empty.sha256, null);
  assert.ok(empty.explanations.length > 0);

  const noBytes = await inspectAttachment({ name: "file.pdf" });
  assert.equal(noBytes.signatureMatch, null);
  assert.match(noBytes.explanations.join(" "), /No file content/);

  const noName = await inspectAttachment({ bytes: PDF });
  assert.equal(noName.detectedType, "pdf");
  assert.equal(noName.signatureMatch, null);

  await inspectAttachment(undefined);
  await inspectAttachment(null);
});

test("inspectAttachments handles lists and bad input", async () => {
  const reports = await inspectAttachments([
    { name: "file.pdf", bytes: PDF },
    { name: "report.pdf.exe", bytes: MZ },
  ]);
  assert.deepEqual(reports.map((r) => r.signatureMatch), [true, true]);
  assert.deepEqual(reports.map((r) => r.doubleExtension), [false, true]);
  assert.deepEqual(await inspectAttachments(undefined), []);
  assert.deepEqual(await inspectAttachments("nope"), []);
});
