// Attachment inspection.
// DOM-free so Node can test it. Files are only read as bytes: this module never
// executes, opens, renders, or uploads a file, and never enables macros.
// The extension check uses an allow list (zyBook 8.7): only listed types get a
// signature comparison. SHA-256 (zyBook 3.7) uses Web Crypto (crypto.subtle.digest),
// which is built into browsers and Node 20+.

export const MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024;

// Magic bytes at the start of a file, and the extensions each type may use.
export const SIGNATURES = [
  { type: "pdf", label: "PDF document", magic: [0x25, 0x50, 0x44, 0x46], extensions: ["pdf"] },
  {
    type: "png",
    label: "PNG image",
    magic: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a],
    extensions: ["png"],
  },
  { type: "jpeg", label: "JPEG image", magic: [0xff, 0xd8, 0xff], extensions: ["jpg", "jpeg"] },
  { type: "gif", label: "GIF image", magic: [0x47, 0x49, 0x46, 0x38], extensions: ["gif"] },
  {
    type: "zip",
    label: "ZIP-based file (ZIP archive or modern Office document)",
    magic: [0x50, 0x4b, 0x03, 0x04],
    extensions: ["zip", "docx", "xlsx", "pptx"],
  },
  {
    type: "ole",
    label: "older Microsoft Office file (OLE)",
    magic: [0xd0, 0xcf, 0x11, 0xe0],
    extensions: ["doc", "xls", "ppt", "msg"],
  },
  {
    type: "exe",
    label: "Windows executable program",
    magic: [0x4d, 0x5a],
    extensions: ["exe", "dll", "scr"],
  },
];

// File types that can run code when opened (block list, zyBook 8.7).
export const DANGEROUS_EXTENSIONS = [
  "exe", "scr", "bat", "cmd", "com", "pif", "js", "jse", "vbs", "vbe", "wsf",
  "ps1", "jar", "msi", "hta", "lnk", "iso", "img", "reg", "dll", "cpl",
];

// Office files that can contain macros.
export const MACRO_EXTENSIONS = ["docm", "xlsm", "pptm"];

// Extensions people expect to be harmless documents or media. A name like
// "report.pdf.exe" uses one of these before the real extension to disguise the file.
const DECOY_EXTENSIONS = new Set([
  "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv",
  "jpg", "jpeg", "png", "gif", "zip", "mp3", "mp4",
]);

// Accepts Uint8Array (including Node Buffer), ArrayBuffer, or an array of numbers.
function toBytes(bytes) {
  if (bytes instanceof Uint8Array) return bytes;
  if (bytes instanceof ArrayBuffer) return new Uint8Array(bytes);
  if (ArrayBuffer.isView(bytes)) return new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (Array.isArray(bytes)) return Uint8Array.from(bytes);
  return null;
}

// Returns the signature type name ("pdf", "exe", ...) or null if none matches.
export function detectSignature(bytes) {
  const data = toBytes(bytes);
  if (!data) return null;
  const found = SIGNATURES.find(
    ({ magic }) => data.length >= magic.length && magic.every((b, i) => data[i] === b)
  );
  return found ? found.type : null;
}

// "C:\\files\\report.PDF.exe " -> { base: "report", allExtensions: ["pdf", "exe"] }.
// Trailing dots and spaces are removed because Windows ignores them, which attackers
// use to hide the real extension.
function splitName(name) {
  const fileName = name.split(/[\\/]/).pop().replace(/[.\s]+$/, "").replace(/^\.+/, "");
  const parts = fileName.split(".");
  const allExtensions = parts.slice(1).map((p) => p.toLowerCase()).filter(Boolean);
  return { fileName, allExtensions };
}

const labelFor = (type) => SIGNATURES.find((s) => s.type === type)?.label ?? type;

function formatSize(bytes) {
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes} bytes`;
}

async function sha256Hex(data) {
  const digest = await globalThis.crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

// Inspects one attachment as bytes. Missing name or bytes never throw.
export async function inspectAttachment(attachment) {
  const name = typeof attachment?.name === "string" ? attachment.name : "";
  const data = toBytes(attachment?.bytes);
  const size =
    Number.isFinite(attachment?.size) && attachment.size >= 0 ? attachment.size : (data?.length ?? 0);
  const { allExtensions } = splitName(name);
  const extension = allExtensions.at(-1) ?? "";
  const doubleExtension =
    allExtensions.length >= 2 && DECOY_EXTENSIONS.has(allExtensions.at(-2));
  const overLimit = size > MAX_ATTACHMENT_BYTES;
  const explanations = [];

  if (!name) explanations.push("No file name was provided.");
  else if (!extension) explanations.push("The file name has no extension, so its type can't be checked by name.");

  if (DANGEROUS_EXTENSIONS.includes(extension)) {
    explanations.push(`.${extension} files can run programs or scripts on your computer. Do not open this file.`);
  } else if (MACRO_EXTENSIONS.includes(extension)) {
    explanations.push(
      `.${extension} is a macro-enabled Office file. Macros can run harmful code; do not enable them.`
    );
  }

  if (doubleExtension) {
    explanations.push(
      `The name has a double extension (.${allExtensions.slice(-2).join(".")}). Only the last one ` +
        `(.${extension}) decides the real file type, so this is a common way to disguise a dangerous file.`
    );
  }

  const report = {
    name,
    extension,
    allExtensions,
    doubleExtension,
    size,
    overLimit,
    detectedType: null,
    signatureMatch: null,
    sha256: null,
    explanations,
  };

  if (overLimit) {
    explanations.push(
      `The file is ${formatSize(size)} (${size} bytes), over the ${MAX_ATTACHMENT_BYTES / (1024 * 1024)} MB limit. ` +
        "It was not inspected: no signature check and no SHA-256 hash."
    );
    return report;
  }

  if (!data) {
    explanations.push("No file content was provided, so the signature and SHA-256 hash were not checked.");
    return report;
  }

  // Signature vs. extension. Only extensions in SIGNATURES are compared (allow list).
  const detectedType = detectSignature(data);
  const expected = SIGNATURES.find((s) => s.extensions.includes(extension));
  report.detectedType = detectedType;

  if (expected) {
    const detected = SIGNATURES.find((s) => s.type === detectedType);
    report.signatureMatch = detected !== undefined && detected.extensions.includes(extension);
    if (report.signatureMatch) {
      explanations.push(
        `The file's content signature matches its .${extension} extension (${labelFor(detectedType)}), ` +
          "but this does not mean the file is safe."
      );
    } else if (detectedType) {
      explanations.push(
        `The name says .${extension}, but the content looks like a ${labelFor(detectedType)}. ` +
          "The extension does not match the content."
      );
    } else {
      explanations.push(
        `The name says .${extension}, but the content doesn't start with the signature of a ${expected.label}. ` +
          "The extension does not match the content."
      );
    }
  } else if (detectedType) {
    explanations.push(
      `Signature check isn't supported for ${extension ? `.${extension}` : "files without an extension"}, ` +
        `but the content looks like a ${labelFor(detectedType)}.`
    );
  } else {
    explanations.push(
      `Signature check isn't supported for ${extension ? `.${extension} files` : "files without an extension"}.`
    );
  }

  // SHA-256. If Web Crypto is missing, say so instead of failing silently.
  if (globalThis.crypto?.subtle) {
    report.sha256 = await sha256Hex(data);
    explanations.push(
      "SHA-256 hash calculated. It identifies this exact file and can be looked up in a malware database without sharing the file."
    );
  } else {
    explanations.push("Warning: SHA-256 hash not calculated because Web Crypto isn't available in this environment.");
  }

  return report;
}

// Inspects a list of attachments. A missing or non-array list gives [].
export async function inspectAttachments(list) {
  if (!Array.isArray(list)) return [];
  return Promise.all(list.map((attachment) => inspectAttachment(attachment)));
}

// Findings for scoring, from reports made by inspectAttachments. One finding per issue
// per file, naming the file. Over-limit files were not inspected, so they give no
// findings (analyzeEmail adds a warning for them instead).
export function attachmentRule(input) {
  const reports = Array.isArray(input?.attachments) ? input.attachments : [];
  const findings = [];

  for (const report of reports) {
    if (!report || report.overLimit) continue;
    const name = report.name || "Unnamed attachment";
    const extension = typeof report.extension === "string" ? report.extension : "";
    const add = (issue) =>
      findings.push({
        category: "dangerous_attachment",
        rule: "dangerous_attachment",
        message: `Attachment "${name}": ${issue}`,
      });

    if (DANGEROUS_EXTENSIONS.includes(extension)) {
      add(`.${extension} files can run programs or scripts on your computer.`);
    }
    if (MACRO_EXTENSIONS.includes(extension)) {
      add(`.${extension} is a macro-enabled Office file; macros can run harmful code.`);
    }
    if (report.doubleExtension) {
      const [decoy] = (report.allExtensions ?? []).slice(-2);
      add(`double extension (.${decoy}.${extension}) disguises the real file type (.${extension}).`);
    }
    if (report.signatureMatch === false) {
      add(
        report.detectedType
          ? `the content looks like a ${labelFor(report.detectedType)}, but the name says .${extension}.`
          : `the content does not match the .${extension} extension.`
      );
    }
  }

  return findings;
}
