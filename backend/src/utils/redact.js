/**
 * Privacy helpers — redact sensitive identifiers from logs and evidence.
 * Detected identifiers are masked by default (show first 2 / last 2 chars max).
 */

export function redactText(text, { keepEvidenceWords = true } = {}) {
  if (!text) return '';
  let out = String(text);
  // Aadhaar: 12 digits (allow spaces/dashes)
  out = out.replace(/\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b/g, 'XXXX-XXXX-XXXX');
  // PAN: 5 letters 4 digits 1 letter
  out = out.replace(/\b[A-Z]{5}\d{4}[A-Z]\b/gi, 'XXXXX0000X');
  // Bank account-ish long digit runs (9-18 digits)
  out = out.replace(/\b\d{9,18}\b/g, '[REDACTED-ACCT]');
  // Card 16 digits
  out = out.replace(/\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g, 'XXXX-XXXX-XXXX-XXXX');
  // OTP 4-8 digits near otp keyword — mask digits only
  out = out.replace(/(\botp\b[\s:.-]*)\d{4,8}/gi, '$1••••••');
  // UPI ids
  out = out.replace(/[\w.\-]{2,}@[a-zA-Z]{2,}/g, '[REDACTED-UPI]');
  // Phone: +91 / 10-digit starting 6-9
  out = out.replace(/(\+?91[\s-]?)?[6-9]\d{9}\b/g, '[REDACTED-PHONE]');
  return out;
}

/** Short excerpt helper — clamp length, redact, add ellipses. */
export function excerpt(text, maxLen = 160) {
  const r = redactText(text);
  if (r.length <= maxLen) return r;
  return r.slice(0, maxLen).trimEnd() + '…';
}
