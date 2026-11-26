// Structured, stable errors. No internal frames are exposed to callers.

const MAX_INPUT_DISPLAY = 240;
const CONTROL_RE = /[\u0000-\u001f\u007f-\u009f]/g;

function safeString(value) {
  if (typeof value === 'string') return value;
  if (value === null || value === undefined) return '';
  try {
    return String(value);
  } catch {
    return '<unprintable>';
  }
}

function redactInput(value) {
  let text = safeString(value).replace(CONTROL_RE, '?');
  text = text.replace(/([a-z][a-z\d+.-]*:\/\/)([^/@\s]*@)/i, '$1[redacted]@');
  if (text.length > MAX_INPUT_DISPLAY) text = `${text.slice(0, MAX_INPUT_DISPLAY)}...[truncated]`;
  return text;
}

export class UrlGuardError extends Error {
  constructor(code, reason, input) {
    const message = safeString(reason) || 'URL rejected';
    super(message);
    this.name = 'UrlGuardError';
    this.code = safeString(code) || 'INVALID_URL';
    this.reason = message;
    this.input = redactInput(input);
    // A fixed, non-leaking stack keeps internal file paths and call frames out of logs.
    this.stack = `UrlGuardError [${this.code}]: ${this.reason}`;
  }

  toJSON() {
    return { name: this.name, code: this.code, reason: this.reason, input: this.input };
  }
}

export function guardError(code, reason, input) {
  return new UrlGuardError(code, reason, input);
}

export function fail(code, reason, input) {
  return { ok: false, code, detail: reason, input: redactInput(input) };
}
