// Bounded recursive scanner for agent tool arguments. Never evaluates input.

const { validateUrl } = require('./url.cjs');

const DEFAULT_MAX_DEPTH = 12;
const DEFAULT_MAX_NODES = 10_000;
const URL_KEY_RE = /^(url|uri|href|link|target|endpoint|website|webhook|callback|redirect|redirect_uri|next|return_to|image_url|avatar_url|src|dest|destination)$/i;

function looksLikeUrl(value) {
  return typeof value === 'string' && /^[a-z][a-z\d+.-]*:\/\//i.test(value);
}

/**
 * Recursively scan nested JSON-ish values for URLs and validate each one.
 * Cycles are safely reported and do not hang the scanner.
 */
function scanToolArguments(value, options) {
  const opts = options && typeof options === 'object' ? options : {};
  const maxDepth = Number.isInteger(opts.maxDepth) && opts.maxDepth >= 0 ? opts.maxDepth : DEFAULT_MAX_DEPTH;
  const maxNodes = Number.isInteger(opts.maxNodes) && opts.maxNodes > 0 ? opts.maxNodes : DEFAULT_MAX_NODES;
  const validationOptions = opts.options || opts;
  const findings = [];
  const seen = new WeakSet();
  let nodes = 0;

  function visit(node, path, depth) {
    nodes += 1;
    if (nodes > maxNodes) return;
    if (depth > maxDepth) return;
    if (typeof node === 'string') {
      if (!looksLikeUrl(node)) return;
      const result = validateUrl(node, validationOptions);
      findings.push({ path, value: node, ...result });
      return;
    }
    if (node === null || typeof node !== 'object') return;
    if (seen.has(node)) return;
    seen.add(node);
    if (Array.isArray(node)) {
      for (let i = 0; i < node.length && nodes <= maxNodes; i += 1) visit(node[i], `${path}[${i}]`, depth + 1);
      return;
    }
    for (const [key, child] of Object.entries(node)) {
      if (nodes > maxNodes) break;
      if (typeof child === 'string' && looksLikeUrl(child) && URL_KEY_RE.test(key)) {
        const result = validateUrl(child, validationOptions);
        findings.push({ path: `${path}.${key}`, value: child, ...result });
      } else {
        visit(child, `${path}.${key}`, depth + 1);
      }
    }
  }

  visit(value, '$', 0);
  const rejected = findings.filter((finding) => !finding.ok);
  return {
    ok: rejected.length === 0,
    findings,
    rejected: rejected.length,
    scanned: findings.length,
    truncated: nodes > maxNodes,
  };
}

exports.scanToolArguments = scanToolArguments;
