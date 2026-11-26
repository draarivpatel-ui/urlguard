// Bounded recursive scanner for agent tool arguments. Never evaluates input.

const { validateUrl, ownOption } = require('./url.cjs');

const DEFAULT_MAX_DEPTH = 12;
const DEFAULT_MAX_NODES = 10_000;
const URL_KEY_RE = /^(url|uri|href|link|target|endpoint|website|webhook|callback|redirect|redirect_uri|next|return_to|image_url|avatar_url|src|dest|destination)$/i;
const SCHEME_RE = /^[a-z][a-z\d+.-]*:/i;
// WHATWG parses these schemes as an authority even without slashes, so
// "https:127.0.0.1" is a real network destination and must be scanned.
const SPECIAL_SCHEME_RE = /^(https?|wss?|ftp|file):/i;

function looksLikeUrl(value) {
  return typeof value === 'string'
    && (/^[a-z][a-z\d+.-]*:\/\//i.test(value) || SPECIAL_SCHEME_RE.test(value));
}

/** A string held under a URL-named key is a destination whatever its scheme. */
function looksLikeUrlValue(value) {
  return typeof value === 'string'
    && (looksLikeUrl(value) || SCHEME_RE.test(value) || value.startsWith('//'));
}

/**
 * Recursively scan nested JSON-ish values for URLs and validate each one.
 * Cycles are safely reported and do not hang the scanner.
 */
function scanToolArguments(value, options) {
  const opts = options && typeof options === 'object' ? options : {};
  const maxDepthOption = ownOption(opts, 'maxDepth');
  const maxNodesOption = ownOption(opts, 'maxNodes');
  const maxDepth = Number.isInteger(maxDepthOption) && maxDepthOption >= 0
    ? maxDepthOption : DEFAULT_MAX_DEPTH;
  const maxNodes = Number.isInteger(maxNodesOption) && maxNodesOption > 0
    ? maxNodesOption : DEFAULT_MAX_NODES;
  const validationOptions = ownOption(opts, 'options') || opts;
  const findings = [];
  const seen = new WeakSet();
  let nodes = 0;

  function visit(node, path, depth) {
    nodes += 1;
    if (nodes > maxNodes) return;
    if (depth > maxDepth) return;
    try {
      visitValue(node, path, depth);
    } catch {
      // Hostile getters, proxies and exotic objects must never abort the scan.
      findings.push({
        path,
        value: '<unreadable>',
        ok: false,
        code: 'INVALID_URL',
        detail: 'value could not be inspected',
      });
    }
  }

  function visitValue(node, path, depth) {
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
      if (typeof child === 'string' && URL_KEY_RE.test(key) && looksLikeUrlValue(child)) {
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
