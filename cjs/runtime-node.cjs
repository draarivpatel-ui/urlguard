// Optional Node.js DNS adapter. Only loaded when explicitly imported.
const { lookup } = require('node:dns/promises');

/** Resolve A and AAAA records with node:dns. Returns a plain address array. */
async function nodeResolve(hostname) {
  const answers = await lookup(hostname, { all: true, verbatim: true });
  return answers.map((entry) => entry.address);
}



exports.nodeResolve = nodeResolve;
exports.default = nodeResolve;
