// Optional Node.js DNS adapter. Only loaded when explicitly imported.
import { lookup } from 'node:dns/promises';

/** Resolve A and AAAA records with node:dns. Returns a plain address array. */
export async function nodeResolve(hostname) {
  const answers = await lookup(hostname, { all: true, verbatim: true });
  return answers.map((entry) => entry.address);
}

export default nodeResolve;
