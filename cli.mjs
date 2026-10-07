#!/usr/bin/env node
/**
 * Verify it yourself, on the command line (F3(b)): the same checks as the public page's button, with the same script,
 * run by Node.js (24 or later, for Ed25519 in its Web Cryptography).
 *
 *   node cli.mjs <attestation id> [--live] [--base https://verify.arvaken.com]
 *
 * It asks the page for what the page states (the attestation's identifier, content hash and audience: /status) and for
 * the signatures and their receipts (/proof), checks them here, and prints each step. With --live it also asks Rekor.
 * Exit 0: verified; 1: not verified; 2: not checked (the steps say why).
 */
import { plainLine, verifyAttestation } from './verify-attestation.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** Run the check; print each line with `print`; return the exit code. */
export async function main(argv, fetchFn = globalThis.fetch, print = (s) => console.log(s)) {
  const args = [...argv];
  const live = args.includes('--live');
  const at = args.indexOf('--base');
  const base = (at >= 0 ? args[at + 1] : 'https://verify.arvaken.com').replace(/\/+$/, '');
  const id = args.find((a, i) => !a.startsWith('--') && (at < 0 || i !== at + 1));
  if (!id || !UUID.test(id)) {
    print('usage: node cli.mjs <attestation id> [--live] [--base https://verify.arvaken.com]');
    return 2;
  }
  const get = async (path) => {
    const r = await fetchFn(`${base}/attestations/${id}/${path}`, { headers: { accept: 'application/json' } });
    if (r.status !== 200) throw new Error(`${base} answered ${r.status} for ${path}`);
    return r.json();
  };
  let status, proof;
  try {
    [status, proof] = [await get('status'), await get('proof')];
  } catch (e) {
    print(`not checked: ${e instanceof Error ? e.message : String(e)}`);
    return 2;
  }
  print(`attestation ${id}: the page states content hash ${status.content_hash} and audience ${status.audience}`);
  const result = await verifyAttestation(proof, { attestation_id: id, content_hash: status.content_hash, audience: status.audience }, {
    live, fetch: fetchFn,
    onStep: (s) => {
      // In plain words, as the page says it, with the technical account beneath (the founder's wording, 2026-10-07).
      const mark = s.ok === true ? 'passed' : s.ok === false ? 'FAILED' : 'not checked';
      print(`${plainLine(s)}${s.signature === null ? '' : ` (signature ${s.signature + 1})`}: ${mark}`);
      print(`    ${s.text}`);
    },
  });
  print(result.verdict === 'verified'
    ? `verified: ${result.assessors.join(' and ')} signed it, ${result.assessors.length} of the ${result.needed} it needs. `
      + `This confirms who signed it, not whether it is still valid; the status shows that: it reads "${status.state}" `
      + `(${base}/attestations/${id}/status).`
    : result.verdict);
  return result.verdict === 'verified' ? 0 : result.verdict === 'could not check' ? 2 : 1;
}

const invoked = typeof process !== 'undefined' && process.argv[1]
  && import.meta.url.replace(/^file:\/+/, '').replace(/\\/g, '/').toLowerCase()
     === process.argv[1].replace(/\\/g, '/').replace(/^\/+/, '').toLowerCase();
if (invoked) main(process.argv.slice(2)).then((code) => { process.exitCode = code; });
