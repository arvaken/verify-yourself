#!/usr/bin/env node
/**
 * Verify it yourself, on the command line (F3(b)): the same checks as the public page's button, with the same script,
 * run by Node.js (24 or later, for Ed25519 in its Web Cryptography).
 *
 *   node cli.mjs <attestation id> [--live] [--base https://verify.arvaken.com]
 *   node cli.mjs <report reference AR-...> [--file <your copy>] [--live] [--base https://verify.arvaken.com]
 *
 * For an attestation it asks the page for what the page states (the attestation's identifier, content hash and audience:
 * /status) and for the signatures and their receipts (/proof). For an assessment report (D514), which has no status, the
 * report's /proof carries what its page states (the SHA-256 of the report and of Exhibit A, the date it describes, and a
 * withdrawal) beside the signatures; with --file, your own copy is hashed here, and sent nowhere, and said to be the report,
 * its Exhibit A, or neither. It checks them here and prints each step. With --live it also asks Rekor.
 * Exit 0: verified (and, with --file, the copy is the report or its exhibit); 1: not verified; 2: not checked.
 */
import { plainLine, sha256, verifyAttestation, verifyReport } from './verify-attestation.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const REFERENCE = /^AR-[0-9A-HJKMNP-TV-Z]{10}$/;
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

/** Run the check; print each line with `print`; return the exit code. */
export async function main(argv, fetchFn = globalThis.fetch, print = (s) => console.log(s), { pinned } = {}) {
  const args = [...argv];
  const live = args.includes('--live');
  const at = args.indexOf('--base');
  const base = (at >= 0 ? args[at + 1] : 'https://verify.arvaken.com').replace(/\/+$/, '');
  const fileAt = args.indexOf('--file');
  const id = args.find((a, i) => !a.startsWith('--') && (at < 0 || i !== at + 1) && (fileAt < 0 || i !== fileAt + 1));
  const onStep = (s) => {
    // In plain words, as the page says it, with the technical account beneath (the founder's wording, 2026-10-07).
    const mark = s.ok === true ? 'passed' : s.ok === false ? 'FAILED' : 'not checked';
    print(`${plainLine(s)}${s.signature === null ? '' : ` (signature ${s.signature + 1})`}: ${mark}`);
    print(`    ${s.text}`);
  };
  if (id && REFERENCE.test(id)) return report(id, base, fileAt >= 0 ? args[fileAt + 1] : null, live, fetchFn, print, onStep, pinned);
  if (!id || !UUID.test(id)) {
    print('usage: node cli.mjs <attestation id> [--live] [--base https://verify.arvaken.com]');
    print('       node cli.mjs <report reference AR-...> [--file <your copy>] [--live] [--base https://verify.arvaken.com]');
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
    live, fetch: fetchFn, onStep,
  });
  print(result.verdict === 'verified'
    ? `verified: ${result.assessors.join(' and ')} signed it, ${result.assessors.length} of the ${result.needed} it needs. `
      + `This confirms who signed it, not whether it is still valid; the status shows that: it reads "${status.state}" `
      + `(${base}/attestations/${id}/status).`
    : result.verdict);
  return result.verdict === 'verified' ? 0 : result.verdict === 'could not check' ? 2 : 1;
}

/** An assessment report (D514): its signatures, and with --file the reader's copy, which never leaves this machine.
 *  PUBLIC TEXT: approved by the founder's click at 17:01:14 UTC on 22 October 2026 (D515), the words in full inside the question. */
async function report(reference, base, file, live, fetchFn, print, onStep, pinned) {
  let proof, copy = null;
  try {
    const r = await fetchFn(`${base}/reports/${reference}/proof`, { headers: { accept: 'application/json' } });
    if (r.status !== 200) throw new Error(`${base} answered ${r.status} for report ${reference}`);
    proof = await r.json();
    if (file) copy = hex(await sha256(new Uint8Array((await import('node:fs')).readFileSync(file))));
  } catch (e) {
    print(`not checked: ${e instanceof Error ? e.message : String(e)}`);
    return 2;
  }
  const page = proof && typeof proof.report === 'object' && proof.report !== null ? proof.report : {};
  print(`report ${reference}: the page states the report's SHA-256 ${page.document_sha256}, Exhibit A's `
        + `${page.exhibit_a_sha256}, and that it describes the setup as of ${page.describes_setup_as_of}`);
  const result = await verifyReport(proof, { reference, document_sha256: page.document_sha256,
                                             exhibit_a_sha256: page.exhibit_a_sha256,
                                             describes_setup_as_of: page.describes_setup_as_of },
                                   { live, fetch: fetchFn, onStep, ...(pinned ? { pinned } : {}) });
  print(result.verdict === 'verified'
    ? `verified: ${result.assessors.join(' and ')} signed it, ${result.assessors.length} of the ${result.needed} it needs. `
      + `It describes the setup as of ${page.describes_setup_as_of}, and says nothing of it after.`
    : result.verdict);
  if (page.withdrawn) print(`Withdrawn on ${page.withdrawn.on}: ${page.withdrawn.reason}`);
  let matches = true;
  if (copy !== null) {
    matches = copy === page.document_sha256 || copy === page.exhibit_a_sha256;
    print(copy === page.document_sha256 ? `your copy ${file} is the report signed here`
      : copy === page.exhibit_a_sha256 ? `your copy ${file} is Exhibit A of the report signed here`
      : `your copy ${file} is not the report signed here, nor its Exhibit A (its SHA-256 is ${copy})`);
  }
  if (result.verdict === 'could not check') return 2;
  return result.verdict === 'verified' && matches ? 0 : 1;
}

const invoked = typeof process !== 'undefined' && process.argv[1]
  && import.meta.url.replace(/^file:\/+/, '').replace(/\\/g, '/').toLowerCase()
     === process.argv[1].replace(/\\/g, '/').replace(/^\/+/, '').toLowerCase();
if (invoked) main(process.argv.slice(2)).then((code) => { process.exitCode = code; });
