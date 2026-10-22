/**
 * Verify it yourself (F3(b), D245, D247): an attestation's signatures, checked by the reader's own browser or by Node,
 * with nothing but the platform's own cryptography (Web Cryptography). It imports nothing and asks no server, except
 * Rekor's public log, and only when the caller asks for that second check.
 *
 * It applies the record's own rules, and this package's tests hold it to them:
 * - a signed object and its key's certificate: `verifySignedObject` and `verifyKeyCert` in packages/core/src/bundle.ts;
 * - whose key it is: `assessorFor` in packages/verify-core/src/trust.ts;
 * - each signature's problems and the count: `signatureFindings` and `derive` in packages/verify-core/src/validity.ts;
 * - a Rekor entry: packages/ledger/mark_ledger/rekor.py, sentence for sentence.
 *
 * What it trusts is pinned below: Arvaken's root from the key ceremony of 24 September 2026 (the committed roots.json)
 * and Rekor's key (the ledger's rekor_keys.json). The tests hold both equal to those files.
 *
 * What it does not check, and the page says so: the attestation's state (valid, stale, revoked, superseded), which is
 * Arvaken's record's; that each assessor's key is on a hardware token (the record checks the device's attestation
 * chain); and that the content hash is the hash of a document, until the document is published (D247, 2).
 *
 * An assessment report (D514) is checked by the same seven steps (`verifyReport`): both founders' signatures, each key's
 * certificate a version-2 one that lists "assessment report" (D324, Q2, 1: "certificates list the types each key may
 * sign; both checkers refuse a type mismatch"), and a statement of the type "assessment report" naming the report's
 * reference by its SHA-256 and the report and its Exhibit A by theirs. Nothing of a report's content reaches the script.
 *
 * When a key is judged (D250, applying D189's rule): at the earliest time the signature's own Rekor entry proves, not
 * when the check runs; with no such entry, when it runs. A revoked key's signature counts only when that entry's time
 * precedes the revocation's "compromised from" date. `keyJudgment` is that rule, held to the record's Python
 * (`mark_product.signature_time`) by the shared vectors (`signature_time_vectors.json`).
 */

// ---- pinned: generated from the committed trust files; test/pins.test.mjs holds them equal --------------------------
export const PINNED = {
  roots: [
    {
      public_key: 'c464d3ba2e4733d25f71f3719a0dad9362906e8f33784fbf4d4b5c84b4656cd2',
      ceremony: 'key_ceremony f00ac164-3d42-4e2e-b9e5-f86e4669c98f (root-generation, 2026-09-24, KEY-CEREMONY.md sha256 3237da8d...)',
    },
  ],
  rekor: [
    {
      origin: 'rekor.sigstore.dev',
      base_url: 'https://rekor.sigstore.dev',
      log_id: 'c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d',
      spki: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==',
      valid_from: '2021-01-12T11:53:27Z',
      valid_until: null,
    },
  ],
};

const SIGNED_OBJECT = 'mark.signed-object/1';
// What an assessor signs: version 1 carries the attestation's identifier; version 2 (D256) its SHA-256 instead, so the
// statement Rekor's operator receives does not unlock the attestation's page.
const STATEMENT_V1 = 'mark.attestation-signature/1';
const STATEMENT_V2 = 'mark.attestation-signature/2';
const KEY_CERT = 'mark.signing-key/1';
// Version 2 lists the documents its key may sign, in place of a purpose (D324, Q2, 1; D514): mark_ledger.keys's rule.
const KEY_CERT_V2 = 'mark.signing-key/2';
const DOCUMENT_TYPES = ['attestation', 'assessment report'];
// What both assessors sign for an assessment report (D514): its type, its reference's SHA-256, the two files' SHA-256 and
// the date it describes, and nothing of its content.
const REPORT_STATEMENT = 'mark.report-signature/1';
const REPORT_TYPE = 'assessment report';
const REPORT_FIELDS = ['describes_setup_as_of', 'document_sha256', 'document_type', 'exhibit_a_sha256', 'issued_at',
  'reference_sha256', 'schema'];
const ASSESSOR_CERT = 'mark.assessor-cert/1';
const REVOCATIONS = 'mark.revocations/1';
const SKEW_MS = 5 * 60_000;
const ISSUED_AT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const ED25519_SPKI = '302a300506032b6570032100';

/** Rekor's entry did not check. The message says which part (the same sentences as rekor.py). */
export class CheckFailed extends Error {}
/** This browser cannot do a check (it has no Ed25519 in Web Cryptography): not a failure of what it was asked. */
export class Unavailable extends Error {}

// ---- bytes ---------------------------------------------------------------------------------------------------------
const utf8 = (s) => new TextEncoder().encode(s);
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

function fromHex(h) {
  if (typeof h !== 'string' || h.length % 2 || !/^[0-9a-fA-F]*$/.test(h)) throw new CheckFailed('not hex');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(2 * i, 2 * i + 2), 16);
  return out;
}

function fromB64(s) {
  let bin;
  try { bin = atob(s); } catch { bin = null; }
  if (typeof s !== 'string' || bin === null) throw new CheckFailed('not base64');
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
};

function subtle() {
  const s = globalThis.crypto && globalThis.crypto.subtle;
  if (!s) throw new Unavailable('this browser has no Web Cryptography');
  return s;
}

export async function sha256(bytes) {
  return new Uint8Array(await subtle().digest('SHA-256', bytes));
}

/** Whether a signed statement names the attestation this page states (the record's `names_attestation`): version 1 by
 *  its identifier; version 2 by its identifier's SHA-256, carrying no identifier. The page computes the hash from its
 *  own identifier; statement_vectors.json holds this to the record's answers (D256). */
export async function namesAttestation(obj, attestationId) {
  if (typeof obj !== 'object' || obj === null || Array.isArray(obj)) return false;
  if (obj.schema === STATEMENT_V1) return obj.attestation_id === attestationId;
  if (obj.schema !== STATEMENT_V2 || 'attestation_id' in obj) return false;
  return obj.attestation_id_sha256 === hex(await sha256(new TextEncoder().encode(attestationId)));
}

const HASH = /^[0-9a-f]{64}$/;
const DAY = /^\d{4}-\d{2}-\d{2}$/;

/** Whether a signed statement names this assessment report (D514; mark_product.report.names_report): exactly the
 *  report statement's fields, the type "assessment report", the SHA-256 of the reference the page states, and the two
 *  SHA-256 and the date the page states. report_statement_vectors.json holds this to the record's answers. */
export async function namesReport(obj, expected) {
  if (typeof obj !== 'object' || obj === null || Array.isArray(obj)) return false;
  if (Object.keys(obj).sort().join() !== REPORT_FIELDS.join()) return false;
  if (obj.schema !== REPORT_STATEMENT || obj.document_type !== REPORT_TYPE) return false;
  for (const k of ['reference_sha256', 'document_sha256', 'exhibit_a_sha256']) if (!HASH.test(String(obj[k]))) return false;
  if (!DAY.test(String(obj.describes_setup_as_of))) return false;
  return obj.reference_sha256 === hex(await sha256(new TextEncoder().encode(expected.reference)))
    && obj.document_sha256 === expected.document_sha256 && obj.exhibit_a_sha256 === expected.exhibit_a_sha256
    && obj.describes_setup_as_of === expected.describes_setup_as_of;
}

// ---- the record's encodings (packages/core/src/bundle.ts) -----------------------------------------------------------
export function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalJson).join(',') + ']';
  const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalJson(value[k])).join(',') + '}';
}

/** A key's identifier: the first 16 hex characters of the SHA-256 of its bytes. */
export async function keyId(publicKeyHex) {
  return hex(await sha256(fromHex(publicKeyHex))).slice(0, 16);
}

let ed25519Probe;
/** Whether this browser verifies Ed25519 at all, asked once with Arvaken's root key, which is a valid key. */
export function ed25519Available() {
  ed25519Probe ??= subtle().importKey('raw', fromHex(PINNED.roots[0].public_key), { name: 'Ed25519' }, false, ['verify'])
    .then(() => true, () => false);
  return ed25519Probe;
}

/** Ed25519 over `message` (text or bytes). False for anything malformed, as the record's own check. */
export async function ed25519Verify(signatureHex, message, publicKeyHex) {
  if (!(await ed25519Available())) throw new Unavailable('this browser cannot check Ed25519 signatures');
  let sig, pub;
  try { sig = fromHex(signatureHex); pub = fromHex(publicKeyHex); } catch { return false; }
  if (sig.length !== 64 || pub.length !== 32) return false;
  try {
    const key = await subtle().importKey('raw', pub, { name: 'Ed25519' }, false, ['verify']);
    return await subtle().verify({ name: 'Ed25519' }, key, sig, typeof message === 'string' ? utf8(message) : message);
  } catch {
    return false;
  }
}

const isObject = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);
const time = (iso) => new Date(iso).getTime();

/** [well formed, instant]: validity.ts's issuedAt. No issued_at is well formed and names no instant. */
function issuedAt(obj) {
  if (!('issued_at' in obj)) return [true, null];
  const v = obj.issued_at;
  if (typeof v !== 'string' || !ISSUED_AT.test(v)) return [false, null];
  const d = new Date(v);
  if (Number.isNaN(d.getTime()) || d.toISOString() !== v) return [false, null];
  return [true, d];
}

/** The revocations a root signed, by key: its pinned list and any list served beside the attestation. */
async function revocationsUnder(root, rootKeyId, served) {
  const byKey = new Map();
  for (const sr of [root.revocations, ...(Array.isArray(served) ? served : [])]) {
    if (!isObject(sr) || !isObject(sr.list) || sr.list.schema !== REVOCATIONS || sr.list.root_id !== rootKeyId) continue;
    if (!(await ed25519Verify(sr.root_signature, canonicalJson(sr.list), root.public_key))) continue;
    for (const r of Array.isArray(sr.list.revoked) ? sr.list.revoked : []) {
      if (isObject(r)) byKey.set(r.key_id, [...(byKey.get(r.key_id) ?? []), r]);
    }
  }
  return byKey;
}

/** A time as the record's Python reads one (mark_ledger.keys.parse_time): a date and time with no zone is UTC. */
function parseTime(v) {
  if (typeof v !== 'string') return NaN;
  return Date.parse(/T\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/.test(v) ? `${v}Z` : v);
}

/** D189, step 4 (mark_ledger.keys.compromised_from): from when a revoked key's signatures are refused, the earlier of
 *  its "compromised from" date and the revocation itself; null when the entry gives no date, or one that does not read. */
function compromisedFrom(r) {
  const since = parseTime(r.compromised_from), at = parseTime(r.at);
  return Number.isNaN(since) || Number.isNaN(at) ? null : Math.min(since, at);
}

/** The revocation that refuses this key's signature, or null: it counts only when an external time (its Rekor entry's)
 *  shows it was made before the compromise began (D189, step 4; D250). */
export function refusingRevocation(entries, external) {
  for (const r of entries ?? []) {
    const since = compromisedFrom(r);
    if (!(since !== null && external && external.getTime() < since)) return r;
  }
  return null;
}

/** mark_ledger.keys._refused_since, word for word. */
function refusedSince(since, external) {
  if (since === null) return "compromised from: unknown, so from the key's creation: every signature it made is refused";
  const from = new Date(since).toISOString();
  if (!external) return `compromised from ${from}, and no external timestamp shows this signature was made before then`;
  return `compromised from ${from}, and this signature's external timestamp ${external.toISOString()} is not before it`;
}

/** What is wrong with a version-2 certificate's list of document types, or null (mark_ledger.keys.document_types_problem). */
function documentTypesProblem(c) {
  if ('purpose' in c) return 'a version-2 key certificate lists document_types and names no purpose';
  const t = c.document_types;
  if (!Array.isArray(t) || t.length === 0) return 'a version-2 key certificate lists the document types its key may sign';
  if (t.some((x) => !DOCUMENT_TYPES.includes(x)) || new Set(t).size !== t.length) return 'document_types must be distinct types';
  return null;
}

const aPurpose = (p) => (p === REPORT_TYPE ? 'an assessment report' : p === 'attestation' ? 'an attestation' : `'${p}'`);

/** verify_signed_object's judgment at `at`, for `purpose` ('attestation' or 'assessment report'), in its order and with
 *  its reasons: [reason, detail], or null when it verifies. A revocation's "compromised from" is read against `external`. */
async function signedObjectVerdict(so, root, revocations, at, external, purpose = 'attestation') {
  const skc = so.key_cert;
  const c = isObject(skc) ? skc.cert : null;
  if (!isObject(c) || (c.schema !== KEY_CERT && c.schema !== KEY_CERT_V2)) return ['schema', 'key certificate missing or malformed'];
  if (c.schema === KEY_CERT_V2) {
    if (documentTypesProblem(c)) return ['schema', 'key certificate missing or malformed'];
    if (!c.document_types.includes(purpose)) return ['type', `the key's certificate does not let it sign ${aPurpose(purpose)}`];
  } else if (purpose === REPORT_TYPE) {
    // Only a version-2 certificate lists the assessment report (D514): a version-1 one never lets its key sign one.
    return ['type', `the key's certificate does not let it sign ${aPurpose(purpose)}`];
  } else if (c.purpose !== purpose) return ['schema', `certificate purpose ${c.purpose} is not ${purpose}`];
  if (c.root_id !== root.id) return ['root', 'certificate was issued under a different root'];
  if (typeof c.public_key !== 'string' || c.key_id !== (await keyId(c.public_key).catch(() => null))) {
    return ['schema', 'certificate key_id does not match its public key'];
  }
  if (!(await ed25519Verify(skc.root_signature, canonicalJson(c), root.public_key))) {
    return ['root', 'certificate signature does not verify under the trusted root'];
  }
  const t = at.getTime();
  if (t + SKEW_MS < time(c.not_before)) return ['cert-not-yet-valid', `key ${c.key_id} valid from ${c.not_before}`];
  if (t - SKEW_MS > time(c.not_after)) return ['cert-expired', `key ${c.key_id} expired ${c.not_after}`];
  const r = refusingRevocation(revocations.get(c.key_id), external);
  if (r) return ['revoked', `key ${c.key_id} revoked ${r.at}: ${r.reason}; ${refusedSince(compromisedFrom(r), external)}`];
  if (so.key_id !== c.key_id) return ['key', 'signed object key_id does not match its certificate'];
  if ('issued_at' in so.object) {
    const issued = parseTime(so.object.issued_at);
    if (Number.isNaN(issued) || issued < time(c.not_before) - SKEW_MS || issued > time(c.not_after) + SKEW_MS) {
      return ['key', `issued_at ${so.object.issued_at} lies outside the signing key's validity`];
    }
  }
  if (!(await ed25519Verify(so.signature, canonicalJson(so.object), c.public_key))) {
    return ['signature', 'the signature over the statement does not verify under the certified key'];
  }
  return null;
}

/** The earliest time any of these receipts proves for this signature, and why each that proves nothing does not:
 *  { entry: checkReceipt's answer or null, refused: [sentence] }. mark_product.signature_time.judged_at. */
export async function entryTime(so, receipts, keys = PINNED.rekor) {
  const cert = isObject(so.key_cert) && isObject(so.key_cert.cert) ? so.key_cert.cert : {};
  let entry = null;
  const refused = [];
  for (const receipt of Array.isArray(receipts) ? receipts : []) {
    try {
      await rekordBinds(receipt.body, utf8(canonicalJson(so.object)), cert.public_key, so.signature);
      const proven = await checkReceipt(receipt, keys);
      if (!entry || proven.integrated_time < entry.integrated_time) entry = proven;
    } catch (e) {
      refused.push(e instanceof CheckFailed ? e.message : `the log entry could not be read (${e && e.name})`);
    }
  }
  return { entry, refused };
}

/**
 * D250's rule, which the shared vectors hold: when this signature's key is judged, and what verifying it there says.
 * root: { public_key, revocations? }; receipts: the signature's Rekor receipts; now: when the check runs.
 * Returns { judged_at, external, verdict: 'ok' or the record's reason, detail, refused, entry }.
 */
export async function keyJudgment(so, root, receipts, now, { keys = PINNED.rekor, served = [], purpose = 'attestation' } = {}) {
  const r = { ...root, id: root.id ?? await keyId(root.public_key) };
  const { entry, refused } = await entryTime(so, receipts, keys);
  const external = entry ? new Date(entry.integrated_time * 1000) : null;
  const at = external ?? now;
  const v = await signedObjectVerdict(so, r, await revocationsUnder(r, r.id, served), at, external, purpose);
  return { judged_at: at.toISOString(), external: external !== null, verdict: v ? v[0] : 'ok', detail: v ? v[1] : null,
           refused, entry };
}

/** [assessor, null] when a certificate under this root names the key at `at`; else [null, why]. trust.ts's assessorFor,
 *  with a revocation read against the signature's external time (D250). */
async function assessorFor(certs, root, rootKeyId, signingKeyId, revocations, at, external) {
  for (const sc of Array.isArray(certs) ? certs : []) {
    const c = (isObject(sc) && isObject(sc.cert)) ? sc.cert : {};
    if (c.schema !== ASSESSOR_CERT || c.root_id !== rootKeyId || !Array.isArray(c.key_ids) || !c.key_ids.includes(signingKeyId)) continue;
    if (!(await ed25519Verify(sc.root_signature || '', canonicalJson(c), root.public_key))) continue;
    const t = at.getTime();
    if (t + SKEW_MS < time(c.not_before) || t - SKEW_MS > time(c.not_after)) continue;
    if (refusingRevocation(revocations.get(signingKeyId), external)) return [null, `key ${signingKeyId} is revoked under root ${rootKeyId}`];
    return [String(c.assessor_id), null];
  }
  return [null, `no valid assessor certificate names key ${signingKeyId}`];
}

// ---- Rekor (packages/ledger/mark_ledger/rekor.py) -------------------------------------------------------------------
/** RFC 6962: a leaf is hashed with a 0x00 prefix. */
export async function leafHash(bodyB64) {
  return sha256(concat(new Uint8Array([0]), fromB64(bodyB64)));
}

/** The root an inclusion proof recomputes to (RFC 9162, 2.1.3.2). Plain arithmetic: indices pass 2^31. */
export async function rootFromInclusion(index, size, leaf, proof) {
  if (!(Number.isSafeInteger(index) && Number.isSafeInteger(size) && index >= 0 && index < size)) {
    throw new CheckFailed(`inclusion proof index ${index} is outside a tree of ${size}`);
  }
  let fn = index, sn = size - 1, r = leaf;
  const one = new Uint8Array([1]);
  for (const p of proof) {
    if (sn === 0) throw new CheckFailed('inclusion proof is longer than the tree allows');
    if (fn % 2 === 1 || fn === sn) {
      r = await sha256(concat(one, p, r));
      if (fn % 2 === 0) {
        while (fn % 2 === 0 && fn !== 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
      }
    } else {
      r = await sha256(concat(one, r, p));
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  if (sn !== 0) throw new CheckFailed('inclusion proof is shorter than the tree needs');
  return r;
}

/** An ECDSA signature as DER (SEQUENCE of two INTEGERs), as Web Cryptography wants it: r and s, 32 bytes each. */
function derToRaw(der) {
  let i = 0;
  if (der[i++] !== 0x30) return null;
  const len = der[i++];
  if (len !== der.length - i) return null;
  const out = new Uint8Array(64);
  for (const at of [0, 32]) {
    if (der[i++] !== 0x02) return null;
    const n = der[i++];
    if (!(n >= 1 && n <= 33) || i + n > der.length) return null;
    let v = der.subarray(i, i + n);
    i += n;
    if (v[0] & 0x80) return null;                          // negative
    if (n > 1 && v[0] === 0 && !(v[1] & 0x80)) return null;  // not minimal
    if (v[0] === 0) v = v.subarray(1);
    if (v.length > 32) return null;
    out.set(v, at + 32 - v.length);
  }
  return i === der.length ? out : null;
}

async function verifyEcdsa(key, derSignature, message, what) {
  const raw = derToRaw(derSignature);
  const pub = await subtle().importKey('spki', fromB64(key.spki), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  if (!raw || !(await subtle().verify({ name: 'ECDSA', hash: 'SHA-256' }, pub, raw, message))) {
    throw new CheckFailed(`${what} does not verify under Rekor's key`);
  }
}

/** Rekor's promise that it logged the entry: its signature over the canonical entry. */
export async function checkSignedEntryTimestamp(entry, key) {
  const payload = canonicalJson({ body: entry.body, integratedTime: entry.integratedTime, logID: entry.logID,
                                  logIndex: entry.logIndex });
  const set = ((entry.verification || {}).signedEntryTimestamp) || '';
  await verifyEcdsa(key, fromB64(set), utf8(payload), 'the signed entry timestamp');
}

/** A signed note: origin, tree size and root hash, signed by the log. Returns [size, root]. */
export async function checkCheckpoint(checkpoint, key) {
  if (typeof checkpoint !== 'string') throw new CheckFailed('the checkpoint is not origin, size and root');
  const cut = checkpoint.indexOf('\n\n');
  const text = cut < 0 ? checkpoint : checkpoint.slice(0, cut);
  const signatures = cut < 0 ? '' : checkpoint.slice(cut + 2);
  const lines = text.split('\n');
  if (lines.length < 3 || !/^\d+$/.test(lines[1])) throw new CheckFailed('the checkpoint is not origin, size and root');
  const [origin, size, root] = [lines[0], Number(lines[1]), fromB64(lines[2])];
  if (!origin.startsWith(key.origin)) throw new CheckFailed(`the checkpoint is from '${origin}', not ${key.origin}`);
  const hint = (await sha256(fromB64(key.spki))).subarray(0, 4);
  for (const line of signatures.trim().split('\n')) {
    const parts = line.split(' ');
    if (parts.length >= 3 && parts[1] === key.origin) {
      const raw = fromB64(parts[2]);
      if (hex(raw.subarray(0, 4)) === hex(hint)) {
        await verifyEcdsa(key, raw.subarray(4), utf8(text + '\n'), "the checkpoint's signature");
        return [size, root];
      }
    }
  }
  throw new CheckFailed("the checkpoint carries no signature by Rekor's key");
}

/** The entry is in the log: its leaf is the uuid's, and its proof recomputes to a checkpoint Rekor signed. */
export async function checkInclusion(entry, uuid, key) {
  const leaf = await leafHash(entry.body);
  if (!uuid.endsWith(hex(leaf))) throw new CheckFailed("the entry's leaf hash is not the one its uuid names");
  const proof = (entry.verification || {}).inclusionProof;
  if (!isObject(proof) || !Array.isArray(proof.hashes)) throw new CheckFailed('Rekor served no inclusion proof');
  const [size, signedRoot] = await checkCheckpoint(proof.checkpoint, key);
  if (size !== proof.treeSize || hex(signedRoot) !== proof.rootHash) {
    throw new CheckFailed("the inclusion proof's tree is not the one the checkpoint signs");
  }
  const got = await rootFromInclusion(proof.logIndex, proof.treeSize, leaf, proof.hashes.map(fromHex));
  if (hex(got) !== proof.rootHash) throw new CheckFailed('the inclusion proof does not recompute to the signed root');
  return { tree_size: size, root_hash: proof.rootHash, index_in_tree: proof.logIndex };
}

function pinnedKeyFor(entry, keys) {
  const key = keys.find((k) => k.log_id === entry.logID);
  if (!key) {
    throw new CheckFailed(`the entry is in a log whose key is not pinned (log id ${String(entry.logID).slice(0, 16)}…)`);
  }
  const t = entry.integratedTime;
  if (t < time(key.valid_from) / 1000 || (key.valid_until && t >= time(key.valid_until) / 1000)) {
    throw new CheckFailed(`the entry was integrated at ${new Date(t * 1000).toISOString()}, outside the dates its key is pinned for`);
  }
  return key;
}

/**
 * The entry is a `rekord` over `data`, carrying this Ed25519 signature and key, and the signature verifies: what the
 * ledger's anchors carry (anchor.py, `RekorAnchor.submit`) and what an attestation's entry will (D247, 3). Rekor keeps
 * the content's SHA-256, not the content.
 */
export async function rekordBinds(bodyB64, data, publicKeyHex, signatureHex) {
  let body;
  try { body = JSON.parse(new TextDecoder().decode(fromB64(bodyB64))); } catch { throw new CheckFailed('the log entry is not a rekord'); }
  const spec = (isObject(body) && body.apiVersion === '0.0.1' && body.kind === 'rekord' && body.spec) || null;
  if (!isObject(spec)) throw new CheckFailed('the log entry is not a rekord');
  const h = (spec.data || {}).hash || {};
  if (h.algorithm !== 'sha256' || h.value !== hex(await sha256(data))) {
    throw new CheckFailed('the log entry is over other content than this statement');
  }
  const sig = spec.signature || {};
  const pem = new TextDecoder().decode(fromB64((sig.publicKey || {}).content || ''));
  const der = hex(fromB64(pem.split(/\r?\n/).filter((l) => l && !l.startsWith('-----')).join('')));
  if (sig.format !== 'x509' || der !== ED25519_SPKI + String(publicKeyHex).toLowerCase()) {
    throw new CheckFailed('the log entry names another key than this signature');
  }
  if (hex(fromB64(sig.content || '')) !== String(signatureHex).toLowerCase()) {
    throw new CheckFailed('the log entry carries another signature than this one');
  }
  if (!(await ed25519Verify(signatureHex, data, publicKeyHex))) {
    throw new CheckFailed("the log entry's signature does not verify over this statement");
  }
}

/** A receipt kept in the record, checked offline: Rekor's key, its signed timestamp and the entry's inclusion. */
export async function checkReceipt(receipt, keys = PINNED.rekor) {
  if (!isObject(receipt) || typeof receipt.uuid !== 'string' || typeof receipt.body !== 'string') {
    throw new CheckFailed('the receipt is not a Rekor entry');
  }
  const key = pinnedKeyFor(receipt, keys);
  await checkSignedEntryTimestamp(receipt, key);
  return { uuid: receipt.uuid, log_index: receipt.logIndex, integrated_time: receipt.integratedTime,
           ...(await checkInclusion(receipt, receipt.uuid, key)) };
}

/** The second check: Rekor, asked now, still serves the entry as the receipt recorded it, in a tree it signed. */
export async function checkLive(receipt, fetchFn = globalThis.fetch, keys = PINNED.rekor) {
  const uuid = receipt.uuid;
  const key = pinnedKeyFor(receipt, keys);
  let answer;
  try {
    answer = await fetchFn(`${key.base_url}/api/v1/log/entries/${uuid}`);
  } catch (e) {
    throw new Unavailable(`Rekor could not be asked for entry ${uuid.slice(0, 16)}…: ${e && e.name}: ${e && e.message}`);
  }
  // A log that is down or busy has said nothing about the entry; one that answers otherwise has.
  if (answer.status >= 500 || answer.status === 429) {
    throw new Unavailable(`Rekor answered ${answer.status} for entry ${uuid.slice(0, 16)}…, so it could not be asked now`);
  }
  if (answer.status !== 200) throw new CheckFailed(`Rekor answered ${answer.status} for entry ${uuid.slice(0, 16)}…`);
  const served = await answer.json().catch(() => null);
  if (!isObject(served) || Object.keys(served).length !== 1 || Object.keys(served)[0] !== uuid) {
    throw new CheckFailed('Rekor served another entry than the one asked for');
  }
  const entry = served[uuid];
  for (const name of ['body', 'logID', 'logIndex', 'integratedTime']) {
    if (entry[name] !== receipt[name]) throw new CheckFailed(`the entry's ${name} as Rekor serves it is not the one recorded`);
  }
  await checkSignedEntryTimestamp(entry, key);
  return { uuid, ...(await checkInclusion(entry, uuid, key)) };
}

// ---- the attestation ------------------------------------------------------------------------------------------------
/** Anything not explicitly internal is held to the third-party rule, the stricter one (validity.ts). */
export const requiredAssessors = (audience) => (audience === 'internal' ? 1 : 2);

/**
 * Check what the public page serves for one attestation against what the page itself states.
 *
 * proof:    { signatures: [{ signed_object, log_entries?: [receipt] }], assessor_certificates: [...], revocations?: [...] }
 *           (the public page's /attestations/<id>/proof; a single `log_entry` is read as a list of one)
 * expected: { attestation_id, content_hash, audience }, read from the page, not from the proof.
 * options:  at (default now), live (ask Rekor too), fetch, requireLog (a signature without an entry fails), onStep.
 *
 * Returns { verdict: 'verified' | 'not verified' | 'could not check', needed, assessors, signatures, steps }. Each step
 * is { step, signature, ok, text }: ok is true, false, or null for a check that could not be made (not a failure).
 * The steps are numbered as the plan's list (CONSOLE-PLAN.md part 12, F3(b)).
 */
export async function verifyAttestation(proof, expected, options = {}) {
  return verifyDocument(proof, {
    needed: requiredAssessors(expected.audience), purpose: 'attestation', kind: 'attestation',
    async names(obj) {
      if (!(await namesAttestation(obj, expected.attestation_id))) return [false, 'the signed object is not a signature over this attestation'];
      if (obj.content_hash !== expected.content_hash) {
        return [false, `signed content ${obj.content_hash ?? 'None'} is not the attestation's content ${expected.content_hash}`];
      }
      const how = obj.schema === STATEMENT_V2 ? `by its identifier's SHA-256, ${obj.attestation_id_sha256}` : `(${obj.attestation_id})`;
      return [true, `the statement names this attestation ${how}, and the content hash this page states`];
    },
  }, options);
}

/**
 * Check what an assessment report's public page serves (D514): the same seven steps, for the document type "assessment
 * report". Both founders sign a report, so two certified assessors are needed; each key's certificate must list the type.
 *
 * proof:    as an attestation's: /reports/<reference>/proof.
 * expected: { reference, document_sha256, exhibit_a_sha256, describes_setup_as_of }, read from the page.
 */
export async function verifyReport(proof, expected, options = {}) {
  // PUBLIC TEXT: approved by the founder's click at 17:01:14 UTC on 22 October 2026 (D515), the words in full inside the question.
  return verifyDocument(proof, {
    needed: 2, purpose: REPORT_TYPE, kind: 'report',
    async names(obj) {
      if (!(await namesReport(obj, expected))) return [false, 'the signed statement is not this assessment report'];
      return [true, `the statement is of an assessment report and names this one by its reference's SHA-256, `
        + `${obj.reference_sha256}, with the SHA-256 of the report and of its Exhibit A this page states`];
    },
  }, options);
}

async function verifyDocument(proof, { needed, purpose, kind, names }, options) {
  const { pinned = PINNED, at = new Date(), live = false, fetch: fetchFn = globalThis.fetch, requireLog = false,
          onStep = () => {} } = options;
  const steps = [];
  const record = (step, signature, ok, text, facts = {}) => {
    // An attestation's steps are as they were before reports; a report's say which kind they are, for plainLine.
    const s = { step, signature, ok, text, facts: kind === 'report' ? { kind, ...facts } : facts };
    steps.push(s);
    onStep(s);
    return ok;
  };
  const result = (verdict, signatures, assessors) => ({ verdict, needed, assessors, signatures, steps });
  const what = purpose === REPORT_TYPE ? 'assessment reports' : 'attestations';

  if (!(await ed25519Available())) {
    record(1, null, null, 'This browser cannot check Ed25519 signatures, so nothing was checked. A current browser can.');
    return result('could not check', [], []);
  }
  const roots = [];
  for (const r of pinned.roots) roots.push({ ...r, id: await keyId(r.public_key) });
  const entries = isObject(proof) && Array.isArray(proof.signatures) ? proof.signatures : [];
  const signatures = [];
  for (const [n, entry] of entries.entries()) signatures.push(await checkOne(n, entry));

  const counted = [...new Set(signatures.filter((s) => s.problems.length === 0 && s.assessor).map((s) => s.assessor))].sort();
  const countOk = counted.length >= needed;
  record(5, null, countOk, `${counted.length} of ${needed} required certified assessor signatures` +
         (counted.length ? `: ${counted.join(', ')}` : ''), { counted: counted.length, needed });
  const failed = !countOk || steps.some((s) => s.ok === false);
  return result(failed ? 'not verified' : 'verified', signatures, counted);

  function receiptsOf(entry) {
    if (Array.isArray(entry.log_entries)) return entry.log_entries;
    return entry.log_entry === undefined || entry.log_entry === null ? [] : [entry.log_entry];
  }

  async function checkOne(n, entry) {
    const so = isObject(entry) ? entry.signed_object : null;
    const out = { key_id: null, assessor: null, problems: [], log: null };
    const fail = (step, text, facts = {}) => { out.problems.push(text); record(step, n, false, text, facts); };
    if (!isObject(so) || so.schema !== SIGNED_OBJECT || !isObject(so.object) || typeof so.signature !== 'string'
        || typeof so.key_id !== 'string' || !('key_cert' in so)) {
      fail(1, 'malformed signed object: not a mark.signed-object/1 with an object, a signature, a key_id and a key_cert');
      return out;
    }
    out.key_id = so.key_id;
    const obj = so.object;
    const cert = isObject(so.key_cert) && isObject(so.key_cert.cert) ? so.key_cert.cert : {};
    const root = roots.find((r) => r.id === cert.root_id);
    if (!root) {
      fail(3, `root ${cert.root_id} is not a trusted root`);
    } else {
      record(3, n, true, `the key's certificate names Arvaken's root ${root.id}, the one this script pins`);
      const revocations = await revocationsUnder(root, root.id, proof.revocations);
      const j = await keyJudgment(so, root, receiptsOf(entry), at, { keys: pinned.rekor, served: proof.revocations, purpose });
      const external = j.external ? new Date(j.judged_at) : null;
      const when = external ? `at ${j.judged_at}, the time its Rekor entry proves` : 'now, as no Rekor entry proves an earlier time';
      const [wellFormed, instant] = issuedAt(obj);
      if (!wellFormed) {
        fail(2, 'does not verify (schema): issued_at must be YYYY-MM-DDTHH:MM:SS.mmmZ');
      } else if (j.verdict !== 'ok' && j.verdict !== 'signature') {
        // For a report, the type's refusal: PUBLIC TEXT: approved by the founder's click at 17:01:14 UTC on 22 October 2026 (D515), the words in full inside the question.
        fail(2, `does not verify (${j.verdict}): ${j.detail}`, { reason: j.verdict });
      } else {
        record(2, n, true, `key ${cert.key_id} is certified by the root for ${what}, from ${cert.not_before} to ${cert.not_after}, judged ${when}`,
               { judged: external ? 'entry' : 'now' });
        if (j.verdict === 'signature') fail(1, `does not verify (signature): ${j.detail}`);
        else record(1, n, true, `the Ed25519 signature over the statement verifies under key ${cert.key_id}`);
      }
      const [who, why] = await assessorFor(proof.assessor_certificates, root, root.id, so.key_id, revocations, instant ?? at, external);
      out.assessor = who;
      if (why) fail(4, why);
      else record(4, n, true, `key ${so.key_id} is ${who}'s, by an assessor certificate the root signed`, { who });
    }
    const [named, text] = await names(obj);
    if (named) record(6, n, true, text);
    else fail(6, text);
    await checkLog(n, receiptsOf(entry), await entryTime(so, receiptsOf(entry), pinned.rekor), out);
    return out;
  }

  // A receipt the record holds that proves nothing is a failure, not an absence: the record checked it before keeping it.
  async function checkLog(n, receipts, proven, out) {
    if (!receipts.length) {
      record(7, n, requireLog ? false : null, 'no public log entry recorded for this signature yet', { log: 'none' });
      return;
    }
    for (const text of proven.refused) { out.problems.push(text); record(7, n, false, text, { log: 'refused' }); }
    if (!proven.entry) return;
    out.log = proven.entry;
    const receipt = receipts.find((r) => isObject(r) && r.uuid === proven.entry.uuid);
    record(7, n, true, `in Rekor's public log at index ${out.log.log_index}, proved by a tree of ${out.log.tree_size} entries Rekor signed`,
           { log: 'logged' });
    if (!live) return;
    try {
      const now = await checkLive(receipt, fetchFn, pinned.rekor);
      record(7, n, true, `Rekor, asked just now, serves the same entry, in a tree of ${now.tree_size} entries it signed`,
             { log: 'live' });
    } catch (e) {
      if (e instanceof Unavailable) { record(7, n, null, e.message, { log: 'unreachable' }); return; }
      const text = e instanceof CheckFailed ? e.message : `Rekor's answer could not be read (${e && e.name})`;
      out.problems.push(text);
      record(7, n, false, text, { log: 'refused' });
    }
  }
}

/**
 * A step in plain words, for the page and the command line alike; the step's `text` is the technical account, with the
 * record's reason in parentheses, shown beneath it (the founder's wording, 2026-10-07).
 */
export function plainLine(step) {
  const f = step.facts ?? {};
  const ok = step.ok;
  switch (step.step) {
    case 1:
      return ok === true ? 'The signature is genuine'
        : ok === null ? 'The signature could not be checked in this browser' : 'The signature is not genuine';
    case 2:
      // A report's lines here and at step 6: PUBLIC TEXT: approved by the founder's click at 17:01:14 UTC on 22 October 2026 (D515), the words in full inside the question.
      if (ok !== true && f.reason === 'type') {
        return `The key's certificate does not let it sign ${f.kind === 'report' ? 'an assessment report' : 'an attestation'}`;
      }
      if (ok !== true) return "The key was not certified by Arvaken's root when it signed";
      return f.judged === 'entry' ? "The key was certified by Arvaken's root when it signed"
        : "The key is certified by Arvaken's root now; no public log entry shows when it signed";
    case 3:
      return ok === true ? "The key's certificate comes from Arvaken's root" : "The key's certificate does not come from Arvaken's root";
    case 4:
      return ok === true ? `The key is ${f.who}'s, a certified assessor` : "The key is not a certified assessor's";
    case 5:
      return `${f.counted} of the ${f.needed} certified assessors it needs signed it`;
    case 6:
      if (f.kind === 'report') return ok === true ? 'This is the report named on this page' : 'What was signed is not the report named on this page';
      return ok === true ? 'This is the attestation named on this page' : 'What was signed is not the attestation named on this page';
    case 7:
      return f.log === 'logged' ? "The signature is in Rekor's public log"
        : f.log === 'live' ? 'Rekor, asked just now, still holds the entry'
        : f.log === 'none' ? 'No public log entry recorded yet'
        : f.log === 'unreachable' ? 'Rekor could not be asked just now'
        : "The log entry does not prove this signature";
    default:
      return `Step ${step.step}`;
  }
}
