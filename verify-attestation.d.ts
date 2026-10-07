/** Types for verify-attestation.mjs, for the TypeScript that imports it (the console). The script itself is plain. */

export interface RekorKey {
  origin: string;
  base_url: string;
  log_id: string;
  /** The key's DER SubjectPublicKeyInfo, base64. */
  spki: string;
  valid_from: string;
  valid_until: string | null;
}

export interface Root {
  public_key: string;
  ceremony: string;
  revocations?: unknown;
}

export const PINNED: { roots: Root[]; rekor: RekorKey[] };

/** A Rekor entry as `mark_ledger.anchor.post_entry` keeps it. */
export interface Receipt {
  uuid: string;
  body: string;
  integratedTime: number;
  logID: string;
  logIndex: number;
  verification: {
    signedEntryTimestamp?: string;
    inclusionProof?: { checkpoint: string; hashes: string[]; logIndex: number; rootHash: string; treeSize: number };
  };
  url?: string;
  pre_existing_entry?: boolean;
}

export interface Included { tree_size: number; root_hash: string; index_in_tree: number }

export class CheckFailed extends Error {}
export class Unavailable extends Error {}

export function canonicalJson(value: unknown): string;
export function keyId(publicKeyHex: string): Promise<string>;
export function sha256(bytes: Uint8Array): Promise<Uint8Array>;
export function ed25519Available(): Promise<boolean>;
export function ed25519Verify(signatureHex: string, message: string | Uint8Array, publicKeyHex: string): Promise<boolean>;
export function leafHash(bodyB64: string): Promise<Uint8Array>;
export function rootFromInclusion(index: number, size: number, leaf: Uint8Array, proof: Uint8Array[]): Promise<Uint8Array>;
export function checkSignedEntryTimestamp(entry: Receipt, key: RekorKey): Promise<void>;
export function checkCheckpoint(checkpoint: string, key: RekorKey): Promise<[number, Uint8Array]>;
export function checkInclusion(entry: Receipt, uuid: string, key: RekorKey): Promise<Included>;
export function rekordBinds(bodyB64: string, data: Uint8Array, publicKeyHex: string, signatureHex: string): Promise<void>;
export function checkReceipt(receipt: Receipt, keys?: RekorKey[]): Promise<{ uuid: string; log_index: number; integrated_time: number } & Included>;
export function checkLive(receipt: Receipt, fetchFn?: (url: string) => Promise<{ status: number; json(): Promise<unknown> }>,
                          keys?: RekorKey[]): Promise<{ uuid: string } & Included>;
export function requiredAssessors(audience: string): number;

/** D250 / D189, step 4: the revocation entry that refuses a key's signature, given the time an entry proves for it. */
export function refusingRevocation(entries: Array<Record<string, any>> | undefined, external: Date | null): Record<string, any> | null;
export function entryTime(so: unknown, receipts: unknown[], keys?: RekorKey[]): Promise<{ entry: ({ uuid: string; log_index: number; integrated_time: number } & Included) | null; refused: string[] }>;
export interface KeyJudgment {
  judged_at: string;
  external: boolean;
  /** 'ok', or the record's reason: schema, root, cert-not-yet-valid, cert-expired, revoked, key, signature */
  verdict: string;
  detail: string | null;
  refused: string[];
  entry: unknown;
}
export function keyJudgment(so: unknown, root: { public_key: string; revocations?: unknown; id?: string }, receipts: unknown[], now: Date,
                            options?: { keys?: RekorKey[]; served?: unknown[] }): Promise<KeyJudgment>;

export interface Step { step: number; signature: number | null; ok: boolean | null; text: string; facts: Record<string, unknown> }
/** A step in plain words, for the page and the command line; `text` is the technical account beneath it. */
export function plainLine(step: Step): string;
export interface Verdict {
  verdict: 'verified' | 'not verified' | 'could not check';
  needed: number;
  assessors: string[];
  signatures: Array<{ key_id: string | null; assessor: string | null; problems: string[]; log: unknown }>;
  steps: Step[];
}
export function verifyAttestation(proof: unknown, expected: { attestation_id: string; content_hash: string; audience: string },
                                  options?: { pinned?: { roots: Root[]; rekor: RekorKey[] }; at?: Date; live?: boolean;
                                              fetch?: (url: string) => Promise<{ status: number; json(): Promise<unknown> }>;
                                              requireLog?: boolean; onStep?: (s: Step) => void }): Promise<Verdict>;
