# verify-yourself

Check an Arvaken attestation's signatures yourself, in a browser or with Node.js.

Each attestation's page on verify.arvaken.com has a "Check it yourself" section. Its button runs
`verify-attestation.mjs`, the script in this repository, in the reader's own browser. `cli.mjs` runs the same script on
the command line. Run this copy on your own machine, and the check no longer relies on Arvaken's server sending the
script unaltered.

## What it checks

For each signature on the attestation:

- The signature is genuine.
- The key was certified by Arvaken's root when it signed. "When it signed" is the earliest time the signature's own
  entry in Rekor proves. Without such an entry, the key is judged as it stands when the check runs.
- The key's certificate comes from Arvaken's root.
- Whose key it is: a certified assessor.
- This is the attestation named on the page: its identifier, content hash and audience.
- The signature is in Rekor's public log, which Sigstore runs. It checks the receipt Arvaken kept. With `--live`, or the
  page's "Also ask Rekor now", it also asks Rekor whether it still holds the entry.

Then it counts the certified assessors who signed, against the number the attestation needs.

## What it does not check

- Whether the attestation is valid, stale or revoked. That comes from Arvaken's record, as the attestation's page shows
  it.
- That the content hash is the hash of the attestation's document, which is not public. It checks that the named
  assessors signed this hash. On the page, a copy of the document you have can be compared with it.
- That each signing key was made on a YubiKey and cannot leave it. Arvaken's record checks that, from each key's
  attestation by its device. This script does not.
- Key revocations from a public log. It applies the list of revoked keys Arvaken serves, signed under its root and
  dated. That list comes from Arvaken, and a list Arvaken did not serve could not be noticed here. Arvaken has published
  no such list yet.

## Run it

With Node.js 24 or later:

```
node cli.mjs <attestation id>
node cli.mjs <attestation id> --live
```

It asks verify.arvaken.com for what the attestation's page states (`/attestations/<id>/status`) and for the signatures
and their log entries (`/attestations/<id>/proof`), checks them on your machine, and prints each step. With `--live` it
also asks Rekor.

Exit code 0 means verified, 1 not verified, 2 not checked (the steps say why).

"Verified" confirms who signed the attestation, not whether it is still valid. The status shows that, and the last line
names the state it reads.

## Check that the page runs this script

Each attestation's page links the script it serves and states its SHA-256. Compare it with this repository's copy:

```
sha256sum verify-attestation.mjs
```

On Windows PowerShell: `Get-FileHash verify-attestation.mjs`

## What it trusts

The script pins, in `PINNED` at its top:

- Arvaken's root public key, from the key ceremony of 24 September 2026;
- Rekor's public key.

It imports nothing and uses only the platform's own cryptography (Web Cryptography).

The scripts' comments name files and decisions in Arvaken's own repository, which is not public. The tests that hold
this script to the rules Arvaken's record applies are there too.

## Licence

Copyright 2026 Arvaken, Inc. Licensed under the Apache License, Version 2.0: see [LICENSE](LICENSE).
