# keyaudit

Audit RSA private keys, public keys and X.509 certificates scattered across
a directory tree. Pure Python standard library — no third-party
dependencies: PEM parsing, the ASN.1 DER decoder/encoder, RSA field
extraction and the demo key generator are all implemented from scratch.

## Usage

    python -m keyaudit.cli --dir <directory> --out <report.json>

`python -m keyaudit` works as an alias. The directory is scanned
recursively; every recognized PEM file produces one record in the JSON
report, and a one-line summary is printed to stdout:

    summary: files=4 private_keys=3 public_keys=0 certificates=1 issues=3

## Demo

    python demo/generate_keys.py          # (re)create demo/keys/
    python -m keyaudit.cli --dir demo/keys --out out/report.json

The demo material (regenerate any time with `demo/generate_keys.py`):

| File                     | Contents                                   | Mode |
|--------------------------|--------------------------------------------|------|
| `main/key.pem`           | 2048-bit PKCS#1 private key                | 0644 |
| `legacy/key.pem`         | 1024-bit PKCS#1 private key                | 0600 |
| `web/cert.pem`           | self-signed X.509 certificate (2048-bit)   | 0644 |
| `web/key.pem`            | 2048-bit PKCS#1 key, NOT matching the cert | 0600 |

Expected findings: `PERMISSION_TOO_OPEN` on `main/key.pem`, `WEAK_KEY` on
`legacy/key.pem`, `UNMATCHED_KEY` on `web/key.pem` — exactly 3 issues.

## Supported PEM types

| Armor label               | Kind          | Structure                                   |
|---------------------------|---------------|---------------------------------------------|
| `RSA PRIVATE KEY`         | `private_key` | PKCS#1 `RSAPrivateKey`                      |
| `PRIVATE KEY`             | `private_key` | PKCS#8 `PrivateKeyInfo` (rsaEncryption)     |
| `ENCRYPTED PRIVATE KEY`   | `private_key` | PKCS#8 `EncryptedPrivateKeyInfo`            |
| `RSA PUBLIC KEY`          | `public_key`  | PKCS#1 `RSAPublicKey`                       |
| `PUBLIC KEY`              | `public_key`  | X.509 `SubjectPublicKeyInfo`                |
| `CERTIFICATE`             | `certificate` | X.509 `Certificate`                         |

A PKCS#1 block carrying `Proc-Type: 4,ENCRYPTED` / `DEK-Info` headers is
also recognized as encrypted.

## How DER fields are extracted

`keyaudit/der.py` is a self-contained DER parser: every TLV becomes a
`Node` (tag class, tag number, constructed flag, raw content bytes,
parsed children). Typed accessors (`as_integer`, `as_oid`, `as_string`,
`as_bit_string`) read the universal types. On top of that:

- **PKCS#1 private key** — `SEQUENCE` of INTEGERs; the modulus `n` is the
  2nd INTEGER, public exponent `e` the 3rd. `bits = n.bit_length()`.
- **PKCS#8 private key** — `SEQUENCE { version, AlgorithmIdentifier,
  OCTET STRING }`; the algorithm OID must be `rsaEncryption`
  (1.2.840.113549.1.1.1) and the OCTET STRING payload is parsed again as
  a PKCS#1 `RSAPrivateKey`.
- **PKCS#1 public key / SPKI** — `SEQUENCE { n, e }`, either directly or
  inside the SPKI BIT STRING.
- **Certificate** — `Certificate.tbsCertificate`: optional `[0]` version,
  serial, signature, issuer, validity (`notBefore`/`notAfter` as UTCTime
  or GeneralizedTime), subject, SPKI. `subject` is rendered from the
  RDNSequence in DER order (`C=CN, O=..., CN=...`); `not_after` is
  normalized to `YYYY-MM-DDTHH:MM:SSZ`.
- **Encryption check** — `ENCRYPTED PRIVATE KEY` armor or a
  `Proc-Type: 4,ENCRYPTED` PEM header means encrypted; encrypted records
  report `encrypted: true` and `bits: null` (the public part is not
  observable). Plaintext keys report `encrypted: false`.
- **Pairing** — the fingerprint is SHA-256 over the canonical DER
  encoding of `RSAPublicKey` (`SEQUENCE { n, e }`). Private keys and
  certificates in the *same directory* are compared by fingerprint; a
  private key with no matching local certificate gets `UNMATCHED_KEY`.
  Directories without certificates are not pairing-audited.
- **Permissions** — the file mode is read with `os.stat`; a private key
  readable by group or other (any of the `044` bits, e.g. 0644, 0640) is
  flagged.

## Report format

JSON object with a `summary` block and one record per file:

    {
      "file": "web/key.pem",          // path relative to --dir
      "kind": "private_key",          // private_key | public_key | certificate
      "bits": 2048,                   // RSA modulus length, null if encrypted
      "encrypted": false,
      "permission": "0600",           // octal file mode
      "issues": [{"code": "...", "detail": "..."}],
      // certificates additionally carry: subject, issuer, not_before, not_after
    }

### Issue codes

| Code                  | Meaning                                              |
|-----------------------|------------------------------------------------------|
| `WEAK_KEY`            | RSA modulus below 2048 bits                          |
| `PERMISSION_TOO_OPEN` | private key readable by group/other (e.g. 0644)      |
| `UNMATCHED_KEY`       | no certificate in the same directory matches the key |
| `PARSE_ERROR`         | file could not be decoded as the claimed structure   |

## Tests

    python -m unittest test_keyaudit -v

The suite builds its own fixture (real 2048/1024-bit RSA keys and a
self-signed certificate generated in pure Python) and covers: the three
expected findings, modulus bit extraction, chmod 0600 clearing the
permission finding, certificate subject/not_after round-trip, the
mandatory record fields, encryption detection, PKCS#8/SPKI armors,
pairing in both directions, and the CLI summary line.
