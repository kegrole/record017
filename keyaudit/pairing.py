"""Pair private keys with certificates living in the same directory.

Matching is done on the fingerprint of the public key part (n, e), which
both sides expose: a private key carries n/e directly, a certificate
carries them inside subjectPublicKeyInfo.
"""

from collections import defaultdict


def apply_pairing(records):
    """Append UNMATCHED_KEY issues to private keys without a local cert.

    Records are report dicts carrying the internal keys '_dir' (absolute
    directory) and '_fingerprint' (public key fingerprint or None).
    Pairing only runs in directories that actually contain at least one
    certificate; directories without certificates are not audited for
    pairing.
    """
    certs_by_dir = defaultdict(set)
    for record in records:
        if record["kind"] == "certificate" and record["_fingerprint"]:
            certs_by_dir[record["_dir"]].add(record["_fingerprint"])
    for record in records:
        if record["kind"] != "private_key":
            continue
        fingerprints = certs_by_dir.get(record["_dir"])
        if not fingerprints:
            continue
        if record["_fingerprint"] is None:
            continue  # encrypted key: public part not observable
        if record["_fingerprint"] not in fingerprints:
            record["issues"].append({
                "code": "UNMATCHED_KEY",
                "detail": "no certificate in the same directory matches "
                          "this private key",
            })
    return records
