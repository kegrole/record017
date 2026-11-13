"""Regenerate the demo key material under demo/keys/ (standard library only).

Usage:  python demo/generate_keys.py

Layout produced:

    demo/keys/main/key.pem    2048-bit PKCS#1 private key, mode 0644
    demo/keys/legacy/key.pem  1024-bit PKCS#1 private key, mode 0600
    demo/keys/web/cert.pem    self-signed X.509 certificate (2048-bit key A)
    demo/keys/web/key.pem     2048-bit PKCS#1 private key B (B != A), 0600

Expected audit findings: PERMISSION_TOO_OPEN on main/key.pem, WEAK_KEY on
legacy/key.pem, UNMATCHED_KEY on web/key.pem.
"""

import base64
import hashlib
import math
import os
import secrets
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from keyaudit import der  # noqa: E402

OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_SHA256_WITH_RSA = "1.2.840.113549.1.1.11"

OID_COUNTRY = "2.5.4.6"
OID_ORGANIZATION = "2.5.4.10"
OID_COMMON_NAME = "2.5.4.3"


def _small_primorial(limit=2000):
    sieve = bytearray([1]) * (limit + 1)
    sieve[0:2] = b"\x00\x00"
    for p in range(2, int(limit ** 0.5) + 1):
        if sieve[p]:
            sieve[p * p::p] = b"\x00" * len(sieve[p * p::p])
    primorial = 1
    for p in range(2, limit + 1):
        if sieve[p]:
            primorial *= p
    return primorial


_PRIMORIAL = _small_primorial()


def is_probable_prime(n, rounds=16):
    if n < 2:
        return False
    if math.gcd(n, _PRIMORIAL) != 1:
        return n in (2, 3, 5, 7)
    d = n - 1
    shift = 0
    while d % 2 == 0:
        d //= 2
        shift += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(shift - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits, e):
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if math.gcd(candidate - 1, e) != 1:
            continue
        if is_probable_prime(candidate):
            return candidate


def generate_rsa_key(bits=2048, e=65537):
    """Pure-Python RSA keypair; returns a dict of PKCS#1 components."""
    half = bits // 2
    while True:
        p = generate_prime(half, e)
        q = generate_prime(bits - half, e)
        if p == q:
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        phi = (p - 1) * (q - 1)
        d = pow(e, -1, phi)
        if p < q:
            p, q = q, p
        return {
            "n": n, "e": e, "d": d, "p": p, "q": q,
            "dp": d % (p - 1), "dq": d % (q - 1),
            "qinv": pow(q, -1, p),
        }


def pkcs1_private_der(key):
    ints = [0, key["n"], key["e"], key["d"], key["p"], key["q"],
            key["dp"], key["dq"], key["qinv"]]
    return der.encode_sequence(*[der.encode_integer(i) for i in ints])


def pkcs1_public_der(key):
    return der.encode_sequence(
        der.encode_integer(key["n"]), der.encode_integer(key["e"]))


def spki_der(key):
    return der.encode_sequence(
        der.encode_sequence(der.encode_oid(OID_RSA_ENCRYPTION), der.encode_null()),
        der.encode_bit_string(pkcs1_public_der(key)),
    )


def name_der(rdns):
    """rdns: list of (oid, value); C is PrintableString, rest UTF8String."""
    avas = []
    for oid, value in rdns:
        if oid == OID_COUNTRY:
            encoded = der.encode_printable_string(value)
        else:
            encoded = der.encode_utf8_string(value)
        avas.append(der.encode_set(
            der.encode_sequence(der.encode_oid(oid), encoded)))
    return der.encode_sequence(*avas)


def _rsa_sign_sha256(key, data):
    digest_info = der.encode_sequence(
        der.encode_sequence(der.encode_oid(OID_SHA256), der.encode_null()),
        der.encode_octet_string(hashlib.sha256(data).digest()),
    )
    key_len = (key["n"].bit_length() + 7) // 8
    padding = b"\xff" * (key_len - len(digest_info) - 3)
    encoded = b"\x00\x01" + padding + b"\x00" + digest_info
    signature = pow(int.from_bytes(encoded, "big"), key["d"], key["n"])
    return signature.to_bytes(key_len, "big")


def build_certificate(key, subject_rdns, issuer_rdns, serial,
                      not_before, not_after):
    """Build a DER X.509 certificate signed with the given RSA key."""
    signature_algorithm = der.encode_sequence(
        der.encode_oid(OID_SHA256_WITH_RSA), der.encode_null())
    tbs = der.encode_sequence(
        der.encode_context(0, der.encode_integer(2)),  # version v3
        der.encode_integer(serial),
        signature_algorithm,
        name_der(issuer_rdns),
        der.encode_sequence(
            der.encode_utc_time(not_before),
            der.encode_utc_time(not_after),
        ),
        name_der(subject_rdns),
        spki_der(key),
    )
    return der.encode_sequence(
        tbs,
        signature_algorithm,
        der.encode_bit_string(_rsa_sign_sha256(key, tbs)),
    )


def to_pem(label, der_bytes):
    b64 = base64.encodebytes(der_bytes).decode("ascii")
    return "-----BEGIN %s-----\n%s-----END %s-----\n" % (label, b64, label)


def _write(path, text, mode):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="ascii") as handle:
        handle.write(text)
    os.chmod(path, mode)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    keys_dir = os.path.join(here, "keys")

    main_key = generate_rsa_key(2048)
    legacy_key = generate_rsa_key(1024)
    cert_key = generate_rsa_key(2048)
    web_key = generate_rsa_key(2048)
    while web_key["n"] == cert_key["n"]:
        web_key = generate_rsa_key(2048)

    _write(os.path.join(keys_dir, "main", "key.pem"),
           to_pem("RSA PRIVATE KEY", pkcs1_private_der(main_key)), 0o644)
    _write(os.path.join(keys_dir, "legacy", "key.pem"),
           to_pem("RSA PRIVATE KEY", pkcs1_private_der(legacy_key)), 0o600)

    now = datetime.now(timezone.utc).replace(microsecond=0)
    subject = [(OID_COUNTRY, "CN"),
               (OID_ORGANIZATION, "Keyaudit Demo"),
               (OID_COMMON_NAME, "demo.example.com")]
    cert_der = build_certificate(
        cert_key, subject, subject,
        serial=secrets.randbits(64) or 1,
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=825),
    )
    _write(os.path.join(keys_dir, "web", "cert.pem"),
           to_pem("CERTIFICATE", cert_der), 0o644)
    _write(os.path.join(keys_dir, "web", "key.pem"),
           to_pem("RSA PRIVATE KEY", pkcs1_private_der(web_key)), 0o600)

    print("demo keys written to %s" % keys_dir)


if __name__ == "__main__":
    main()
