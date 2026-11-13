"""RSA key material extraction from DER structures (PKCS#1, PKCS#8, X.509)."""

import hashlib

from . import asn1, der


OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"


class RsaError(ValueError):
    """Raised when a structure is not the expected RSA object."""


def _expect_rsa_algorithm(algorithm_node, where):
    der.expect(algorithm_node, der.TAG_SEQUENCE)
    if not algorithm_node.children:
        raise RsaError("empty AlgorithmIdentifier in " + where)
    oid = der.as_oid(algorithm_node.children[0])
    if oid != OID_RSA_ENCRYPTION:
        raise RsaError(
            "unsupported algorithm %s (%s) in %s"
            % (oid, asn1.algorithm_name(oid), where)
        )
    return oid


def parse_pkcs1_private(der_bytes):
    """RSAPrivateKey ::= SEQUENCE { version, n, e, d, p, q, dp, dq, qinv }."""
    seq = der.parse_one(der_bytes)
    der.expect(seq, der.TAG_SEQUENCE)
    if not seq.children or len(seq.children) < 9:
        raise RsaError("RSAPrivateKey needs at least 9 INTEGERs")
    ints = [der.as_integer(child) for child in seq.children]
    return {
        "version": ints[0],
        "modulus": ints[1],
        "public_exponent": ints[2],
        "private_exponent": ints[3],
        "prime1": ints[4],
        "prime2": ints[5],
        "exponent1": ints[6],
        "exponent2": ints[7],
        "coefficient": ints[8],
    }


def parse_pkcs1_public(der_bytes):
    """RSAPublicKey ::= SEQUENCE { modulus, publicExponent }."""
    seq = der.parse_one(der_bytes)
    der.expect(seq, der.TAG_SEQUENCE)
    if not seq.children or len(seq.children) != 2:
        raise RsaError("RSAPublicKey needs exactly 2 INTEGERs")
    return {
        "modulus": der.as_integer(seq.children[0]),
        "public_exponent": der.as_integer(seq.children[1]),
    }


def parse_pkcs8_private(der_bytes):
    """PrivateKeyInfo ::= SEQUENCE { version, algorithm, privateKey }.

    Returns the DER bytes of the inner PKCS#1 RSAPrivateKey carried in the
    privateKey OCTET STRING.
    """
    seq = der.parse_one(der_bytes)
    der.expect(seq, der.TAG_SEQUENCE)
    if not seq.children or len(seq.children) < 3:
        raise RsaError("PrivateKeyInfo needs at least 3 fields")
    _expect_rsa_algorithm(seq.children[1], "PrivateKeyInfo")
    private_key = seq.children[2]
    der.expect(private_key, der.TAG_OCTET_STRING)
    return private_key.value


def parse_spki(der_bytes):
    """SubjectPublicKeyInfo -> DER bytes of the inner RSAPublicKey."""
    seq = der.parse_one(der_bytes)
    der.expect(seq, der.TAG_SEQUENCE)
    return _spki_node_to_pkcs1(seq)


def _spki_node_to_pkcs1(spki_node):
    der.expect(spki_node, der.TAG_SEQUENCE)
    if not spki_node.children or len(spki_node.children) < 2:
        raise RsaError("SubjectPublicKeyInfo needs 2 fields")
    _expect_rsa_algorithm(spki_node.children[0], "SubjectPublicKeyInfo")
    return der.as_bit_string(spki_node.children[1])


def parse_certificate(der_bytes):
    """X.509 Certificate -> dict with subject, not_after and SPKI bits.

    Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm,
                               signatureValue }
    TBSCertificate ::= SEQUENCE { [0] version?, serialNumber, signature,
                                  issuer, validity, subject,
                                  subjectPublicKeyInfo, ... }
    """
    cert = der.parse_one(der_bytes)
    der.expect(cert, der.TAG_SEQUENCE)
    if not cert.children:
        raise RsaError("empty Certificate")
    tbs = cert.children[0]
    der.expect(tbs, der.TAG_SEQUENCE)
    fields = tbs.children
    index = 0
    if fields and fields[0].tag_class == der.CONTEXT and fields[0].tag == 0:
        index = 1  # skip explicit version
    if len(fields) < index + 6:
        raise RsaError("TBSCertificate has too few fields")
    validity = fields[index + 3]
    der.expect(validity, der.TAG_SEQUENCE)
    if len(validity.children) != 2:
        raise RsaError("validity needs notBefore and notAfter")
    pkcs1_der = _spki_node_to_pkcs1(fields[index + 5])
    public = parse_pkcs1_public(pkcs1_der)
    return {
        "issuer": asn1.name_to_string(fields[index + 2]),
        "subject": asn1.name_to_string(fields[index + 4]),
        "not_before": asn1.parse_time(validity.children[0]),
        "not_after": asn1.parse_time(validity.children[1]),
        "modulus": public["modulus"],
        "public_exponent": public["public_exponent"],
    }


def modulus_bits(modulus):
    return modulus.bit_length()


def public_key_fingerprint(modulus, public_exponent):
    """SHA-256 over the canonical DER encoding of RSAPublicKey.

    The same (n, e) always yields the same fingerprint no matter which
    container (PKCS#1, PKCS#8, SPKI, certificate) it was read from, so
    private keys and certificates can be paired by comparing fingerprints.
    """
    pkcs1_der = der.encode_sequence(
        der.encode_integer(modulus),
        der.encode_integer(public_exponent),
    )
    return hashlib.sha256(pkcs1_der).hexdigest()
