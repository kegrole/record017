"""Audit files and directories, build JSON-serializable report records."""

import json
import os

from . import asn1, der, pairing, pem, perm, rsa


MIN_RSA_BITS = 2048

_PRIVATE_LABELS = ("RSA PRIVATE KEY", "PRIVATE KEY", "ENCRYPTED PRIVATE KEY")
_PUBLIC_LABELS = ("RSA PUBLIC KEY", "PUBLIC KEY")
_KNOWN_LABELS = _PRIVATE_LABELS + _PUBLIC_LABELS + ("CERTIFICATE",)


def _issue(code, detail):
    return {"code": code, "detail": detail}


def _public_parts_from_block(block):
    """Return (modulus, exponent) for any supported PEM block."""
    label = block.label
    if label == "RSA PRIVATE KEY":
        key = rsa.parse_pkcs1_private(block.der)
        return key["modulus"], key["public_exponent"]
    if label == "PRIVATE KEY":
        inner = rsa.parse_pkcs8_private(block.der)
        key = rsa.parse_pkcs1_private(inner)
        return key["modulus"], key["public_exponent"]
    if label == "RSA PUBLIC KEY":
        key = rsa.parse_pkcs1_public(block.der)
        return key["modulus"], key["public_exponent"]
    if label == "PUBLIC KEY":
        inner = rsa.parse_spki(block.der)
        key = rsa.parse_pkcs1_public(inner)
        return key["modulus"], key["public_exponent"]
    if label == "CERTIFICATE":
        cert = rsa.parse_certificate(block.der)
        return cert["modulus"], cert["public_exponent"]
    raise pem.PemError("unsupported PEM label: %s" % label)


def _is_encrypted_private(block):
    if block.label == "ENCRYPTED PRIVATE KEY":
        return True
    proc_type = block.headers.get("Proc-Type", "")
    return "ENCRYPTED" in proc_type.upper()


def audit_file(path, display_path):
    """Audit one file; return a report record or None if it is not PEM."""
    with open(path, "rb") as handle:
        raw = handle.read()
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    try:
        blocks = pem.parse(text)
    except pem.PemError as exc:
        return _error_record(path, display_path, str(exc))
    blocks = [block for block in blocks if block.label in _KNOWN_LABELS]
    if not blocks:
        return None
    block = blocks[0]

    record = {
        "file": display_path,
        "kind": None,
        "bits": None,
        "encrypted": False,
        "permission": perm.mode_string(os.stat(path).st_mode),
        "issues": [],
        "_dir": os.path.dirname(os.path.abspath(path)),
        "_fingerprint": None,
    }

    if block.label in _PRIVATE_LABELS:
        record["kind"] = "private_key"
        record["encrypted"] = _is_encrypted_private(block)
    elif block.label in _PUBLIC_LABELS:
        record["kind"] = "public_key"
    else:
        record["kind"] = "certificate"

    try:
        if record["encrypted"]:
            pass  # ciphertext: no public parts observable
        elif record["kind"] == "certificate":
            cert = rsa.parse_certificate(block.der)
            record["subject"] = cert["subject"]
            record["issuer"] = cert["issuer"]
            record["not_before"] = asn1.format_time(cert["not_before"])
            record["not_after"] = asn1.format_time(cert["not_after"])
            record["bits"] = rsa.modulus_bits(cert["modulus"])
            record["_fingerprint"] = rsa.public_key_fingerprint(
                cert["modulus"], cert["public_exponent"])
        else:
            modulus, exponent = _public_parts_from_block(block)
            record["bits"] = rsa.modulus_bits(modulus)
            record["_fingerprint"] = rsa.public_key_fingerprint(modulus, exponent)
    except (der.DerError, rsa.RsaError, ValueError) as exc:
        record["issues"].append(_issue("PARSE_ERROR", str(exc)))

    if record["bits"] is not None and record["bits"] < MIN_RSA_BITS:
        record["issues"].append(_issue(
            "WEAK_KEY",
            "RSA modulus is %d bits; minimum is %d"
            % (record["bits"], MIN_RSA_BITS),
        ))

    if record["kind"] == "private_key":
        if perm.is_too_open(os.stat(path).st_mode):
            record["issues"].append(_issue(
                "PERMISSION_TOO_OPEN",
                "private key file mode %s is readable by group/other"
                % record["permission"],
            ))

    return record


def _error_record(path, display_path, detail):
    return {
        "file": display_path,
        "kind": "unknown",
        "bits": None,
        "encrypted": False,
        "permission": perm.mode_string(os.stat(path).st_mode),
        "issues": [_issue("PARSE_ERROR", detail)],
        "_dir": os.path.dirname(os.path.abspath(path)),
        "_fingerprint": None,
    }


def audit_directory(root):
    """Recursively audit every PEM file under root; return record list."""
    records = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for filename in sorted(filenames):
            path = os.path.join(dirpath, filename)
            if not os.path.isfile(path):
                continue
            display = os.path.relpath(path, root)
            record = audit_file(path, display)
            if record is not None:
                records.append(record)
    pairing.apply_pairing(records)
    for record in records:
        record.pop("_dir", None)
        record.pop("_fingerprint", None)
    records.sort(key=lambda record: record["file"])
    return records


def summarize(records):
    return {
        "files": len(records),
        "private_keys": sum(1 for r in records if r["kind"] == "private_key"),
        "public_keys": sum(1 for r in records if r["kind"] == "public_key"),
        "certificates": sum(1 for r in records if r["kind"] == "certificate"),
        "issues": sum(len(r["issues"]) for r in records),
    }


def write_report(records, out_path):
    directory = os.path.dirname(os.path.abspath(out_path))
    os.makedirs(directory, exist_ok=True)
    payload = {"summary": summarize(records), "records": records}
    with open(out_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    return payload
