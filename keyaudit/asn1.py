"""ASN.1 helpers: OID names, X.501 Name rendering, time parsing."""

from datetime import datetime, timezone

from . import der


ALGORITHM_OIDS = {
    "1.2.840.113549.1.1.1": "rsaEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
}

ATTRIBUTE_SHORT_NAMES = {
    "2.5.4.3": "CN",
    "2.5.4.4": "SN",
    "2.5.4.5": "serialNumber",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.9": "street",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "2.5.4.12": "title",
    "2.5.4.42": "GN",
    "1.2.840.113549.1.9.1": "emailAddress",
    "0.9.2342.19200300.100.1.25": "DC",
    "0.9.2342.19200300.100.1.1": "UID",
}


def algorithm_name(oid):
    return ALGORITHM_OIDS.get(oid, oid)


def name_to_string(name_node):
    """Render an X.501 Name (RDNSequence) as 'C=CN, O=..., CN=...'.

    RDNs are emitted in DER order; each AVA becomes SHORT=value with the
    attribute OID substituted when it has no well-known short name.
    """
    der.expect(name_node, der.TAG_SEQUENCE)
    parts = []
    for rdn in name_node.children:
        der.expect(rdn, der.TAG_SET)
        avas = []
        for atv in rdn.children:
            der.expect(atv, der.TAG_SEQUENCE)
            oid = der.as_oid(atv.children[0])
            label = ATTRIBUTE_SHORT_NAMES.get(oid, oid)
            avas.append("%s=%s" % (label, der.as_string(atv.children[1])))
        parts.append("+".join(avas))
    return ", ".join(parts)


def parse_time(node):
    """UTCTime / GeneralizedTime -> timezone-aware UTC datetime."""
    raw = node.value.decode("ascii")
    if not raw.endswith("Z"):
        raise der.DerError("only Zulu times are supported: %r" % raw)
    digits = raw[:-1]
    if node.tag == der.TAG_UTC_TIME:
        if len(digits) != 12 or not digits.isdigit():
            raise der.DerError("bad UTCTime: %r" % raw)
        year = int(digits[0:2])
        year += 2000 if year < 50 else 1900
        rest = digits[2:]
    elif node.tag == der.TAG_GENERALIZED_TIME:
        if len(digits) != 14 or not digits.isdigit():
            raise der.DerError("bad GeneralizedTime: %r" % raw)
        year = int(digits[0:4])
        rest = digits[4:]
    else:
        raise der.DerError("not a time tag: %d" % node.tag)
    month, day = int(rest[0:2]), int(rest[2:4])
    hour, minute, second = int(rest[4:6]), int(rest[6:8]), int(rest[8:10])
    return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)


def format_time(moment):
    """Canonical report form: 'YYYY-MM-DDTHH:MM:SSZ'."""
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
