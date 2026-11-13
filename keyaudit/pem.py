"""PEM text parsing: locate armor blocks, split headers, base64-decode."""

import base64
import binascii
import re


class PemError(ValueError):
    """Raised when a PEM block is malformed."""


_BLOCK_RE = re.compile(
    r"-----BEGIN ([A-Z0-9][A-Z0-9 ]*)-----[ \t]*\r?\n"
    r"(.*?)"
    r"-----END \1-----",
    re.DOTALL,
)

_HEADER_RE = re.compile(r"^([A-Za-z][A-Za-z0-9-]*):[ \t]*(.*)$")


class PemBlock:
    __slots__ = ("label", "headers", "der")

    def __init__(self, label, headers, der):
        self.label = label
        self.headers = headers
        self.der = der

    def __repr__(self):
        return "PemBlock(%r, %d bytes)" % (self.label, len(self.der))


def parse(text):
    """Return every PEM block found in text as a list of PemBlock."""
    blocks = []
    for match in _BLOCK_RE.finditer(text):
        label = match.group(1).strip()
        body = match.group(2)
        headers = {}
        payload_lines = []
        for raw_line in body.replace("\r", "").split("\n"):
            line = raw_line.strip()
            if not line:
                continue
            header = _HEADER_RE.match(line) if not payload_lines else None
            if header:
                headers[header.group(1)] = header.group(2).strip()
            else:
                payload_lines.append(line)
        try:
            der = base64.b64decode("".join(payload_lines), validate=True)
        except (binascii.Error, ValueError) as exc:
            raise PemError("bad base64 in %s block: %s" % (label, exc))
        blocks.append(PemBlock(label, headers, der))
    return blocks
