"""Minimal ASN.1 DER parser and encoder (standard library only)."""


class DerError(ValueError):
    """Raised when input bytes are not valid DER."""


UNIVERSAL = 0
APPLICATION = 1
CONTEXT = 2
PRIVATE = 3

TAG_INTEGER = 0x02
TAG_BIT_STRING = 0x03
TAG_OCTET_STRING = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_UTF8_STRING = 0x0C
TAG_SEQUENCE = 0x10
TAG_SET = 0x11
TAG_PRINTABLE_STRING = 0x13
TAG_IA5_STRING = 0x16
TAG_UTC_TIME = 0x17
TAG_GENERALIZED_TIME = 0x18


class Node:
    """One parsed DER TLV.

    value holds the raw content bytes for primitive nodes; children
    holds parsed sub-nodes for constructed nodes.
    """

    __slots__ = ("tag_class", "constructed", "tag", "value", "children")

    def __init__(self, tag_class, constructed, tag, value, children):
        self.tag_class = tag_class
        self.constructed = constructed
        self.tag = tag
        self.value = value
        self.children = children

    def __repr__(self):
        return (
            "Node(cls=%d tag=%d constructed=%r len=%d)"
            % (self.tag_class, self.tag, self.constructed, len(self.value))
        )


def _read_length(data, pos):
    if pos >= len(data):
        raise DerError("truncated: missing length octet")
    first = data[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    count = first & 0x7F
    if count == 0:
        raise DerError("indefinite length is not valid DER")
    if count > 4 or pos + count > len(data):
        raise DerError("truncated or absurd length octets")
    length = int.from_bytes(data[pos:pos + count], "big")
    if length < 0x80:
        raise DerError("non-minimal length encoding")
    return length, pos + count


def parse(data, pos=0):
    """Parse one TLV starting at pos; return (Node, next_offset)."""
    if pos >= len(data):
        raise DerError("truncated: missing tag")
    first = data[pos]
    pos += 1
    tag_class = (first >> 6) & 0x03
    constructed = bool(first & 0x20)
    tag = first & 0x1F
    if tag == 0x1F:  # high-tag-number form
        tag = 0
        while True:
            if pos >= len(data):
                raise DerError("truncated multi-octet tag")
            byte = data[pos]
            pos += 1
            tag = (tag << 7) | (byte & 0x7F)
            if not byte & 0x80:
                break
    length, pos = _read_length(data, pos)
    end = pos + length
    if end > len(data):
        raise DerError("truncated content")
    content = data[pos:end]
    if constructed:
        children = []
        offset = 0
        while offset < len(content):
            child, offset = parse(content, offset)
            children.append(child)
        return Node(tag_class, True, tag, content, children), end
    return Node(tag_class, False, tag, content, None), end


def parse_one(data):
    """Parse exactly one TLV and require the input to be fully consumed."""
    node, end = parse(data, 0)
    if end != len(data):
        raise DerError("trailing bytes after DER value")
    return node


def expect(node, tag, tag_class=UNIVERSAL):
    if node.tag != tag or node.tag_class != tag_class:
        raise DerError(
            "unexpected tag: got class=%d tag=%d, want class=%d tag=%d"
            % (node.tag_class, node.tag, tag_class, tag)
        )
    return node


def as_integer(node):
    """Unsigned INTEGER value (RSA moduli are always non-negative)."""
    expect(node, TAG_INTEGER)
    if not node.value:
        raise DerError("empty INTEGER")
    return int.from_bytes(node.value, "big", signed=False)


def _read_base128(data, pos):
    value = 0
    while True:
        if pos >= len(data):
            raise DerError("truncated base-128 subidentifier")
        byte = data[pos]
        pos += 1
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            return value, pos


def as_oid(node):
    """Dotted-decimal OID string, e.g. '1.2.840.113549.1.1.1'."""
    expect(node, TAG_OID)
    if not node.value:
        raise DerError("empty OID")
    subs = []
    pos = 0
    while pos < len(node.value):
        sub, pos = _read_base128(node.value, pos)
        subs.append(sub)
    first = subs[0]
    if first < 40:
        arcs = [0, first]
    elif first < 80:
        arcs = [1, first - 40]
    else:
        arcs = [2, first - 80]
    arcs.extend(subs[1:])
    return ".".join(str(arc) for arc in arcs)


def as_string(node):
    """Decode a DirectoryString-ish primitive to str."""
    if node.tag in (TAG_UTF8_STRING, TAG_PRINTABLE_STRING, TAG_IA5_STRING):
        try:
            return node.value.decode("utf-8")
        except UnicodeDecodeError:
            return node.value.decode("latin-1")
    raise DerError("not a string tag: %d" % node.tag)


def as_bit_string(node):
    """BIT STRING payload with the unused-bits octet stripped."""
    expect(node, TAG_BIT_STRING)
    if not node.value:
        raise DerError("empty BIT STRING")
    if node.value[0] != 0:
        raise DerError("only byte-aligned BIT STRINGs are supported")
    return node.value[1:]


def encode_length(length):
    if length < 0x80:
        return bytes([length])
    body = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def encode_tlv(tag_byte, content):
    return bytes([tag_byte]) + encode_length(len(content)) + content


def encode_integer(value):
    if value < 0:
        raise DerError("only non-negative INTEGERs are supported")
    body = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if body[0] & 0x80:
        body = b"\x00" + body
    return encode_tlv(TAG_INTEGER, body)


def encode_sequence(*items):
    return encode_tlv(0x30, b"".join(items))


def encode_set(*items):
    return encode_tlv(0x31, b"".join(items))


def encode_oid(dotted):
    arcs = [int(part) for part in dotted.split(".")]
    if len(arcs) < 2 or arcs[0] > 2:
        raise DerError("invalid OID: %s" % dotted)
    subs = [arcs[0] * 40 + arcs[1]] + arcs[2:]
    out = bytearray()
    for sub in subs:
        if sub < 0:
            raise DerError("invalid OID arc")
        stack = [sub & 0x7F]
        sub >>= 7
        while sub:
            stack.append(0x80 | (sub & 0x7F))
            sub >>= 7
        out.extend(reversed(stack))
    return encode_tlv(TAG_OID, bytes(out))


def encode_null():
    return encode_tlv(TAG_NULL, b"")


def encode_bit_string(payload):
    return encode_tlv(TAG_BIT_STRING, b"\x00" + payload)


def encode_octet_string(payload):
    return encode_tlv(TAG_OCTET_STRING, payload)


def encode_utf8_string(text):
    return encode_tlv(TAG_UTF8_STRING, text.encode("utf-8"))


def encode_printable_string(text):
    return encode_tlv(TAG_PRINTABLE_STRING, text.encode("ascii"))


def encode_utc_time(moment):
    return encode_tlv(TAG_UTC_TIME, moment.strftime("%y%m%d%H%M%SZ").encode("ascii"))


def encode_context(tag_number, content, constructed=True):
    tag_byte = (CONTEXT << 6) | (0x20 if constructed else 0) | tag_number
    return encode_tlv(tag_byte, content)
