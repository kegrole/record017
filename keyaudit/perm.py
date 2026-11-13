"""Filesystem permission checks for private key files."""

import stat


def mode_string(file_mode):
    """'0644'-style rendering of the permission bits."""
    return format(stat.S_IMODE(file_mode), "04o")


def is_too_open(file_mode):
    """True when group or other has any read permission on the file."""
    return bool(stat.S_IMODE(file_mode) & 0o044)
