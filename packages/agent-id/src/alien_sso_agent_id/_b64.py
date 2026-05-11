from __future__ import annotations

import base64
import re

# RFC 7515 §2 / RFC 7519 §7.2: base64url segments use the RFC 4648 §5
# alphabet WITHOUT padding, whitespace, or other characters. Python's
# urlsafe_b64decode silently tolerates whitespace and a 5-char-residue
# input — pre-screen the segment before decoding.
_B64URL_ALPHABET_RE = re.compile(r"^[A-Za-z0-9_-]*$")


def b64url_decode(s: str) -> bytes:
    if not _B64URL_ALPHABET_RE.fullmatch(s):
        raise ValueError("Invalid base64url segment (RFC 7515 §2)")
    if len(s) % 4 == 1:
        raise ValueError("Invalid base64url length (RFC 7515 §2)")
    s = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")
