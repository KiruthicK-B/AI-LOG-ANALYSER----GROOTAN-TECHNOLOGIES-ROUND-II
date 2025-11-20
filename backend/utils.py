# utils.py
import hashlib
from typing import Iterator

def sha256_text_iter(lines: Iterator[str]):
    """
    Compute SHA-256 incrementally from an iterator of strings.
    """
    h = hashlib.sha256()
    for s in lines:
        if isinstance(s, str):
            h.update(s.encode("utf-8"))
        else:
            h.update(str(s).encode("utf-8"))
    return h.hexdigest()
