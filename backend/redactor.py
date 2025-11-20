# redactor.py
import re
from typing import Dict, Tuple, List
from sensitive_store import load_sensitive_store
import logging

logger = logging.getLogger(__name__)

class Redactor:
    def __init__(self):
        self._compiled_patterns = {}  # name -> compiled regex
        self._literals: List[str] = []
        self.reload_store()

    def reload_store(self):
        """
        Load patterns & literals from sensitive_store.json and compile them.
        Invalid regexes are skipped but logged.
        """
        store = load_sensitive_store()
        self._compiled_patterns = {}
        self._literals = store.get("literals", []) or []
        patterns = store.get("patterns", {}) or {}

        for name, pattern in patterns.items():
            try:
                compiled = re.compile(pattern, flags=re.IGNORECASE | re.MULTILINE)
                self._compiled_patterns[name] = compiled
            except re.error as e:
                logger.warning("Skipping invalid pattern '%s': %s", name, e)

        # Sort literals by length desc to match longer tokens first
        self._literals = sorted(set(self._literals), key=lambda s: -len(s))

    def redact_line(self, line: str, redaction_counts: Dict[str, int]) -> str:
        """
        Redact a single line applying patterns first then literals.
        Update redaction_counts in-place.
        """
        # Apply patterns
        def _replace_pattern(m):
            # find which named group matched (if any)
            # but since we compile individual patterns, we just know the pattern name externally
            # we will use a closure trick when substituting below
            return "[REDACTED]"

        # Patterns - iterate so we can tag counts per pattern name
        redacted_line = line
        for name, regex in self._compiled_patterns.items():
            try:
                redacted_line, n = regex.subn(f"[REDACTED_{name.upper()}]", redacted_line)
                if n:
                    redaction_counts[name] = redaction_counts.get(name, 0) + n
            except re.error as e:
                logger.warning("Regex error while redacting with '%s': %s", name, e)

        # Literals - do exact/escaped matches (case-insensitive)
        for literal in self._literals:
            if not literal:
                continue
            esc = re.escape(literal)
            try:
                # Try word-boundary variant if literal is word-like
                if re.search(r"\w", literal):
                    pat = re.compile(rf"\b{esc}\b", flags=re.IGNORECASE)
                    redacted_line, n = pat.subn("[REDACTED_LITERAL]", redacted_line)
                else:
                    pat = re.compile(esc, flags=re.IGNORECASE)
                    redacted_line, n = pat.subn("[REDACTED_LITERAL]", redacted_line)

                if n:
                    redaction_counts["literal"] = redaction_counts.get("literal", 0) + n
            except re.error as e:
                logger.warning("Skipping literal due to regex error for '%s': %s", literal, e)

        return redacted_line

    def redact_stream(self, stream, max_preview_chars: int = 2000) -> Tuple[str, Dict[str, int], int]:
        """
        Redact content from a file-like stream (iterable of lines or bytes).
        Returns (sanitized_preview, redaction_counts, total_bytes_processed)
        - Keeps memory usage low by processing per-line.
        - sanitized_preview is a truncated concatenation of the sanitized lines (useful to show first N chars).
        """
        summary = {}
        preview_parts: List[str] = []
        total_bytes = 0
        # If stream yields bytes, decode per-chunk
        for raw in stream:
            if isinstance(raw, bytes):
                try:
                    line = raw.decode("utf-8", errors="ignore")
                except Exception:
                    line = raw.decode("utf-8", errors="ignore")
            else:
                line = str(raw)

            total_bytes += len(line)
            redacted = self.redact_line(line, summary)

            # Collect preview up to max_preview_chars
            if sum(len(p) for p in preview_parts) < max_preview_chars:
                preview_parts.append(redacted)
        preview = "".join(preview_parts)
        if len(preview) > max_preview_chars:
            preview = preview[:max_preview_chars] + "..."

        return preview, summary, total_bytes

# Singleton redactor for app
_redactor = Redactor()

def reload_redaction_store():
    _redactor.reload_store()

def redact_file_stream(file_like) -> Tuple[str, Dict[str, int], int]:
    """
    file_like should be an iterator over bytes chunks or lines (UploadFile.file is fine).
    """
    return _redactor.redact_stream(file_like)
