# redactor.py - Enhanced version with improved name detection
import re
from typing import Dict, Tuple, List, Set
from sensitive_store import load_sensitive_store
import logging

logger = logging.getLogger(__name__)

class Redactor:
    def __init__(self):
        self._compiled_patterns = {}  # name -> compiled regex
        self._literals: List[str] = []
        self._name_patterns: List[re.Pattern] = []
        self.reload_store()

    def _build_enhanced_patterns(self):
        """Build comprehensive name and PII detection patterns"""
        
        # Enhanced name patterns that catch various formats
        name_patterns = [
            # Full names with common prefixes/suffixes
            r'\b(?:Mr\.?|Mrs\.?|Ms\.?|Dr\.?|Prof\.?)\s+[A-Z][a-z]+(?:\s+[A-Z]\.?)?\s+[A-Z][a-z]+\b',
            
            # Standard full names (First Middle? Last)
            r'\b[A-Z][a-z]{1,20}(?:\s+[A-Z]\.?)?\s+[A-Z][a-z]{1,20}\b',
            
            # Names with hyphens or apostrophes
            r'\b[A-Z][a-z]+(?:-[A-Z][a-z]+)?\s+[A-Z][a-z]+(?:-[A-Z][a-z]+)?\b',
            r"\b[A-Z][a-z]+(?:'[A-Z][a-z]+)?\s+[A-Z][a-z]+\b",
            
            # Three-part names (First Middle Last)
            r'\b[A-Z][a-z]{1,20}\s+[A-Z][a-z]{1,20}\s+[A-Z][a-z]{1,20}\b',
            
            # Names in common contexts
            r'(?:username|user|name|admin|customer|client|employee|person)[:=\s]+["\']?([A-Z][a-z]+\s+[A-Z][a-z]+)["\']?',
            
            # Email-based names (before @ symbol)
            r'\b([a-z]+\.[a-z]+)@',
            
            # Cardholder names (often in quotes or after "Name:")
            r'(?:cardholder|holder|name)[:=\s]+["\']?([A-Z][a-z]+(?:\s+[A-Z]\.?)?\s+[A-Z][a-z]+)["\']?',
        ]
        
        self._name_patterns = [
            re.compile(pattern, re.IGNORECASE | re.MULTILINE) 
            for pattern in name_patterns
        ]

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

        # Build enhanced name detection patterns
        self._build_enhanced_patterns()

        # Sort literals by length desc to match longer tokens first
        self._literals = sorted(set(self._literals), key=lambda s: -len(s))

    def _extract_names_from_line(self, line: str) -> Set[str]:
        """
        Extract potential names from a line using various heuristics.
        Returns a set of detected names.
        """
        detected_names = set()
        
        # Apply all name patterns
        for pattern in self._name_patterns:
            for match in pattern.finditer(line):
                # Get the matched name (either full match or first group)
                if match.groups():
                    name = match.group(1)
                else:
                    name = match.group(0)
                
                if name:
                    # Clean up the name
                    name = name.strip().strip('"\'')
                    
                    # Validate it looks like a real name
                    if self._is_valid_name(name):
                        detected_names.add(name)
        
        return detected_names

    def _is_valid_name(self, text: str) -> bool:
        """
        Validate if text looks like a real name.
        Filters out common false positives.
        """
        if not text or len(text) < 3:
            return False
        
        # Exclude common technical terms that match name patterns
        exclusions = {
            'Java', 'Spring', 'Hibernate', 'Apache', 'Tomcat', 'Redis', 
            'MySQL', 'Postgres', 'Docker', 'Kubernetes', 'Linux', 'Windows',
            'Python', 'JavaScript', 'React', 'Angular', 'Node', 'Express',
            'Database Connection', 'User Agent', 'Content Type', 'Http',
            'Request Body', 'Response Body', 'Error Message', 'Stack Trace',
            'Internal Server', 'Bad Request', 'Not Found', 'Service Unavailable',
            'Connection Pool', 'Thread Pool', 'Session Id', 'Transaction Id',
            'Api Key', 'Access Token', 'Refresh Token', 'Bearer Token',
            'Native Method', 'Query Executor', 'Connection Timeout',
            'File Upload', 'File Size', 'Rate Limit', 'Cache Manager',
            'Security Filter', 'Authentication Filter', 'Audit Logger',
            'Tech Company', 'Mail Provider', 'Cloud Internal', 'Park Street',
            'Elm Avenue', 'Main Street'
        }
        
        if text in exclusions:
            return False
        
        # Must have at least one space for full names
        if ' ' in text:
            parts = text.split()
            # Each part should be capitalized and alphabetic
            if all(part[0].isupper() and part.isalpha() for part in parts if part):
                # Exclude if it contains common technical keywords
                text_lower = text.lower()
                tech_keywords = ['error', 'exception', 'connection', 'request', 'response', 
                                'service', 'server', 'client', 'method', 'class', 'pool',
                                'manager', 'handler', 'controller', 'filter', 'executor']
                if not any(keyword in text_lower for keyword in tech_keywords):
                    return True
        
        return False

    def redact_line(self, line: str, redaction_counts: Dict[str, int]) -> str:
        """
        Redact a single line applying patterns, name detection, and literals.
        Update redaction_counts in-place.
        """
        redacted_line = line
        
        # Step 1: Apply predefined patterns from store
        for name, regex in self._compiled_patterns.items():
            try:
                redacted_line, n = regex.subn(f"[REDACTED_{name.upper()}]", redacted_line)
                if n:
                    redaction_counts[name] = redaction_counts.get(name, 0) + n
            except re.error as e:
                logger.warning("Regex error while redacting with '%s': %s", name, e)
        
        # Step 2: Detect and redact names dynamically
        detected_names = self._extract_names_from_line(redacted_line)
        for name in detected_names:
            # Use word boundaries for whole-word matching
            pattern = re.compile(r'\b' + re.escape(name) + r'\b', re.IGNORECASE)
            redacted_line, n = pattern.subn('[REDACTED_NAME]', redacted_line)
            if n:
                redaction_counts['detected_name'] = redaction_counts.get('detected_name', 0) + n
        
        # Step 3: Apply literal redactions
        for literal in self._literals:
            if not literal:
                continue
            esc = re.escape(literal)
            try:
                # Try word-boundary variant if literal is word-like
                if re.search(r"\w", literal):
                    pat = re.compile(rf"\b{esc}\b", flags=re.IGNORECASE)
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
        - sanitized_preview is a truncated concatenation of the sanitized lines.
        """
        summary = {}
        preview_parts: List[str] = []
        total_bytes = 0
        
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