# sensitive_store.py
import json
from pathlib import Path
from typing import Dict

STORE_PATH = Path(__file__).parent / "sensitive_store.json"

def load_sensitive_store() -> Dict:
    """
    Load the JSON store. Ensures file exists.
    """
    if not STORE_PATH.exists():
        STORE_PATH.write_text(json.dumps({"literals": [], "patterns": {}}, indent=2), encoding="utf-8")
    with open(STORE_PATH, "r", encoding="utf-8") as f:
        return json.load(f)
