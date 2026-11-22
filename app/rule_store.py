import json
import os
import tempfile
from pathlib import Path
from threading import Lock

from app.catalog import RULES

MAX_RULES = 12
_lock = Lock()


def rules_path():
    configured = os.getenv("RULES_FILE")
    return Path(configured) if configured else None


def current_rules():
    return read_rules(rules_path())


def read_rules(path):
    if path is not None:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            pass
    return RULES


def save_change(path, rule_id, replacement):
    with _lock:
        rules = list(read_rules(path))
        index = next((i for i, rule in enumerate(rules) if rule["id"] == rule_id), None)
        if replacement is None:
            if index is None:
                raise KeyError(rule_id)
            del rules[index]
        elif index is not None:
            rules[index] = replacement
        elif len(rules) >= MAX_RULES:
            raise ValueError(f"At most {MAX_RULES} detection rules can be enabled.")
        else:
            rules.append(replacement)

        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as stream:
            temp_path = Path(stream.name)
            try:
                json.dump(rules, stream, indent=2)
                stream.write("\n")
                stream.close()
                temp_path.replace(path)
            finally:
                temp_path.unlink(missing_ok=True)
        return rules
