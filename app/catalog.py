import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "app" / "static"
CAPTURES = ROOT / "sample_pcaps"
RULES = json.loads((ROOT / "app/data/control_matrix.json").read_text())
SAMPLES = {rule["sample"]: rule for rule in RULES}
MAX_BYTES = 50 * 1024 * 1024
MAX_FRAMES = 10_000
