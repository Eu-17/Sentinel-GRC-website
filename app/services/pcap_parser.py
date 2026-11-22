import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from ipaddress import IPv4Address
from pathlib import Path

from app.catalog import CAPTURES, MAX_FRAMES, RULES, SAMPLES
from app.rule_store import current_rules
from app.services import capture_overview
from app.services.pipeline import build_report

MAGIC = {bytes.fromhex(value) for value in (
    "d4c3b2a1", "a1b2c3d4", "4d3cb2a1", "a1b23c4d", "0a0d0d0a"
)}
WORKER = Path(__file__).with_name("dissector_worker.py")
FIXTURES = json.loads((CAPTURES / "fixtures.json").read_text())


class InvalidCapture(ValueError):
    pass


class ParserUnavailable(RuntimeError):
    pass


def tshark_binary():
    return shutil.which("tshark") or next((str(p) for p in [
        Path("/Applications/Wireshark.app/Contents/MacOS/tshark")
    ] if os.access(p, os.X_OK)), None)


def fields(binary, capture, names, display_filter=None):
    command = [sys.executable, "-I", str(WORKER), binary, "-n", "-r", str(capture.resolve()),
               "-c", str(MAX_FRAMES + 1), "-T", "fields", "-E", "occurrence=f"]
    if display_filter:
        command.extend(["-Y", display_filter])
    for field in names:
        command.extend(["-e", field])
    with tempfile.TemporaryDirectory() as private, tempfile.TemporaryFile() as output:
        # A clean profile prevents third-party plugins or personal preferences loading.
        env = {"HOME": private, "XDG_CONFIG_HOME": private, "LC_ALL": "C", "PATH": os.defpath}
        try:
            completed = subprocess.run(command, stdout=output, stderr=subprocess.DEVNULL,
                cwd=private, env=env, timeout=8, check=False, stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired as exc:
            raise InvalidCapture("The capture exceeded the parser time limit.") from exc
        if completed.returncode:
            raise InvalidCapture("The capture is damaged, unsupported, or exceeded parser limits.")
        output.seek(0)
        return output.read().decode("ascii").splitlines()


def rule_filter(expression):
    return f"ip && ({expression})"


def validate_filter(expression):
    binary = tshark_binary()
    if not binary:
        raise ParserUnavailable("Install TShark to edit detection rules.")
    sample = CAPTURES / SAMPLES["ssh"]["file"]
    try:
        fields(binary, sample, ["frame.number"], rule_filter(expression))
    except InvalidCapture as exc:
        raise InvalidCapture("TShark could not run this display filter. Check its syntax.") from exc


def analyze(capture, name, *, rules=None):
    binary = tshark_binary()
    if not binary:
        raise ParserUnavailable("Install TShark to analyse a custom capture.")
    frame_count = len(fields(binary, capture, ["frame.number"]))
    if frame_count > MAX_FRAMES:
        raise InvalidCapture(f"Captures must contain at most {MAX_FRAMES:,} frames.")
    rules = current_rules() if rules is None else rules
    matches = {}
    columns = ["frame.number", "frame.time_epoch", "ip.src", "ip.dst", "tcp.srcport", "frame.len"]
    for rule in rules:
        flows = []
        for row in fields(binary, capture, columns, rule_filter(rule["filter"])):
            frame, time, source, dest, port, size = row.split("\t")
            if not (source and dest) or ("min_connections" in rule and not port):
                continue
            flows.append({"frame": int(frame), "time": float(time), "source": str(IPv4Address(source)),
                "destination": str(IPv4Address(dest)), "port": int(port) if port else None, "bytes": int(size),
                "protocol": rule["protocol"]})
        matches[rule["id"]] = flows
    report = build_report(name, "TShark", frame_count, matches, rules=rules)
    try:
        rows = fields(binary, capture, capture_overview.FIELDS)
        report["overview"] = capture_overview.summarize(rows, report["findings"])
    except InvalidCapture:
        # Keep completed rule results if the additional dissection exceeds its limits.
        pass
    return report


def analyze_sample(sample):
    path = CAPTURES / SAMPLES[sample]["file"]
    if tshark_binary():
        return analyze(path, path.name)
    if os.getenv("REQUIRE_TSHARK") == "1":
        raise ParserUnavailable("The configured TShark binary is unavailable.")
    if current_rules() != RULES:
        raise ParserUnavailable("Install TShark to run your edited rules on bundled captures.")
    fixture = FIXTURES[sample]
    if hashlib.sha256(path.read_bytes()).hexdigest() != fixture["sha256"]:
        raise ParserUnavailable("The bundled capture did not pass its integrity check.")
    return fixture["report"]
