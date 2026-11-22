import errno
import hashlib
import os
import re
import shutil
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from app.models import SavedCapture


def library_path():
    configured = os.getenv("CAPTURE_LIBRARY_DIR")
    return Path(configured) if configured else None


def get_capture(library, capture_id):
    if not re.fullmatch(r"[a-f0-9]{64}", capture_id):
        raise FileNotFoundError
    folder = library / capture_id
    capture = SavedCapture.model_validate_json((folder / "metadata.json").read_bytes())
    path = folder / "capture.bin"
    if not path.is_file():
        raise FileNotFoundError
    return capture, path


def list_captures(library):
    if not library.exists():
        return []
    captures = []
    for folder in library.iterdir():
        try:
            capture, _ = get_capture(library, folder.name)
        except FileNotFoundError:
            continue
        captures.append(capture)
    return sorted(captures, key=lambda capture: capture.uploaded_at, reverse=True)


def save_capture(library, source, name):
    with source.open("rb") as upload:
        capture_id = hashlib.file_digest(upload, "sha256").hexdigest()
    try:
        return get_capture(library, capture_id)[0]
    except FileNotFoundError:
        pass

    library.mkdir(mode=0o700, parents=True, exist_ok=True)
    capture = SavedCapture(id=capture_id, name=name, size=source.stat().st_size, uploaded_at=datetime.now(UTC))
    with tempfile.TemporaryDirectory(prefix=".pending-", dir=library) as directory:
        pending = Path(directory)
        shutil.copyfile(source, pending / "capture.bin")
        (pending / "metadata.json").write_text(capture.model_dump_json(), encoding="utf-8")
        try:
            pending.rename(library / capture_id)
        except OSError as exc:
            if exc.errno not in {errno.EEXIST, errno.ENOTEMPTY}:
                raise
            # An identical upload completed while this one was being stored.
            return get_capture(library, capture_id)[0]
    return capture
