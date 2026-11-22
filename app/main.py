import asyncio
import os
import re
import tempfile
import time
from collections import deque
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from starlette.concurrency import run_in_threadpool

from app import capture_store
from app.catalog import MAX_BYTES, SAMPLES, STATIC
from app.models import Analysis, Rule
from app.rule_store import current_rules, rules_path, save_change
from app.services import pcap_parser as parser

app = FastAPI(title="SentinelGRC", version="1.0.0", docs_url=None, redoc_url=None,
    description="Offline packet inspection and scenario-based SOC and GRC evidence.")
recent_jobs = deque()
active_jobs = 0
PUBLIC_ASSETS = {"index.html", "style.css", "app.js", "demo-data.js", "mark.svg"}


@app.middleware("http")
async def security_headers(request: Request, call_next):
    origin = request.headers.get("origin")
    try:
        foreign = bool(origin and urlsplit(origin).netloc != request.headers.get("host"))
    except ValueError:
        foreign = True
    if request.method in {"POST", "PUT", "DELETE"} and (foreign or request.headers.get("sec-fetch-site") == "cross-site"):
        response = JSONResponse({"detail": "Cross-site requests are disabled."}, status_code=403)
    else:
        response = await call_next(request)
    response.headers.update({
        "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; font-src 'self'; base-uri 'none'; "
            "form-action 'none'; frame-ancestors 'none'; object-src 'none'",
        "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer", "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        "Cache-Control": "no-store",
    })
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response


@asynccontextmanager
async def analysis_slot():
    # Uvicorn runs one event loop per worker. No await occurs during admission.
    global active_jobs
    now = time.monotonic()
    while recent_jobs and now - recent_jobs[0] >= 60:
        recent_jobs.popleft()
    if active_jobs >= 2 or len(recent_jobs) >= 30:
        raise HTTPException(429, "Analysis capacity reached. Try again shortly.", headers={"Retry-After": "30"})
    recent_jobs.append(now)
    active_jobs += 1
    try:
        yield
    finally:
        active_jobs -= 1


@app.exception_handler(parser.InvalidCapture)
async def invalid_capture(request, exc):
    return JSONResponse({"detail": str(exc)}, status_code=422)


@app.exception_handler(parser.ParserUnavailable)
async def unavailable(request, exc):
    return JSONResponse({"detail": str(exc)}, status_code=503)


def uploads_enabled():
    return os.getenv("ENABLE_UPLOADS") == "1" and bool(parser.tshark_binary())


@app.get("/healthz", tags=["Service"])
def health():
    ready = bool(parser.tshark_binary()) or os.getenv("REQUIRE_TSHARK") != "1"
    return JSONResponse({"status": "ready" if ready else "parser unavailable"}, status_code=200 if ready else 503)


@app.get("/api/v1/config", tags=["Service"])
def config():
    repository = os.getenv("GITHUB_REPOSITORY", "")
    return {"uploads": uploads_enabled(), "live_parser": bool(parser.tshark_binary()),
        "max_upload_bytes": MAX_BYTES,
        "repository": repository if re.fullmatch(r"[a-zA-Z0-9-]+/[a-zA-Z0-9_.-]+", repository) else None}


def local_request(request):
    return (request.client is not None and request.client.host in {"127.0.0.1", "::1"}
            and request.url.hostname in {"127.0.0.1", "::1", "localhost"})


def editable_rules_path(request):
    path = rules_path()
    return path if path is not None and local_request(request) and parser.tshark_binary() else None


def change_rule(request, rule_id, replacement):
    path = editable_rules_path(request)
    if path is None:
        raise HTTPException(403, "Rule editing requires a local server with RULES_FILE and TShark.")
    if replacement is not None:
        parser.validate_filter(replacement["filter"])
    try:
        rules = save_change(path, rule_id, replacement)
    except KeyError:
        raise HTTPException(404, "Unknown detection rule.") from None
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    except OSError:
        raise HTTPException(503, "Could not write the local rule catalogue.") from None
    return {"rules": rules, "editable": True}


@app.get("/api/v1/rules", tags=["Detection rules"])
def list_rules(request: Request):
    return {"rules": current_rules(), "editable": editable_rules_path(request) is not None}


@app.put("/api/v1/rules/{rule_id}", tags=["Detection rules"])
def put_rule(request: Request, rule_id: str, rule: Rule):
    if rule.id != rule_id:
        raise HTTPException(422, "The rule ID must match the URL.")
    replacement = rule.model_dump(mode="json", exclude_none=True)
    replacement["short"] = replacement["short"].strip() or rule.name
    for sample in SAMPLES.values():
        if sample["id"] == rule_id:
            replacement.update(sample=sample["sample"], file=sample["file"])
            break
    return change_rule(request, rule_id, replacement)


@app.delete("/api/v1/rules/{rule_id}", tags=["Detection rules"])
def delete_rule(request: Request, rule_id: str):
    return change_rule(request, rule_id, None)


@app.post("/api/v1/analyze-pcap/{sample}", response_model=Analysis, tags=["Analysis"])
async def sample_analysis(sample: str):
    """Analyse a bundled sample. Available sample names are ransomware, sqli and ssh."""
    if sample not in SAMPLES:
        raise HTTPException(404, "Unknown sample capture.")
    async with analysis_slot():
        return await run_in_threadpool(parser.analyze_sample, sample)


def capture_library(request):
    path = capture_store.library_path()
    return path if path is not None and local_request(request) and uploads_enabled() else None


@app.get("/api/v1/captures", tags=["Capture library"])
def saved_captures(request: Request):
    library = capture_library(request)
    if library is None:
        return {"enabled": False, "captures": []}
    try:
        return {"enabled": True, "captures": capture_store.list_captures(library)}
    except (OSError, ValueError):
        raise HTTPException(503, "The local capture library could not be read.") from None


@app.post("/api/v1/captures/{capture_id}/analyze", response_model=Analysis, tags=["Capture library"])
async def analyze_saved_capture(request: Request, capture_id: str):
    library = capture_library(request)
    if library is None:
        raise HTTPException(403, "The local capture library is disabled.")
    async with analysis_slot():
        try:
            capture, path = await run_in_threadpool(capture_store.get_capture, library, capture_id)
        except FileNotFoundError:
            raise HTTPException(404, "Saved capture not found.") from None
        except (OSError, ValueError):
            raise HTTPException(503, "The saved capture could not be read.") from None
        report = await run_in_threadpool(parser.analyze, path, capture.name)
        return {**report, "saved_capture": capture}


@app.post("/api/v1/upload", response_model=Analysis, tags=["Analysis"],
    openapi_extra={"requestBody": {"required": True, "content": {
        "application/octet-stream": {"schema": {"type": "string", "format": "binary"}}}}})
async def upload(request: Request, name: str | None = Query(default=None, max_length=255)):
    """Analyse a raw PCAP or PCAPNG body. The host must enable uploads."""
    if not uploads_enabled():
        raise HTTPException(403, "Custom uploads are disabled on this host.")
    if request.headers.get("content-type", "").split(";")[0] != "application/octet-stream":
        raise HTTPException(415, "Send the capture as application/octet-stream.")
    too_large = f"The capture exceeds the {MAX_BYTES // 1024**2} MiB upload limit."
    length = request.headers.get("content-length")
    if length and (not length.isascii() or not length.isdecimal() or len(length) > 10 or int(length) > MAX_BYTES):
        raise HTTPException(413, too_large)
    async with analysis_slot():
        with tempfile.TemporaryDirectory(prefix="sentinel-") as directory:
            path = Path(directory, "capture.bin")
            size = 0
            try:
                async with asyncio.timeout(15):
                    with path.open("xb") as output:
                        async for block in request.stream():
                            size += len(block)
                            if size > MAX_BYTES:
                                raise HTTPException(413, too_large)
                            output.write(block)
            except TimeoutError:
                raise HTTPException(408, "The upload timed out.") from None
            with path.open("rb") as source:
                if source.read(4) not in parser.MAGIC:
                    raise HTTPException(415, "Expected an uncompressed PCAP or PCAPNG file.")
            report = await run_in_threadpool(parser.analyze, path, "Custom capture")
            library = capture_library(request) if name else None
            if library is not None:
                filename = "".join(char for char in name.replace("\\", "/").rsplit("/", 1)[-1] if char.isprintable())
                try:
                    report["saved_capture"] = await run_in_threadpool(
                        capture_store.save_capture, library, path, filename.strip() or "Untitled capture")
                except (OSError, ValueError):
                    raise HTTPException(503, "The capture was analysed but could not be saved to the library.") from None
            return report


@app.get("/", include_in_schema=False)
def dashboard():
    return FileResponse(STATIC / "index.html")


@app.get("/{name}", include_in_schema=False)
def asset(name: str):
    if name not in PUBLIC_ASSETS:
        raise HTTPException(404)
    return FileResponse(STATIC / name)
