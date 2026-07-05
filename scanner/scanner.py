import io
import os
import re
import socket
from dataclasses import dataclass
from typing import Iterable

import pikepdf
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.datastructures import UploadFile


CLAMAV_HOST = os.getenv("CLAMAV_HOST", "clamav")
CLAMAV_PORT = int(os.getenv("CLAMAV_PORT", "3310"))
MAX_FILE_SIZE_BYTES = int(os.getenv("MAX_FILE_SIZE_BYTES", str(50 * 1024 * 1024)))


app = FastAPI()


DANGEROUS_PDF_NAMES = {
    "/JavaScript",
    "/JS",
    "/OpenAction",
    "/AA",
    "/Launch",
    "/SubmitForm",
    "/ImportData",
    "/RichMedia",
    "/EmbeddedFile",
    "/AcroForm",
    "/XFA",
    "/Names",
}


RAW_BLOCK_PATTERNS: list[tuple[str, re.Pattern[bytes]]] = [
    # Universal EICAR detection:
    # - exact canonical EICAR string;
    # - tolerant to whitespace/newlines between chunks;
    # - also catches the stable EICAR marker text.
    (
        "eicar_test_signature",
        re.compile(
            rb"X5O!P%@AP\s*"
            rb"\[\s*4\s*\\\s*PZX54\s*"
            rb"\(\s*P\^\s*\)\s*7CC\s*\)\s*7\s*}\s*"
            rb"\$?\s*EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\s*"
            rb"\$?\s*H\+H\*",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "eicar_marker",
        re.compile(
            rb"EICAR-STANDARD-ANTIVIRUS-TEST-FILE",
            re.IGNORECASE | re.DOTALL,
        ),
    ),

    # Raw JavaScript-ish risky markers.
    # These are intentionally conservative for a vulnerable PDF-processing monolith.
    (
        "javascript_eval",
        re.compile(rb"\beval\s*\(", re.IGNORECASE | re.DOTALL),
    ),
    (
        "javascript_function_constructor",
        re.compile(rb"\bFunction\s*\(", re.IGNORECASE | re.DOTALL),
    ),
    (
        "javascript_set_timeout",
        re.compile(rb"\bsetTimeout\s*\(", re.IGNORECASE | re.DOTALL),
    ),
    (
        "javascript_set_interval",
        re.compile(rb"\bsetInterval\s*\(", re.IGNORECASE | re.DOTALL),
    ),
    (
        "javascript_launch_url",
        re.compile(rb"app\s*\.\s*launchURL", re.IGNORECASE | re.DOTALL),
    ),
    (
        "javascript_submit_form",
        re.compile(rb"\bsubmitForm\b", re.IGNORECASE | re.DOTALL),
    ),
    (
        "javascript_export_data_object",
        re.compile(rb"\bexportDataObject\b", re.IGNORECASE | re.DOTALL),
    ),
    (
        "javascript_get_field",
        re.compile(rb"\bgetField\s*\(", re.IGNORECASE | re.DOTALL),
    ),
]


DANGEROUS_STREAM_PATTERNS = RAW_BLOCK_PATTERNS


@dataclass
class ScanResult:
    allowed: bool
    reason: str = "ok"
    detail: str = ""


def clamav_instream_scan(data: bytes) -> ScanResult:
    if len(data) > MAX_FILE_SIZE_BYTES:
        return ScanResult(False, "file_too_large", "File exceeds scanner limit")

    try:
        with socket.create_connection((CLAMAV_HOST, CLAMAV_PORT), timeout=5) as sock:
            sock.settimeout(60)

            # zINSTREAM uses a zero-terminated command and zero-terminated response.
            sock.sendall(b"zINSTREAM\0")

            chunk_size = 8192
            for offset in range(0, len(data), chunk_size):
                chunk = data[offset : offset + chunk_size]
                sock.sendall(len(chunk).to_bytes(4, "big") + chunk)

            sock.sendall((0).to_bytes(4, "big"))

            response = b""
            while not response.endswith(b"\0"):
                part = sock.recv(4096)
                if not part:
                    break
                response += part

        text = response.rstrip(b"\0").decode("utf-8", errors="replace")

    except Exception as exc:
        return ScanResult(False, "clamav_error", str(exc))

    if "FOUND" in text:
        return ScanResult(False, "malware_detected", text)

    if "OK" in text:
        return ScanResult(True)

    return ScanResult(False, "clamav_unexpected_response", text)


def raw_policy_scan(data: bytes) -> ScanResult:
    for name, pattern in RAW_BLOCK_PATTERNS:
        if pattern.search(data):
            return ScanResult(
                False,
                "raw_pattern_blocked",
                f"Raw dangerous pattern detected: {name}",
            )

    return ScanResult(True)


def looks_like_pdf(data: bytes) -> bool:
    return data.lstrip().startswith(b"%PDF-")


def iter_pikepdf_objects(pdf: pikepdf.Pdf) -> Iterable[object]:
    for obj in pdf.objects:
        yield obj


def object_contains_dangerous_name(obj: object) -> str | None:
    text = repr(obj)

    for name in DANGEROUS_PDF_NAMES:
        if name in text:
            return name

    return None


def stream_contains_dangerous_pattern(obj: object) -> str | None:
    if not isinstance(obj, pikepdf.Stream):
        return None

    try:
        data = obj.read_bytes()
    except Exception:
        return "unreadable_stream"

    for name, pattern in DANGEROUS_STREAM_PATTERNS:
        if pattern.search(data):
            return name

    return None


def pdf_policy_scan(data: bytes) -> ScanResult:
    if not looks_like_pdf(data):
        return ScanResult(True)

    try:
        with pikepdf.open(io.BytesIO(data)) as pdf:
            for obj in iter_pikepdf_objects(pdf):
                dangerous_name = object_contains_dangerous_name(obj)
                if dangerous_name:
                    return ScanResult(
                        False,
                        "pdf_active_content_blocked",
                        f"Dangerous PDF object/name detected: {dangerous_name}",
                    )

                dangerous_stream = stream_contains_dangerous_pattern(obj)
                if dangerous_stream:
                    return ScanResult(
                        False,
                        "pdf_script_pattern_blocked",
                        f"Dangerous decoded stream pattern detected: {dangerous_stream}",
                    )

    except pikepdf.PdfError as exc:
        return ScanResult(
            False,
            "pdf_parse_failed",
            f"PDF parser failed: {exc}",
        )
    except Exception as exc:
        return ScanResult(
            False,
            "pdf_policy_error",
            str(exc),
        )

    return ScanResult(True)


async def extract_payloads(request: Request) -> list[tuple[str, bytes]]:
    content_type = request.headers.get("content-type", "")

    if "multipart/form-data" in content_type:
        form = await request.form()
        payloads: list[tuple[str, bytes]] = []

        for key, value in form.multi_items():
            if isinstance(value, UploadFile):
                payloads.append((value.filename or key, await value.read()))

        # После request.form() нельзя делать fallback на request.body(),
        # иначе Starlette может вернуть "Stream consumed".
        return payloads

    body = await request.body()
    return [("request-body", body)]


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/scan")
async def scan(request: Request):
    try:
        payloads = await extract_payloads(request)
    except Exception as exc:
        return JSONResponse(
            status_code=403,
            content={
                "error": "payload_extract_failed",
                "message": str(exc),
            },
        )

    if not payloads:
        return {
            "status": "ok",
            "message": "no payloads",
        }

    for filename, data in payloads:
        print(
            f"scanning filename={filename}, size={len(data)}",
            flush=True,
        )

        if len(data) > MAX_FILE_SIZE_BYTES:
            return JSONResponse(
                status_code=413,
                content={
                    "error": "file_too_large",
                    "filename": filename,
                    "message": "File exceeds scanner limit",
                },
            )

        # 1. Raw bytes policy.
        # Ловит EICAR/eval/Function/app.launchURL даже в PDF comments/raw body.
        raw_result = raw_policy_scan(data)
        if not raw_result.allowed:
            return JSONResponse(
                status_code=403,
                content={
                    "error": raw_result.reason,
                    "filename": filename,
                    "message": raw_result.detail,
                },
            )

        # 2. ClamAV known malware signatures.
        av_result = clamav_instream_scan(data)
        if not av_result.allowed:
            status_code = 403 if av_result.reason == "malware_detected" else 503
            return JSONResponse(
                status_code=status_code,
                content={
                    "error": av_result.reason,
                    "filename": filename,
                    "message": av_result.detail,
                },
            )

        # 3. PDF structural policy via pikepdf.
        # Ловит PDF actions/names/objects и decoded stream patterns.
        pdf_result = pdf_policy_scan(data)
        if not pdf_result.allowed:
            return JSONResponse(
                status_code=403,
                content={
                    "error": pdf_result.reason,
                    "filename": filename,
                    "message": pdf_result.detail,
                },
            )

    return {
        "status": "ok",
        "files_scanned": len(payloads),
    }