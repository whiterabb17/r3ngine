"""Evidence validator.

Validates evidence before it is persisted: type, size, MIME type, and
allowed extensions. Returns a list of error messages (empty = valid).

Usage:
    from evidence.validators import validate_evidence_upload
    errors = validate_evidence_upload(content, filename, evidence_type)
    if errors:
        raise ValidationError(errors)
"""
import mimetypes
import os
from typing import List

from django.conf import settings


# ---------------------------------------------------------------------------
# Allowed type → extension mapping
# ---------------------------------------------------------------------------
ALLOWED_EXTENSIONS: dict[str, List[str]] = {
    'Screenshot':      ['.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp'],
    'NetworkCapture':  ['.pcap', '.pcapng', '.har', '.cap'],
    'RequestResponse': ['.txt', '.json', '.xml', '.http', '.har'],
    'CommandOutput':   ['.txt', '.log', '.json', '.xml', '.csv'],
    'Log':             ['.log', '.txt', '.json', '.gz', '.zip'],
    'Report':          ['.pdf', '.docx', '.xlsx', '.html', '.md', '.txt'],
    'Other':           [],  # Empty = any extension allowed
}

ALLOWED_MIME_TYPES: List[str] = [
    'image/png', 'image/jpeg', 'image/gif', 'image/webp', 'image/bmp',
    'application/json', 'application/xml', 'application/pdf',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/octet-stream',  # pcap, etc.
    'application/gzip', 'application/zip',
    'text/plain', 'text/html', 'text/csv', 'text/xml',
    'text/markdown',
]


def validate_evidence_upload(
    content: bytes,
    filename: str,
    evidence_type: str,
) -> List[str]:
    """Validate evidence content before persisting it.

    Performs the following checks:
    1. File size does not exceed EVIDENCE_MAX_SIZE_BYTES.
    2. File extension is allowed for the given evidence_type.
    3. Detected MIME type is in the allowed list.

    Args:
        content (bytes): Raw file bytes.
        filename (str): Original filename (used to determine extension).
        evidence_type (str): One of the EVIDENCE_TYPE_CHOICES keys.

    Returns:
        list[str]: List of validation error messages. Empty = valid.
    """
    errors: List[str] = []
    max_bytes = getattr(settings, 'EVIDENCE_MAX_SIZE_BYTES', 50 * 1024 * 1024)
    ext = os.path.splitext(filename)[-1].lower()

    # 1. Size check
    if len(content) > max_bytes:
        max_mb = max_bytes / (1024 * 1024)
        actual_mb = len(content) / (1024 * 1024)
        errors.append(f"File too large: {actual_mb:.1f} MB exceeds limit of {max_mb:.0f} MB.")

    # 2. Extension check (skip for 'Other' type)
    allowed_exts = ALLOWED_EXTENSIONS.get(evidence_type, [])
    if allowed_exts and ext not in allowed_exts:
        errors.append(
            f"Extension '{ext}' is not allowed for evidence type '{evidence_type}'. "
            f"Allowed: {', '.join(allowed_exts)}"
        )

    # 3. MIME type check (best-effort via filename — deep inspection is out of scope)
    guessed_mime, _ = mimetypes.guess_type(filename)
    if guessed_mime and guessed_mime not in ALLOWED_MIME_TYPES:
        errors.append(f"MIME type '{guessed_mime}' is not in the allowed list.")

    return errors


def detect_mime_type(filename: str, content: bytes) -> str:
    """Detect MIME type from filename with a fallback to binary.

    Args:
        filename (str): The original filename.
        content (bytes): File bytes (used for magic-byte detection if python-magic is available).

    Returns:
        str: Detected MIME type string.
    """
    # Prefer python-magic if available for accurate detection
    try:
        import magic
        mime = magic.from_buffer(content[:4096], mime=True)
        return mime
    except ImportError:
        pass

    guessed, _ = mimetypes.guess_type(filename)
    return guessed or 'application/octet-stream'
