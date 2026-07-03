"""Evidence hashing service.

Provides SHA-256 hashing and integrity verification for evidence files.
All hashes are hex-encoded lowercase strings compatible with EvidenceEvent.hash_at_event.

Usage:
    from evidence.hashing import compute_sha256, verify_integrity
    hash_hex = compute_sha256(file_bytes)
    ok = verify_integrity(evidence_item)
"""
import hashlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from evidence.models import Evidence


def compute_sha256(content: bytes) -> str:
    """Compute the SHA-256 hash of raw bytes.

    Args:
        content (bytes): Raw file content.

    Returns:
        str: Lowercase hex-encoded SHA-256 digest, e.g. 'a3f1b2...'.
    """
    return hashlib.sha256(content).hexdigest()


def compute_sha256_stream(file_obj, chunk_size: int = 65536) -> str:
    """Compute SHA-256 by streaming a file-like object without loading it all into memory.

    Useful for large captures or PCAP files.

    Args:
        file_obj: Any file-like object with a .read() method.
        chunk_size (int): Number of bytes to read per chunk. Default: 64 KB.

    Returns:
        str: Lowercase hex-encoded SHA-256 digest.
    """
    h = hashlib.sha256()
    while True:
        chunk = file_obj.read(chunk_size)
        if not chunk:
            break
        h.update(chunk)
    return h.hexdigest()


def verify_integrity(evidence: 'Evidence') -> bool:
    """Verify that a stored evidence file matches its recorded SHA-256 hash.

    Reads the file from the configured storage backend and computes its hash,
    then compares it to evidence.sha256_hash.

    Args:
        evidence (Evidence): The Evidence model instance to verify.

    Returns:
        bool: True if the hash matches, False if the file has been tampered with
              or is missing.
    """
    from evidence.storage import get_storage_backend

    if not evidence.sha256_hash or not evidence.file_path:
        return False

    try:
        storage = get_storage_backend()
        content = storage.read(evidence.file_path)
        current_hash = compute_sha256(content)
        return current_hash == evidence.sha256_hash
    except (FileNotFoundError, Exception):
        return False


def record_integrity_check(evidence: 'Evidence', user=None) -> bool:
    """Verify integrity and write an EvidenceEvent record for the check.

    Args:
        evidence (Evidence): The Evidence item to verify.
        user: Optional Django User who triggered the check.

    Returns:
        bool: True if integrity check passed, False if it failed.
    """
    from evidence.models import EvidenceEvent
    from django.utils import timezone

    passed = verify_integrity(evidence)
    EvidenceEvent.objects.create(
        evidence=evidence,
        event_type='Verified',
        actor=user,
        hash_at_event=evidence.sha256_hash,
        note='Integrity check passed' if passed else 'INTEGRITY FAILURE: hash mismatch detected',
        timestamp=timezone.now(),
    )
    return passed
