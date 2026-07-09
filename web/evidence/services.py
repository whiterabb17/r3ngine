"""Evidence service layer.

High-level operations for creating, retrieving, verifying, archiving,
and purging evidence. This is the authoritative interface for the rest of
the codebase to interact with evidence — activities, views, and signals
should all call through this service.

Usage:
    from evidence.services import EvidenceService
    item = EvidenceService.create_evidence(
        collection=collection,
        content=screenshot_bytes,
        filename='screenshot.png',
        evidence_type='Screenshot',
        title='Login page screenshot',
        collected_by=user,
        vulnerability_ids=[42],
    )
    url = EvidenceService.get_download_url(item)
    EvidenceService.archive_evidence(item, actor=user)
"""
import logging
from typing import List, Optional

from django.db import transaction
from django.utils import timezone

from evidence.hashing import compute_sha256, record_integrity_check
from evidence.models import (
    Evidence,
    EvidenceCollection,
    EvidenceEvent,
    EvidenceRetentionPolicy,
)
from evidence.storage import get_storage_backend
from evidence.validators import validate_evidence_upload, detect_mime_type

logger = logging.getLogger(__name__)


class EvidenceService:
    """Facade for all evidence CRUD and lifecycle operations."""

    # ------------------------------------------------------------------ #
    # Collections
    # ------------------------------------------------------------------ #

    @staticmethod
    @transaction.atomic
    def get_or_create_collection(
        assessment,
        scan_history=None,
        name: Optional[str] = None,
    ) -> EvidenceCollection:
        """Get an existing Active collection or create a new one for an assessment.

        Args:
            assessment: Assessment model instance.
            scan_history: Optional ScanHistory model instance.
            name (str, optional): Custom name. Defaults to
                'Assessment <name> — <ISO date>'.

        Returns:
            EvidenceCollection: Existing or newly created collection.
        """
        existing = EvidenceCollection.objects.filter(
            assessment=assessment,
            status='Active',
        ).first()

        if existing:
            # Link scan_history if not yet set
            if scan_history and not existing.scan_history:
                existing.scan_history = scan_history
                existing.save(update_fields=['scan_history', 'updated_at'])
            return existing

        if not name:
            date_str = timezone.now().strftime('%Y-%m-%d')
            name = f"{assessment.name} — {date_str}"

        collection = EvidenceCollection.objects.create(
            assessment=assessment,
            scan_history=scan_history,
            name=name,
            status='Active',
        )

        # Create default retention policy inheriting from Assessment.retention_days
        retention_days = getattr(assessment, 'retention_days', 365)
        EvidenceRetentionPolicy.objects.create(
            collection=collection,
            archive_after_days=retention_days,
            purge_after_days=0,
            purge_files=False,
            next_action_at=timezone.now() + timezone.timedelta(days=retention_days) if retention_days > 0 else None,
        )

        logger.info(f"[EVIDENCE] Created collection '{name}' for assessment {assessment.uuid}")
        return collection

    # ------------------------------------------------------------------ #
    # Evidence creation
    # ------------------------------------------------------------------ #

    @staticmethod
    @transaction.atomic
    def create_evidence(
        collection: EvidenceCollection,
        content: bytes,
        filename: str,
        evidence_type: str,
        title: str,
        description: str = '',
        subfolder: str = '',
        collected_by=None,
        vulnerability_ids: Optional[List[int]] = None,
        scope_ids: Optional[List[int]] = None,
        skip_validation: bool = False,
    ) -> Evidence:
        """Create, hash, validate, and persist a new evidence item.

        Steps:
          1. Validate content (size, extension, MIME).
          2. Compute SHA-256 hash.
          3. Detect MIME type.
          4. Store file via storage backend.
          5. Create Evidence record.
          6. Write 'Created' chain-of-custody event.
          7. Link to Vulnerabilities and Scopes if provided.

        Args:
            collection (EvidenceCollection): Parent collection.
            content (bytes): Raw file bytes.
            filename (str): Original filename.
            evidence_type (str): One of the EVIDENCE_TYPE_CHOICES keys.
            title (str): Short description for the evidence item.
            description (str, optional): Analyst notes.
            subfolder (str, optional): Storage subfolder/prefix.
            collected_by: Optional User who collected this evidence.
            vulnerability_ids (list[int], optional): Vulnerability PKs to link.
            scope_ids (list[int], optional): AssessmentScope PKs to link.
            skip_validation (bool): Set True in automated pipelines to skip file validation.

        Returns:
            Evidence: The persisted Evidence instance.

        Raises:
            ValueError: If validation fails.
        """
        if not skip_validation:
            errors = validate_evidence_upload(content, filename, evidence_type)
            if errors:
                raise ValueError(f"Evidence validation failed: {'; '.join(errors)}")

        # Hash and detect MIME before storage (fail-fast if there's an issue)
        sha256 = compute_sha256(content)
        mime_type = detect_mime_type(filename, content)

        # Persist to storage backend
        storage = get_storage_backend()
        assessment_uuid = str(collection.assessment.uuid) if collection.assessment else None
        storage_key = storage.save(
            content, filename, subfolder or evidence_type.lower(),
            assessment_uuid=assessment_uuid,
        )

        # Create Evidence record
        evidence = Evidence.objects.create(
            collection=collection,
            evidence_type=evidence_type,
            title=title,
            description=description,
            file_path=storage_key,
            file_name=filename,
            file_size=len(content),
            mime_type=mime_type,
            sha256_hash=sha256,
            status='Active',
            collected_at=timezone.now(),
            collected_by=collected_by,
        )

        # Chain-of-custody event
        EvidenceEvent.objects.create(
            evidence=evidence,
            event_type='Created',
            actor=collected_by,
            hash_at_event=sha256,
            note=f"Evidence created via {evidence_type} collection",
            timestamp=timezone.now(),
        )

        # Link findings
        if vulnerability_ids:
            from startScan.models import Vulnerability
            vulns = Vulnerability.objects.filter(id__in=vulnerability_ids)
            evidence.vulnerabilities.set(vulns)

        # Link scope entries
        if scope_ids:
            from engagements.models import AssessmentScope
            scopes = AssessmentScope.objects.filter(id__in=scope_ids)
            evidence.scopes.set(scopes)

        logger.info(f"[EVIDENCE] Created evidence item {evidence.uuid} ({evidence_type}) in collection {collection.uuid}")
        return evidence

    # ------------------------------------------------------------------ #
    # Retrieval
    # ------------------------------------------------------------------ #

    @staticmethod
    def get_download_url(evidence: Evidence, expiry_seconds: Optional[int] = None) -> str:
        """Return a signed/serve URL for downloading an evidence file.

        Also records a 'Downloaded' chain-of-custody event.

        Args:
            evidence (Evidence): The evidence item to access.
            expiry_seconds (int, optional): URL lifetime for signed URLs.

        Returns:
            str: Download URL.
        """
        if not evidence.file_path:
            raise ValueError(f"Evidence {evidence.uuid} has no file_path set.")

        storage = get_storage_backend()
        url = storage.get_signed_url(evidence.file_path, expiry_seconds)

        EvidenceEvent.objects.create(
            evidence=evidence,
            event_type='Downloaded',
            note='Signed/serve URL generated',
            timestamp=timezone.now(),
        )
        return url

    @staticmethod
    def get_content(evidence: Evidence) -> bytes:
        """Read and return the raw bytes for an evidence file.

        Args:
            evidence (Evidence): The evidence item to read.

        Returns:
            bytes: Raw file content.
        """
        storage = get_storage_backend()
        return storage.read(evidence.file_path)

    # ------------------------------------------------------------------ #
    # Integrity
    # ------------------------------------------------------------------ #

    @staticmethod
    def verify_integrity(evidence: Evidence, actor=None) -> bool:
        """Verify SHA-256 hash and write a Verified event.

        Args:
            evidence (Evidence): The evidence item to check.
            actor: Optional User triggering the check.

        Returns:
            bool: True = hash matches, False = tampered or file missing.
        """
        return record_integrity_check(evidence, user=actor)

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    @staticmethod
    @transaction.atomic
    def archive_evidence(evidence: Evidence, actor=None, note: str = '') -> Evidence:
        """Move an evidence item to Archived status.

        Args:
            evidence (Evidence): The evidence item to archive.
            actor: Optional User triggering the archive.
            note (str, optional): Reason / context for archiving.

        Returns:
            Evidence: Updated evidence instance.
        """
        evidence.status = 'Archived'
        evidence.updated_at = timezone.now()
        evidence.save(update_fields=['status', 'updated_at'])
        EvidenceEvent.objects.create(
            evidence=evidence,
            event_type='Archived',
            actor=actor,
            note=note or 'Evidence archived',
            timestamp=timezone.now(),
        )
        logger.info(f"[EVIDENCE] Archived evidence {evidence.uuid}")
        return evidence

    @staticmethod
    @transaction.atomic
    def purge_evidence(evidence: Evidence, actor=None, delete_file: bool = False) -> None:
        """Purge evidence from the database (and optionally from storage).

        Always writes a Purged chain-of-custody event before deletion,
        so the audit trail survives even if the file is deleted.

        Args:
            evidence (Evidence): The evidence item to purge.
            actor: Optional User triggering the purge.
            delete_file (bool): If True, also delete the file from storage.
        """
        # Record purge event before anything else
        EvidenceEvent.objects.create(
            evidence=evidence,
            event_type='Purged',
            actor=actor,
            note=f"Purged. File deleted from storage: {delete_file}",
            timestamp=timezone.now(),
        )

        if delete_file and evidence.file_path:
            try:
                storage = get_storage_backend()
                storage.delete(evidence.file_path)
            except Exception as e:
                logger.warning(f"[EVIDENCE] Failed to delete file for {evidence.uuid}: {e}")

        evidence.status = 'Purged'
        evidence.file_path = None
        evidence.save(update_fields=['status', 'file_path', 'updated_at'])
        logger.info(f"[EVIDENCE] Purged evidence {evidence.uuid}")

    @staticmethod
    @transaction.atomic
    def archive_collection(collection: EvidenceCollection, actor=None) -> EvidenceCollection:
        """Archive all Active evidence items in a collection, then archive the collection.

        Args:
            collection (EvidenceCollection): The collection to archive.
            actor: Optional User triggering the archive.

        Returns:
            EvidenceCollection: Updated collection.
        """
        active_items = collection.evidence_items.filter(status='Active')
        for item in active_items:
            EvidenceService.archive_evidence(item, actor=actor, note='Collection archive')

        collection.status = 'Archived'
        collection.save(update_fields=['status', 'updated_at'])
        logger.info(f"[EVIDENCE] Archived collection {collection.uuid} ({active_items.count()} items)")
        return collection
