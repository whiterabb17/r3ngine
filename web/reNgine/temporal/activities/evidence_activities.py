"""Evidence Temporal activities.

These activities run on the python-orchestrator-queue and are called from
assessment child workflows (DiscoveryWorkflow, AnalysisWorkflow, etc.) to
collect and manage evidence.

Activities:
  - CollectScreenshotEvidenceActivity: Captures a screenshot and stores it.
  - CollectHTTPEvidenceActivity: Captures an HTTP request/response pair.
  - CollectCommandOutputEvidenceActivity: Stores tool command output.
  - EnforceEvidenceRetentionActivity: Runs retention lifecycle checks.
  - VerifyEvidenceIntegrityActivity: Batch integrity verification.
"""
from dataclasses import dataclass, field
from typing import Optional, List

from temporalio import activity
from asgiref.sync import sync_to_async

from reNgine.utils.logger import get_module_logger

logger = get_module_logger(__name__)


# ---------------------------------------------------------------------------
# Input dataclasses
# ---------------------------------------------------------------------------

@dataclass
class ScreenshotEvidenceInput:
    """Input for CollectScreenshotEvidenceActivity.

    Args:
        assessment_id (str): UUID of the parent Assessment.
        target_url (str): URL of the page to screenshot.
        title (str): Short description for the evidence item.
        vulnerability_ids (list[int]): Optional list of Vulnerability PKs to link.
        scope_ids (list[int]): Optional list of AssessmentScope PKs to link.
    """
    assessment_id:    str
    target_url:       str
    title:            str
    vulnerability_ids: List[int] = field(default_factory=list)
    scope_ids:         List[int] = field(default_factory=list)


@dataclass
class HTTPCaptureEvidenceInput:
    """Input for CollectHTTPEvidenceActivity.

    Args:
        assessment_id (str): UUID of the parent Assessment.
        url (str): The request URL.
        method (str): HTTP method (GET, POST, etc.).
        request_headers (dict): Request header dict.
        request_body (str): Request body as string.
        response_status (int): HTTP response status code.
        response_headers (dict): Response header dict.
        response_body (str): Response body as string (may be truncated for large responses).
        title (str): Short description for the evidence item.
        vulnerability_ids (list[int]): Optional linked Vulnerability PKs.
        scope_ids (list[int]): Optional linked AssessmentScope PKs.
    """
    assessment_id:    str
    url:              str
    method:           str
    request_headers:  dict
    request_body:     str
    response_status:  int
    response_headers: dict
    response_body:    str
    title:            str
    vulnerability_ids: List[int] = field(default_factory=list)
    scope_ids:         List[int] = field(default_factory=list)


@dataclass
class CommandOutputEvidenceInput:
    """Input for CollectCommandOutputEvidenceActivity.

    Args:
        assessment_id (str): UUID of the parent Assessment.
        command (str): The full command that was executed.
        output (str): Stdout/stderr output.
        title (str): Short description.
        evidence_type (str): Type classification (CommandOutput, Log, etc.).
        vulnerability_ids (list[int]): Optional linked findings.
        scope_ids (list[int]): Optional linked scope entries.
    """
    assessment_id:    str
    command:          str
    output:           str
    title:            str
    evidence_type:    str = 'CommandOutput'
    vulnerability_ids: List[int] = field(default_factory=list)
    scope_ids:         List[int] = field(default_factory=list)


@dataclass
class RetentionEnforcementInput:
    """Input for EnforceEvidenceRetentionActivity.

    Args:
        dry_run (bool): If True, report what would be done without making changes.
        max_collections (int): Max number of collections to process per run.
    """
    dry_run:         bool = False
    max_collections: int  = 50


@dataclass
class IntegrityVerificationInput:
    """Input for VerifyEvidenceIntegrityActivity.

    Args:
        collection_uuid (str): UUID of the EvidenceCollection to verify.
            If empty, all Active collections are checked.
        max_items (int): Max number of evidence items to verify per run.
    """
    collection_uuid: str = ''
    max_items:       int = 200


# ---------------------------------------------------------------------------
# Activities
# ---------------------------------------------------------------------------

@activity.defn(name="CollectScreenshotEvidenceActivity")
async def collect_screenshot_evidence_activity(input: ScreenshotEvidenceInput) -> str:
    """Capture a screenshot using gowitness/httpx and store it as evidence.

    Looks up the assessment, creates or retrieves the active EvidenceCollection,
    runs the screenshot tool, and calls EvidenceService.create_evidence().

    Args:
        input (ScreenshotEvidenceInput): Target URL, assessment, and linking info.

    Returns:
        str: UUID of the created Evidence item (or empty string on failure).
    """
    @sync_to_async
    def _capture() -> str:
        import subprocess
        import os
        import tempfile

        from engagements.models import Assessment
        from evidence.services import EvidenceService

        try:
            assessment = Assessment.objects.get(uuid=input.assessment_id)
        except Assessment.DoesNotExist:
            logger.log_line("[EVIDENCE]", "ERROR", f"Assessment {input.assessment_id} not found")
            return ''

        collection = EvidenceService.get_or_create_collection(assessment)

        # Try gowitness screenshot
        screenshot_bytes = None
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, 'screenshot.png')
            try:
                result = subprocess.run(
                    ['gowitness', 'single', '--url', input.target_url,
                     '--screenshot-path', out_file],
                    timeout=60,
                    capture_output=True,
                )
                if os.path.isfile(out_file):
                    with open(out_file, 'rb') as f:
                        screenshot_bytes = f.read()
            except (subprocess.TimeoutExpired, FileNotFoundError):
                logger.log_line("[EVIDENCE]", "WARN", f"gowitness not available for {input.target_url}")

        if not screenshot_bytes:
            logger.log_line("[EVIDENCE]", "WARN", f"No screenshot captured for {input.target_url}")
            return ''

        evidence = EvidenceService.create_evidence(
            collection=collection,
            content=screenshot_bytes,
            filename=f"screenshot_{input.target_url.replace('/', '_')[:50]}.png",
            evidence_type='Screenshot',
            title=input.title or f"Screenshot: {input.target_url}",
            subfolder='screenshots',
            vulnerability_ids=input.vulnerability_ids,
            scope_ids=input.scope_ids,
            skip_validation=True,  # Automated pipeline — skip size validation
        )
        return str(evidence.uuid)

    return await _capture()


@activity.defn(name="CollectHTTPEvidenceActivity")
async def collect_http_evidence_activity(input: HTTPCaptureEvidenceInput) -> str:
    """Store an HTTP request/response pair as structured evidence.

    Formats the pair as a text file with proper HTTP framing and stores it.

    Args:
        input (HTTPCaptureEvidenceInput): Full HTTP context including headers and bodies.

    Returns:
        str: UUID of the created Evidence item, or empty string on failure.
    """
    @sync_to_async
    def _store() -> str:
        from engagements.models import Assessment
        from evidence.services import EvidenceService

        try:
            assessment = Assessment.objects.get(uuid=input.assessment_id)
        except Assessment.DoesNotExist:
            return ''

        collection = EvidenceService.get_or_create_collection(assessment)

        # Format as HTTP capture text
        req_headers = '\r\n'.join(f"{k}: {v}" for k, v in input.request_headers.items())
        resp_headers = '\r\n'.join(f"{k}: {v}" for k, v in input.response_headers.items())

        capture_text = (
            f"=== REQUEST ===\n"
            f"{input.method} {input.url}\n"
            f"{req_headers}\n\n"
            f"{input.request_body}\n\n"
            f"=== RESPONSE ===\n"
            f"HTTP/1.1 {input.response_status}\n"
            f"{resp_headers}\n\n"
            f"{input.response_body}\n"
        )
        content = capture_text.encode('utf-8', errors='replace')
        safe_name = input.url.split('//')[-1].replace('/', '_').replace('?', '_')[:50]

        evidence = EvidenceService.create_evidence(
            collection=collection,
            content=content,
            filename=f"http_capture_{safe_name}.txt",
            evidence_type='RequestResponse',
            title=input.title or f"HTTP {input.method} {input.url} [{input.response_status}]",
            subfolder='http_captures',
            vulnerability_ids=input.vulnerability_ids,
            scope_ids=input.scope_ids,
            skip_validation=True,
        )
        return str(evidence.uuid)

    return await _store()


@activity.defn(name="CollectCommandOutputEvidenceActivity")
async def collect_command_output_evidence_activity(input: CommandOutputEvidenceInput) -> str:
    """Store tool command output (e.g. nmap, nuclei) as evidence.

    Args:
        input (CommandOutputEvidenceInput): Command, output, and linking info.

    Returns:
        str: UUID of the created Evidence item, or empty string on failure.
    """
    @sync_to_async
    def _store() -> str:
        from engagements.models import Assessment
        from evidence.services import EvidenceService

        try:
            assessment = Assessment.objects.get(uuid=input.assessment_id)
        except Assessment.DoesNotExist:
            return ''

        collection = EvidenceService.get_or_create_collection(assessment)
        content = f"$ {input.command}\n\n{input.output}".encode('utf-8', errors='replace')
        safe_cmd = input.command.split()[0].replace('/', '_')[:30]

        evidence = EvidenceService.create_evidence(
            collection=collection,
            content=content,
            filename=f"output_{safe_cmd}.txt",
            evidence_type=input.evidence_type,
            title=input.title or f"Command output: {input.command[:80]}",
            subfolder='command_outputs',
            vulnerability_ids=input.vulnerability_ids,
            scope_ids=input.scope_ids,
            skip_validation=True,
        )
        return str(evidence.uuid)

    return await _store()


@activity.defn(name="EnforceEvidenceRetentionActivity")
async def enforce_evidence_retention_activity(input: RetentionEnforcementInput) -> dict:
    """Enforce retention policies on EvidenceCollection records.

    Checks all EvidenceRetentionPolicy records where next_action_at <= now,
    and archives or purges the associated collections accordingly.

    Args:
        input (RetentionEnforcementInput): dry_run flag and max_collections limit.

    Returns:
        dict: Summary with keys 'archived', 'purged', 'errors'.
    """
    @sync_to_async
    def _enforce() -> dict:
        from django.utils import timezone
        from evidence.models import EvidenceRetentionPolicy, EvidenceCollection
        from evidence.services import EvidenceService

        now = timezone.now()
        policies = EvidenceRetentionPolicy.objects.filter(
            next_action_at__lte=now,
            collection__status='Active',
        ).select_related('collection')[:input.max_collections]

        archived = 0
        purged = 0
        errors = []

        for policy in policies:
            collection = policy.collection
            try:
                if input.dry_run:
                    logger.log_line("[EVIDENCE]", "RETAIN", f"DRY RUN: Would archive collection {collection.uuid}")
                    archived += 1
                    continue

                EvidenceService.archive_collection(collection)
                policy.last_enforced_at = now

                if policy.purge_after_days > 0:
                    policy.next_action_at = now + timezone.timedelta(days=policy.purge_after_days)
                    purged += 1
                else:
                    policy.next_action_at = None

                policy.save(update_fields=['last_enforced_at', 'next_action_at'])
                archived += 1
            except Exception as e:
                errors.append(f"Collection {collection.uuid}: {e}")
                logger.log_line("[EVIDENCE]", "ERROR", f"Retention enforcement failed for {collection.uuid}: {e}", level="error")

        return {'archived': archived, 'purged': purged, 'errors': errors}

    return await _enforce()


@activity.defn(name="VerifyEvidenceIntegrityActivity")
async def verify_evidence_integrity_activity(input: IntegrityVerificationInput) -> dict:
    """Batch-verify SHA-256 hashes for Active evidence items.

    Reads each evidence file from storage, recomputes its hash, and writes
    a Verified or integrity-failure EvidenceEvent for each item.

    Args:
        input (IntegrityVerificationInput): Optional collection UUID and max items.

    Returns:
        dict: Summary with keys 'passed', 'failed', 'skipped'.
    """
    @sync_to_async
    def _verify() -> dict:
        from evidence.models import Evidence, EvidenceCollection
        from evidence.services import EvidenceService

        qs = Evidence.objects.filter(status='Active', sha256_hash__isnull=False)
        if input.collection_uuid:
            try:
                coll = EvidenceCollection.objects.get(uuid=input.collection_uuid)
                qs = qs.filter(collection=coll)
            except EvidenceCollection.DoesNotExist:
                return {'passed': 0, 'failed': 0, 'skipped': 0, 'error': f"Collection {input.collection_uuid} not found"}

        qs = qs[:input.max_items]
        passed = failed = skipped = 0

        for item in qs:
            if not item.file_path:
                skipped += 1
                continue
            try:
                ok = EvidenceService.verify_integrity(item)
                if ok:
                    passed += 1
                else:
                    failed += 1
                    logger.log_line("[EVIDENCE]", "WARN", f"Integrity failure for evidence {item.uuid}")
            except Exception as e:
                skipped += 1
                logger.log_line("[EVIDENCE]", "ERROR", f"Error verifying {item.uuid}: {e}")

        return {'passed': passed, 'failed': failed, 'skipped': skipped}

    return await _verify()
