# Phase 5 + Phase 6 — Neo4j Assessment Intelligence & Exposure Correlation Engine

**Branch:** `v4`
**Author:** design brainstorm 2026-07-05
**Status:** Draft — awaiting user review before writing-plans handoff
**Depends on:** Phases 1 (Assessment models), 2 (AssessmentWorkflow), 3 (Evidence), 4 (Finding lifecycle) — all merged
**Reference:** `documents/future/v4/assessment_operations.md` §Phase 5, §Phase 6

---

## 0. Executive summary

Extend two existing scan-scoped systems in place to also work at the assessment tier, **without breaking standalone scans**:

- **Phase 5** adds four Neo4j node labels (`:Assessment`, `:Finding`, `:Evidence`, `:AuthenticationSystem`) and three edges (`CONTAINS`, `SUPPORTED_BY`, `USES`) to the APME graph, plus a nullable `assessment_id` property on `APMENode`. Sync runs from a new Temporal activity called by `AssessmentWorkflow` after the Validation stage.
- **Phase 6** introduces two Postgres models (`Asset`, `AssetSource`) that represent the canonical, deduplicated attack-surface asset within an assessment. A new `AssetCorrelationService` fans out to the existing `ExposureCorrelationEngine` per scan, then rolls up sources into canonical `Asset` records. A new Temporal activity wires this into the AssessmentWorkflow between Analysis and Validation.

All new columns, properties, labels, and paths are additive/optional. Scans without an assessment behave exactly as they do on `v4` today.

**Storage rule:** every assessment-scoped artifact (evidence files, canonical asset exports, report bundles produced by the AssessmentWorkflow) is persisted under `/usr/src/assessments/`. **Nothing under `/usr/src/app/`**. Scan-only artifacts under `/usr/src/scan_results/` are unchanged.

---

## 1. Current state (verified 2026-07-05)

| Layer | File / location | State |
|-------|-----------------|-------|
| Assessment models | `web/engagements/models.py` — Client, Engagement, Assessment, AssessmentScope, AssessmentAsset, AssessmentWorkflowState, AssessmentEvent | ✅ Phase 1 shipped |
| Assessment workflow | `web/reNgine/temporal/workflows/assessment_workflow.py` | ✅ Phase 2 shipped |
| Evidence models | `web/evidence/models.py` — Evidence, EvidenceCollection, EvidenceEvent, EvidenceAnnotation, EvidenceRetentionPolicy | ✅ Phase 3 shipped |
| Finding lifecycle | `startScan.Vulnerability.validation_status` with states `new/verified/needs_review/false_positive/accepted_risk/resolved` | ✅ Phase 4 shipped (commit `b4c90f0`) |
| ScanHistory ↔ Assessment | `startScan.ScanHistory.assessment` FK — nullable, on_delete=SET_NULL, related_name='scan_histories' | ✅ present at line 42 |
| APME graph | `web/apme/graph/schema.py` — 13 node types, 14 edge types; `web/apme/graph/builder.py` — GraphBuilder with idempotent MERGEs, scoped by `scan_id` | ✅ scan-scoped |
| Legacy Neo4j sync | `web/reNgine/utils/graph.py` — `Neo4jManager.sync_scan_results` / `sync_all_scans` (separate from APME) | ✅ scan-scoped; evidence sync path already sketched in for assessment-linked scans (bug fixed 2026-07-05, see §7) |
| Exposure correlation | `web/reNgine/exposure_correlation.py` — `ExposureCorrelationEngine`; `startScan.Exposure`, `startScan.ExposureEvidence` | ✅ scan-scoped, subdomain-centric |
| Evidence storage | `web/evidence/storage.py` — filesystem backend rooted at `/usr/src/app/evidence/` (violates storage rule) | ⚠️ to relocate |

---

## 2. Architecture — extend in place, dual-scope

```
        Standalone scan (unchanged, no assessment)              Assessment-driven work
        ────────────────────────────────────                    ─────────────────────────
        MasterScanWorkflow                                      AssessmentWorkflow
             │                                                       │
             ▼                                                       ▼
        Tier 1 … Tier 7                                          Discovery → Enumeration → Analysis
             │                                                       │
             ▼                                            ┌──────────┴───────────┐
        ExposureCorrelationEngine                         ▼                      ▼
        (Postgres: Exposure, ExposureEvidence)     RunAssetCorrelation-    SyncAssessmentGraph-
             │                                    Activity                 Activity  (after Validation)
             ▼                                          │                         │
        APME GraphBuilder                               ▼                         ▼
        (Neo4j: APMENode with scan_id,             AssetCorrelationService   Neo4j:
         assessment_id=null)                       (delegates per-scan to    :Assessment, :Finding,
                                                    ExposureCorrelation-      :Evidence,
                                                    Engine, then merges into  :AuthenticationSystem
                                                    canonical Postgres        + edges CONTAINS,
                                                    Asset/AssetSource)        SUPPORTED_BY, USES
                                                          │
                                                          ▼
                                                    Postgres: Asset,
                                                    AssetSource
```

**Invariants:**
- Existing scan sync path is untouched. New sync path is additive.
- `APMENode.assessment_id` is nullable. Scans without an assessment continue to write nodes with `assessment_id = null`.
- `Asset` / `AssetSource` are never created by standalone scans. `Exposure` / `ExposureEvidence` continue exclusively.
- Feature flags gate both new activities off in initial merge.

---

## 3. Phase 5 — Neo4j Assessment Intelligence Layer

### 3.1 Schema additions (`web/apme/graph/schema.py`)

Add to `NODE_TYPES`:

```python
NODE_TYPES = {
    ...  # existing entries kept unchanged
    "Assessment": ["generic"],
    "Finding": ["generic"],
    "Evidence": ["screenshot", "network_capture", "request_response",
                 "command_output", "log", "report", "other"],
    "AuthenticationSystem": ["oauth", "saml", "oidc", "ldap", "basic",
                             "form_login", "mtls", "api_key", "generic"],
}
```

Add to `EDGE_TYPES`:

```python
EDGE_TYPES = [
    ...  # existing entries kept unchanged
    "CONTAINS",       # Assessment -> Finding
    "SUPPORTED_BY",   # Finding -> Evidence
    "USES",           # Application -> AuthenticationSystem
    "HAS_ASSET",      # Assessment -> Asset (Phase 6 canonical asset node)
    "DISCOVERED_IN",  # Finding -> ScanHistory (audit trail)
]
```

Backward compat: existing `AUTHENTICATES_VIA` (Application → IdentityInfra) stays. `USES` is the new, narrower Application → AuthenticationSystem edge for identity-provider intelligence. Both coexist; `AUTHENTICATES_VIA` remains authoritative for legacy consumers.

### 3.2 APMENode property additions

Add nullable properties (Neo4j is schemaless — no migration needed, just documented):

| Property | On labels | Meaning |
|----------|-----------|---------|
| `assessment_id` | any APMENode | UUID of the parent Assessment when the node was produced under an AssessmentWorkflow. Null for standalone-scan nodes. Indexed. |
| `finding_id` | `:Finding` only | Postgres PK of `startScan.Vulnerability`. Indexed. |
| `evidence_uuid` | `:Evidence` only | UUID of `evidence.Evidence`. Indexed. |
| `auth_system_type` | `:AuthenticationSystem` only | One of the subtypes above. |

Indexes to create in `_ensure_graph_indexes`:

```cypher
CREATE INDEX apme_assessment_id IF NOT EXISTS FOR (n:APMENode) ON (n.assessment_id)
CREATE INDEX apme_finding_id    IF NOT EXISTS FOR (n:Finding)   ON (n.finding_id)
CREATE INDEX apme_evidence_uuid IF NOT EXISTS FOR (n:Evidence)  ON (n.evidence_uuid)
```

### 3.3 GraphBuilder additions (`web/apme/graph/builder.py`)

New methods on the existing `GraphBuilder` class:

```python
def merge_assessment_node(self, assessment) -> None:
    """MERGE (:Assessment {uuid, name, engagement_uuid, assessment_type, status})."""

def merge_finding_node(self, vulnerability, assessment=None) -> None:
    """MERGE (:Finding {finding_id, uuid, name, severity, validation_status}).
    When assessment is provided, also MERGE (a:Assessment)-[:CONTAINS]->(f:Finding).
    When vulnerability.scan_history is set, MERGE (f)-[:DISCOVERED_IN]->(sc:Scan)."""

def merge_evidence_node(self, evidence, finding_ids) -> None:
    """MERGE (:Evidence {evidence_uuid, evidence_type, sha256_hash, storage_path}).
    For each finding_id, MERGE (f:Finding)-[:SUPPORTED_BY]->(e:Evidence)."""

def merge_authentication_system(self, host, auth_type, metadata) -> str:
    """MERGE (:AuthenticationSystem {host, auth_system_type}) and return its apme_id."""

def link_application_to_auth(self, application_apme_id, auth_system_apme_id) -> None:
    """MERGE (app:Application)-[:USES]->(auth:AuthenticationSystem)."""

def attach_assessment_id(self, scan_id, assessment_uuid) -> int:
    """Bulk backfill assessment_id on all APMENodes previously written under scan_id.
    Called when a scan is retroactively attached to an assessment. Returns count."""
```

All methods use MERGE — idempotent. All write via the existing `_driver.session()` pattern with per-batch UNWINDs for `merge_finding_node` and `merge_evidence_node` (called with lists).

### 3.4 New Temporal activity: `SyncAssessmentGraphActivity`

Location: `web/reNgine/temporal/activities/__init__.py`. Registered on `python-orchestrator-queue` in `scanEngine/management/commands/run_temporal_orchestrator.py`.

```python
@activity.defn
async def sync_assessment_graph_activity(assessment_id: str) -> dict:
    """Sync an assessment's Findings + Evidence + AuthenticationSystems into Neo4j.

    Idempotent. Runs after the AssessmentWorkflow's Validation stage.
    Only syncs findings with validation_status IN ('verified', 'needs_review', 'accepted_risk')
    — 'new', 'false_positive', 'resolved' are intentionally excluded from graph exposure.
    """
```

**Sequence:**
1. Load Assessment (`engagements.Assessment.objects.get(uuid=assessment_id)`).
2. `builder.merge_assessment_node(assessment)`.
3. For each Vulnerability with `assessment=assessment` and validation_status in the allowlist above:
   - `builder.merge_finding_node(vuln, assessment=assessment)`.
4. For each Evidence in `EvidenceCollection.objects.filter(assessment=assessment)`:
   - Resolve linked vulnerability_ids via M2M.
   - `builder.merge_evidence_node(evidence, finding_ids)`.
5. For each unique (Application, host_auth_signals) pair inferred from scan data:
   - `builder.merge_authentication_system(...)`, then `builder.link_application_to_auth(...)`.
6. Emit `AssessmentEvent(event_type='graph_synced', event_data={'nodes_written': ..., 'edges_written': ..., 'skipped_findings': ...})`.
7. Return `{'nodes': int, 'edges': int, 'finding_count': int, 'evidence_count': int}`.

**Logging (per `r3ngine-temporal.md` Pattern 2):**

```python
logger = get_module_logger(__name__)
logger.log_line("[GRAPH]", "START", "sync assessment %s" % assessment_id)
logger.log_line("[GRAPH]", "COMPLETE", "assessment %s: %d nodes, %d edges" % (assessment_id, n, e))
logger.log_line("[GRAPH]", "ERROR", format_exception_for_log(exc), level="error", exc_info=True)
```

**Retry policy:** default `RetryPolicy(initial_interval=5, backoff_coefficient=2, maximum_interval=300, maximum_attempts=5)` per r3ngine-temporal.md deliverable 12.

### 3.5 AssessmentWorkflow integration

`assessment_workflow.py` gains one new stage between `VALIDATION` and `REPORTING`:

```
Discovery → Enumeration → Analysis → Correlation → Validation → GraphSync → Reporting
                                     (Phase 6)                  (Phase 5)
```

Two changes to `AssessmentStatus` and the workflow state machine:
- Add `CORRELATION` and `GRAPH_SYNC` intermediate states (both transient — not surfaced to end-users unless expanded UI wants them).
- Wire `RunAssetCorrelationActivity` (see §4.4) and `SyncAssessmentGraphActivity` at their respective points.

Both stages are gated by feature flags — see §5.

### 3.6 Backfill helper

`attach_assessment_id(scan_id, assessment_uuid)` is exposed as a management command:

```
python manage.py apme_attach_assessment --scan-id N --assessment-uuid UUID
```

Used when a scan launched before Phase 5 (or launched standalone) is retroactively attached to a new assessment. Runs a single Cypher UPDATE:

```cypher
MATCH (n:APMENode {scan_id: $scan_id})
SET n.assessment_id = $assessment_uuid
RETURN count(n) AS updated
```

---

## 4. Phase 6 — Exposure Correlation Engine (Canonical Assets)

### 4.1 New Django app or models location

Add models to `web/engagements/models.py` (co-locates with Assessment; no new app). Rationale: Asset and AssetSource are assessment-scoped by definition, so they belong to the same domain as Assessment.

### 4.2 Postgres models

```python
class Asset(models.Model):
    """Canonical assessment-scoped attack-surface asset.

    Deduplicates observations from httpx, nuclei, katana, screenshots, ffuf,
    exposure_correlation.Exposure, etc. into a single canonical entity per
    (assessment, normalized_identifier).
    """

    ASSET_TYPES = (
        # Aligns with ExposureCorrelationEngine._ASSET_TYPE_WEIGHTS categories:
        ('VPN Gateway', 'VPN Gateway'),
        ('Remote Access Protocol', 'Remote Access Protocol'),
        ('Identity & SSO', 'Identity & SSO'),
        ('Database', 'Database'),
        ('Admin Portal', 'Admin Portal'),
        ('CI/CD & Automation', 'CI/CD & Automation'),
        ('Container / Orchestration', 'Container / Orchestration'),
        ('Source Code Repository', 'Source Code Repository'),
        ('Cloud Storage', 'Cloud Storage'),
        ('Email Server', 'Email Server'),
        ('File Sharing', 'File Sharing'),
        ('Message Queue', 'Message Queue'),
        ('API Endpoint', 'API Endpoint'),
        ('Staging / Dev', 'Staging / Dev'),
        ('WAF / Edge', 'WAF / Edge'),
        ('VoIP / Communication', 'VoIP / Communication'),
        ('Web Application', 'Web Application'),
        ('Application', 'Application'),
        ('Unclassified Asset', 'Unclassified Asset'),
    )

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    assessment = models.ForeignKey(
        Assessment,
        on_delete=models.CASCADE,
        related_name='canonical_assets',
    )
    asset_type = models.CharField(max_length=64, choices=ASSET_TYPES,
                                  default='Unclassified Asset')

    # Normalized identifier used for dedup — see §4.5 for normalization rules.
    canonical_identifier = models.CharField(max_length=1024, db_index=True)

    # SHA-256 of (assessment.uuid || normalized_identifier) — guarantees no
    # cross-assessment collision. Enforced unique per assessment.
    canonical_key_hash = models.CharField(max_length=64, db_index=True)

    first_seen_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(auto_now=True)

    # Recomputed by AssetCorrelationService.correlate() on every run.
    risk_score = models.FloatField(default=0.0)

    # Freeform tool-agnostic metadata (page titles, tech list, ports, etc.).
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        unique_together = ('assessment', 'canonical_key_hash')
        indexes = [
            models.Index(fields=['assessment', 'asset_type']),
            models.Index(fields=['assessment', '-risk_score']),
        ]

    def __str__(self):
        return f"{self.asset_type} :: {self.canonical_identifier}"


class AssetSource(models.Model):
    """A single tool observation that contributed to a canonical Asset."""

    SOURCE_TOOLS = (
        ('httpx', 'httpx'),
        ('nuclei', 'nuclei'),
        ('katana', 'katana'),
        ('screenshot', 'screenshot'),
        ('ffuf', 'ffuf'),
        ('port_scan', 'port_scan'),
        ('exposure_engine', 'exposure_engine'),
        ('subdomain_enum', 'subdomain_enum'),
        ('other', 'other'),
    )

    asset = models.ForeignKey(Asset, on_delete=models.CASCADE,
                              related_name='sources')
    source_tool = models.CharField(max_length=32, choices=SOURCE_TOOLS)
    source_scan_history = models.ForeignKey(
        'startScan.ScanHistory', on_delete=models.SET_NULL, null=True,
        related_name='asset_sources',
    )

    # Generic FK back to the originating record (Subdomain, EndPoint,
    # Screenshot, Vulnerability, Exposure, etc.)
    source_content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    source_object_id = models.PositiveIntegerField()
    source_object = GenericForeignKey('source_content_type', 'source_object_id')

    observed_at = models.DateTimeField()
    payload = models.JSONField(default=dict, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=['asset', 'source_tool']),
            models.Index(fields=['source_scan_history']),
        ]
        unique_together = ('asset', 'source_content_type', 'source_object_id')
```

**What we do NOT touch:**
- `startScan.Exposure` and `startScan.ExposureEvidence` remain as-is. `ExposureCorrelationEngine` continues to write them. `Asset` is an assessment-level rollup that references them via `AssetSource`.

### 4.3 AssetCorrelationService (`web/reNgine/asset_correlation.py`)

```python
class AssetCorrelationService:
    """Assessment-scoped canonical asset correlator.

    Per assessment run:
      1. Ensure ExposureCorrelationEngine has produced Exposure records for
         every scan_history linked to the assessment (idempotent — skip if
         already run).
      2. Fan out to per-scan sources (Subdomain, EndPoint, Screenshot,
         Vulnerability, Exposure).
      3. Compute canonical_identifier + canonical_key_hash for each source.
      4. update_or_create Asset; upsert AssetSource with the raw payload.
      5. Recompute Asset.risk_score across ALL sources for the canonical
         asset using the same weights ExposureCorrelationEngine uses:
             50% max vulnerability severity
             35% asset-type base weight
             15% high-risk port presence
    """

    def __init__(self, assessment: Assessment): ...

    def correlate(self) -> AssetCorrelationResult:
        """Run one full correlation pass. Returns counts for the workflow."""
```

Return dataclass:

```python
@dataclass
class AssetCorrelationResult:
    new_assets: int
    updated_assets: int
    new_sources: int
    scans_processed: int
```

### 4.4 New Temporal activity: `RunAssetCorrelationActivity`

```python
@activity.defn
async def run_asset_correlation_activity(assessment_id: str) -> dict:
    """Roll up per-scan Exposure records into canonical assessment-scoped Assets."""
```

Runs the `AssetCorrelationService`. Same retry policy, same logging pattern. Emits `AssessmentEvent(event_type='assets_correlated', event_data={...counts...})`.

### 4.5 Canonical identifier normalization

The single most important correctness rule in Phase 6. All rules produce a string; `canonical_key_hash = sha256(assessment.uuid.hex || ':' || normalized_identifier)`.

| Source signal | Normalization |
|---------------|---------------|
| HTTP URL (from httpx, katana, screenshot) | Parse with `urllib.parse.urlparse`. Lowercase host. Strip default ports (80 for http, 443 for https). Collapse path to `/` (application-root). Drop query string, fragment, credentials. Result: `scheme://host[:non-default-port]/`. |
| Subdomain hostname only | Lowercase. Strip trailing dot. Result: `host://hostname`. |
| Host+port service (SSH/RDP/SMB) | `service://host:port` where `service` is derived from port (22→ssh, 3389→rdp, etc.). |
| IP+port only | `ip://ip:port`. |
| Certificate | `cert://sha256:hex-fingerprint`. |
| API endpoint (from APIIntelligenceProfile) | Same URL rule as HTTP URL. |

Two different tools that observed the same URL produce the same `canonical_key_hash` → same `Asset` row → two `AssetSource` rows.

### 4.6 Risk-score compatibility

`AssetCorrelationService._score(asset)` uses the same weights and constants as `ExposureCorrelationEngine._calculate_risk_score` — the code will import from `exposure_correlation` (`_ASSET_TYPE_WEIGHTS`, `_SEVERITY_TO_SCORE`, `_HIGH_RISK_PORTS`) rather than duplicating them, satisfying r3ngine-security.md Rule 7.1 (no duplicated logic).

The false-positive damper stays scan-scoped (Exposure lookup by subdomain+target_domain). AssetCorrelationService applies the damper transitively when any linked source's Exposure was marked `false_positive`.

---

## 5. Storage layout — `/usr/src/assessments`

**Rule:** all assessment-scoped artifacts persist outside `/usr/src/app/`. New root: `/usr/src/assessments/`.

### 5.1 Path layout

```
/usr/src/assessments/
├── <assessment_uuid>/
│   ├── evidence/
│   │   └── <YYYY>/<MM>/<DD>/<sha256-hex>.<ext>
│   ├── exports/
│   │   ├── canonical-assets.jsonl
│   │   └── findings.jsonl
│   └── reports/
│       ├── executive.pdf
│       ├── technical.pdf
│       └── attachments/
└── _shared/
    └── retention-state/           # EvidenceRetentionPolicy checkpoints
```

Directory permissions: parent `0o750`, files `0o640` per r3ngine-security.md Rule 6.1.

### 5.2 Settings changes (`web/reNgine/settings.py`)

```python
# New assessment root — MUST NOT be under /usr/src/app/
ASSESSMENTS_ROOT = env('ASSESSMENTS_ROOT', default='/usr/src/assessments')

# Evidence storage relocates from /usr/src/app/evidence/ to under ASSESSMENTS_ROOT.
# Backend still respects the same env var interface for override.
EVIDENCE_STORAGE_ROOT = env(
    'EVIDENCE_STORAGE_ROOT',
    default=os.path.join(ASSESSMENTS_ROOT, 'evidence'),
)
```

### 5.3 Evidence storage backend changes (`web/evidence/storage.py`)

- `FilesystemEvidenceStorage.__init__`: default falls back to `settings.ASSESSMENTS_ROOT + '/evidence/'` instead of `/usr/src/app/evidence/`. Existing `EVIDENCE_STORAGE_ROOT` env override continues to work.
- `_unique_key` gains an optional `assessment_uuid` prefix so files land under `<assessment_uuid>/evidence/<YYYY>/<MM>/<DD>/…` when called with an assessment context. Existing call sites unaware of an assessment continue to write to a flat `/evidence/<YYYY>/…` path — same behavior as today.

### 5.4 Docker mount

`docker/docker-compose.yml` — the `web` service gets an additional named volume mount `assessments_data:/usr/src/assessments` (matching the pattern used for `scan_results`). **Named-volume style is required** to keep the Docker-managed volume physically outside the git working tree — a bind mount pointing into the repo would leak assessment data into git. The repository `.gitignore` additionally rejects any accidental `assessments/` or `usr/src/assessments/` path as a belt-and-suspenders defense.

**Migration correction (2026-07-05):** the pre-Task-3 default `EVIDENCE_STORAGE_ROOT = /usr/src/app/evidence/` did **not** point to a clean data directory — it pointed at the Django `evidence` app's *source directory* (bind-mounted from `web/evidence/`), which happened to also contain real evidence writes under date-partitioned subfolders. A naive one-shot copy therefore also drags Django `.py` source into the new volume. The `relocate_evidence` command (task M-1) MUST filter by the storage backend's naming pattern (`[<subfolder>/]YYYY/MM/DD/<32-hex>.<ext>`) and rejects anything outside that shape. A `--clean` flag also purges any non-evidence files that a prior naive run may have deposited at the destination.

Path validation in `evidence.storage` continues to enforce r3ngine-security.md Rule 1.2 (path traversal defense) with the new root as the base.

### 5.5 Path-traversal defense

Every new path construction uses `os.path.realpath()` + `startswith(ASSESSMENTS_ROOT)` guard per r3ngine-security.md Rule 1.2 and 1.3. Reuse of the helper in `common_func.py` where it exists.

---

## 6. Feature flags & sequencing

Both new stages default OFF in the initial merge. Enable in staging → prod after separate sign-off.

```python
# settings.py additions
ASSESSMENT_ASSET_CORRELATION_ENABLED = env.bool('ASSESSMENT_ASSET_CORRELATION_ENABLED', default=False)
ASSESSMENT_GRAPH_SYNC_ENABLED       = env.bool('ASSESSMENT_GRAPH_SYNC_ENABLED', default=False)
```

`AssessmentWorkflow` short-circuits the corresponding activity call when the flag is false — logs `[GRAPH] SKIP feature flag disabled` / `[CORRELATION] SKIP feature flag disabled`.

**Cutover order (each is a merge-worthy PR):**

| PR | Content |
|----|---------|
| P5.1 | APME `schema.py` node/edge additions + GraphBuilder new methods + tests |
| P5.2 | `SyncAssessmentGraphActivity` + worker registration + workflow wiring behind flag |
| P5.3 | `attach_assessment_id` management command + backfill script |
| P6.1 | `Asset` + `AssetSource` models + migration + tests |
| P6.2 | `AssetCorrelationService` + tests using existing exposure_correlation fixtures |
| P6.3 | `RunAssetCorrelationActivity` + worker registration + workflow wiring behind flag |
| P6.4 | Frontend surfaces (canonical assets table, graph filter by assessment) — separate design |
| STO.1 | `/usr/src/assessments` root, docker mount, evidence storage relocation, one-shot copy command |
| CLN.1 | Remove feature flags after two-release stability window |

---

## 7. Bug fixed inline on 2026-07-05

Related to Phase 5 evidence sync, three defects in `web/reNgine/utils/graph.py` `sync_scan_results` — visible as the log line `graph.sync_all_scans | ERROR | Failed to sync scan 20: Cannot resolve keyword 'type' into field.`:

1. Query used `.values('uuid', 'type', 'description', 'integrity_hash')` but the `Evidence` model has no `type` or `integrity_hash` fields — they are `evidence_type` and `sha256_hash`. Fixed.
2. Row mapping used `row['type']` and `row['integrity_hash']`. Fixed.
3. `_batch_merge_evidence` was called but never defined on `Neo4jManager`. Would have crashed with `AttributeError` even if the ORM query had worked. Added the method mirroring the other `_batch_merge_*` helpers.

These changes are already committed to the working tree ahead of the plan. Phase 5 implementation will supersede this ad-hoc sync path by moving evidence sync into `SyncAssessmentGraphActivity`, at which point this block in `sync_scan_results` can be deleted.

---

## 8. Testing

Per `r3ngine-tests.md` — all tests run inside Docker with `--keepdb --verbosity=2`.

### 8.1 New test modules

| File | Coverage |
|------|----------|
| `web/tests/test_apme_assessment_nodes.py` | GraphBuilder merges Assessment/Finding/Evidence/AuthenticationSystem idempotently; CONTAINS/SUPPORTED_BY/USES edges created; scan-only nodes still work with `assessment_id=None`; indexes created without error on empty Neo4j. |
| `web/tests/test_sync_assessment_graph_activity.py` | Activity idempotent on re-run (double invocation produces same node/edge counts); only findings with validation_status in {verified, needs_review, accepted_risk} are synced; skipped counts match; standalone scans unaffected; feature-flag off = SKIP log line + no writes. |
| `web/tests/test_asset_correlation_service.py` | Canonical dedup: httpx + nuclei + screenshot for the same URL merge to a single Asset with three AssetSource rows. Cross-assessment isolation: same URL under Assessment A and Assessment B produce two distinct Assets. No-assessment scans produce zero Assets. Risk score matches ExposureCorrelationEngine within 0.01. False-positive damper propagates transitively. |
| `web/tests/test_run_asset_correlation_activity.py` | Activity is idempotent; feature flag OFF short-circuits; AssessmentEvent emitted with correct counts. |
| `web/tests/test_assessment_workflow_new_stages.py` | Stages CORRELATION and GRAPH_SYNC run in order after Analysis and after Validation respectively; skippable via each flag independently; existing Discovery→Enum→Analysis→Validation→Reporting behavior unchanged when both flags off. |
| `web/tests/test_evidence_storage_new_root.py` | `EVIDENCE_STORAGE_ROOT` default resolves to `/usr/src/assessments/evidence/`. Path traversal guard rejects `..` and absolute paths. File permissions are `0o640`. Existing `EVIDENCE_STORAGE_ROOT` env override still honored. Assessment-uuid prefix path shape verified. |
| `web/tests/test_graph_sync_evidence_field_fix.py` | Regression test for the 2026-07-05 bug: `sync_scan_results` runs against a scan whose ScanHistory.assessment is set and Evidence records exist, without raising FieldError. |

### 8.2 Migration & backfill validation

| Task | Test |
|------|------|
| M-1 evidence copy from `/usr/src/app/evidence/` to `/usr/src/assessments/evidence/` | Idempotent — running twice does not corrupt or duplicate files. sha256 preserved. Signed URLs remain valid post-move (URLs are relative to storage root). |
| M-2 backfill `assessment_id` on APMENodes via `apme_attach_assessment` command | Command applied to a scan with 500 existing APMENodes updates all of them, no others; safe to re-run. |

### 8.3 Load / determinism

- `SyncAssessmentGraphActivity` with 50k findings + 200k evidence associations completes under 5 minutes with heartbeats emitted every 500 rows.
- `AssetCorrelationService.correlate()` runs deterministically: two runs on the same underlying data produce identical Asset UUIDs, identical AssetSource counts, identical risk scores. (First run seeds UUIDs; subsequent runs update-in-place.)

---

## 9. Security & compliance touchpoints

| Rule | Application |
|------|-------------|
| r3ngine-security.md 1.1–1.4 (path traversal) | All new writes under `/usr/src/assessments/` validated with `os.path.realpath()` + startswith guard against `ASSESSMENTS_ROOT`. Sanitized components — assessment UUID (validated) and sha256-hex names — only. |
| 2.1 (log injection) | All new logger calls use `%s` formatting. Externally-controlled values (assessment uuid, hostname, URL) never in f-strings. |
| 3.1–3.2 (URL comparison) | Canonical URL normalization uses `urllib.parse.urlparse`, not substring checks. Scheme allowlist `{http, https}` enforced before host comparison. |
| 6.1 (file permissions) | `FILE_UPLOAD_PERMISSIONS = 0o640` for evidence writes; directories `0o750`. |
| 7.1 (no duplicated security logic) | Path helper reused from `common_func.py`. Risk-score constants imported from `exposure_correlation`, not copied. |
| 8.1–8.2 (info exposure via exceptions) | AssetCorrelationService and both activities catch and log with `format_exception_for_log` — return only counts and status codes to the workflow. |
| RBAC (Phase 15 preview) | Not in scope for this design. New Assessment-scoped API views to expose Assets are deferred to a UI task; when added, they will require Assessment-Lead/Manager roles per assessment_operations.md Phase 15. |

---

## 10. Risks & mitigations

| Risk | Mitigation |
|------|------------|
| APME schema drift breaks existing Tier 7 sync | Additive-only changes; existing queries by `apme_id`/`scan_id` still work because new properties are nullable. Regression test in `test_apme_assessment_nodes.py` re-runs a scan-only sync and asserts identical output. |
| Neo4j write amplification (assessment sync duplicates scan sync) | `SyncAssessmentGraphActivity` MERGEs on the same `apme_id` as scan sync — no duplicate nodes, just added labels/properties. |
| Canonical dedup collides across assessments | `canonical_key_hash = sha256(assessment.uuid.hex || ':' || normalized_identifier)`. Assessment UUID is part of the hash. Enforced by DB unique_together. |
| Evidence storage move breaks existing signed URLs | Signed URLs are relative to storage root, not absolute. Move is atomic per file. M-1 test asserts URL stability. |
| Feature-flag rollback surface too big | Two independent flags, each on a single activity. Either can be turned off in prod without redeploying. Flags default OFF at merge. |
| Existing tests break due to new required migrations | All new columns nullable; migrations additive. Full suite runs against `--keepdb` in CI before merge with flags OFF. |
| Assessment file copy fills disk on first migration | M-1 uses `shutil.copy2` (preserves mtime, hardlink where possible); logs bytes-remaining every 100 files; can be resumed if killed. |

---

## 11. Expected end state

After both phases land and both feature flags are enabled:

- Every Assessment has a `:Assessment` node in Neo4j containing its live Findings (validation_status in {verified, needs_review, accepted_risk}) via `CONTAINS`; each Finding is linked to its Evidence via `SUPPORTED_BY`; Applications reveal their authentication providers via `USES`. Findings marked `false_positive`, `resolved`, or still `new` are intentionally not exposed in the graph.
- Every Assessment has a set of canonical `Asset` records in Postgres — one per real attack-surface entity — with all tool observations attached as `AssetSource` rows. Risk scores are consistent with the existing `Exposure` scoring model.
- Standalone scans work exactly as they did on `v4` today: scan-scoped APME nodes, scan-scoped Exposure records, no Assessment/Finding/Evidence graph nodes, no canonical Assets.
- All assessment artifacts (evidence files, exports, reports) live under `/usr/src/assessments/<assessment_uuid>/…`. Nothing under `/usr/src/app/` writes assessment data.
- The verification queue (Phase 4) is now graph-visible: an analyst can pivot from a `:Finding` to its Evidence, back to its owning Assessment, and out to related canonical Assets, all in one graph view.

---

## 12. Open questions (to resolve before implementation)

None blocking. Deferred to sub-tasks:
- Frontend UX for the Assessment-scoped canonical assets table (separate design task after backend lands).
- Whether `AuthenticationSystem` should also merge with existing `IdentityInfra` nodes on `host`, or stay independent. Recommendation: independent, cross-linked via `[:SPECIALIZES]` in a follow-up. Not in scope for this design.
