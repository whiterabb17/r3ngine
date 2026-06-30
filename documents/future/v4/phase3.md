Phase 3 — Evidence Management Platform
Production-Ready Evidence Collection, Storage, Chain-of-Custody, and Analyst Workflow Architecture
ALL WORK MUST BE DONE IN A v4 BRANCH

Phase 3 Goal
Phase 2 introduced:
Assessment
    ↓
Temporal Workflow

Phase 3 introduces:
Assessment
    ↓
Finding
    ↓
Evidence

The objective is to create a complete evidence platform that supports:
Penetration testing engagements
Vulnerability assessments
API assessments
Active Directory assessments
Cloud assessments

while maintaining:
Chain of custody
Auditability
Traceability
Reportability
Multi-tenant isolation
Long-term retention

At the end of Phase 3:
Every finding must be traceable to supporting evidence.
Nothing enters a report without evidence.
Architectural Principles
Evidence Is A First-Class Entity
Never store screenshots, requests, responses or files directly on findings.

Forbidden:
Finding.screenshot
Finding.request
Finding.response

Instead:
Assessment
    ↓
Evidence
    ↓
Finding

Immutable Evidence
Evidence must never be modified.
If an analyst changes something:
Create New Version
Never overwrite.
Evidence Is Assessment Scoped
Evidence cannot exist outside:
Assessment
This simplifies:
RBAC
Reporting
Retention
Auditing

Deliverable 1 — Evidence Domain Model
Create:
Evidence
Fields
id
uuid
assessment_id
type
category
source
filename
content_type
storage_backend
storage_path
sha256_hash
file_size
created_by
created_at
version
is_deleted
Enums
EvidenceType
SCREENSHOT
HTTP_REQUEST
HTTP_RESPONSE
RAW_SCAN_OUTPUT
TERMINAL_OUTPUT
FILE_UPLOAD
GRAPH_SNAPSHOT
API_SCHEMA
CERTIFICATE
DNS_RECORD
LDAP_RECORD
KERBEROS_RECORD
BLOODHOUND_DATA
CUSTOM
EvidenceSource
NUCLEI
HTTPX
KATANA
FFUF
SUBFINDER
AMASS
PLUGIN
ANALYST
SYSTEM
Expected Outcome:
Universal evidence container.

Deliverable 2 — Evidence Relationship Model
Create:
FindingEvidence
Purpose
Many-to-many support.
Example:
Evidence
    ↓
Supports
Finding A
Evidence
    ↓
Supports
Finding B
Relationship Metadata
relevance_score
primary_evidence
added_by
created_at
Expected Outcome
Single screenshot may support multiple findings.

Deliverable 3 — Object Storage Architecture
Do NOT store evidence inside database.
Allowed
MinIO
S3
Filesystem
Implement Storage Abstraction
StorageProvider
Methods
save()
retrieve()
delete()
verify()
generate_signed_url()
Providers
FilesystemStorageProvider
MinIOStorageProvider
S3StorageProvider
Default
Filesystem
Expected Outcome
Storage backend can change without code changes.

Deliverable 4 — Evidence Hashing
Every evidence item must be hashed.
Hash
SHA256
Store
sha256_hash
Verify On Retrieval
verify_integrity()
Expected Outcome
Tamper detection.

Deliverable 5 — Chain Of Custody System
Create:
EvidenceAuditEvent
Track
CREATED
VIEWED
DOWNLOADED
LINKED_TO_FINDING
UNLINKED_FROM_FINDING
EXPORTED
ARCHIVED
Fields
evidence_id
user_id
action
ip_address
timestamp
Expected Outcome
Full evidence audit trail.

Deliverable 6 — Temporal Evidence Activities
Create:
StoreEvidenceActivity
VerifyEvidenceActivity
LinkEvidenceActivity
ArchiveEvidenceActivity
Never perform storage directly inside workflows.
Only activities.
Expected Outcome
Temporal-safe evidence handling.

Deliverable 7 — Screenshot Evidence Service
Integrate with screenshot architecture.
Workflow
Screenshot Service
        ↓
PNG
        ↓
Evidence Storage
        ↓
Evidence Record
Metadata
width
height
browser
timestamp
page_title
http_status
Expected Outcome
Screenshots become evidence objects.

Deliverable 8 — HTTP Evidence Capture
Capture:
Requests
Method
URL
Headers
Body
Responses
Status
Headers
Body
Content-Type
Storage
Compressed JSON
gzip
Expected Outcome
Reproducible findings.

Deliverable 9 — Graph Snapshot Service
Neo4j evidence support.
Generate snapshots for:
Attack Surface
AD Relationships
Trust Paths
Exposure Graphs
Store
PNG
SVG
JSON
Expected Outcome
Reports contain graph evidence.

Deliverable 10 — Evidence Upload API
Endpoints
POST /api/evidence
GET /api/evidence
GET /api/evidence/{id}
DELETE /api/evidence/{id}
Requirements
RBAC
Ownership validation
MIME validation
Size limits

Deliverable 11 — Secure File Validation
Create:
EvidenceValidator
Validate
MIME
Allowed list.
Extension
Allowed list.
Size
Configurable.
Hash
Verify upload integrity.
Forbidden
Executable uploads
unless explicitly allowed.
Expected Outcome
No arbitrary file abuse.

Deliverable 12 — React Evidence Module
Route
/assessments/:id/evidence
Views
Evidence List
Columns
Type
Source
Size
Created
Linked Findings
Evidence Detail
Preview
Metadata
Audit History
Relationships

Deliverable 13 — Evidence Explorer
Filters
Assessment
Source
Type
Date
Linked Findings
Analyst
Search
Filename
Hash
Metadata
Expected Outcome
Analyst can locate evidence instantly.

Deliverable 14 — Evidence Preview Components
Supported
Images
PNG
JPG
WEBP
JSON
Pretty viewer.
Text
Syntax highlighting.
HTTP
Request/Response viewer.
Graphs
Neo4j snapshot viewer.

Deliverable 15 — Finding Integration
Finding Detail Page
Add:
Evidence Tab
Display
Primary Evidence
Supporting Evidence
Timeline
Expected Outcome
Findings become evidence-backed.

Deliverable 16 — Analyst Notes
Create
EvidenceAnnotation
Fields
evidence_id
author
note
created_at
Purpose
Evidence review.

Deliverable 17 — Evidence Versioning
Never overwrite.
Workflow
Evidence V1
    ↓
Evidence V2
Relationship
parent_evidence_id
Expected Outcome
Historical preservation.

Deliverable 18 — Report Integration
Reporting APIs must consume:
EvidenceService
Supported
Screenshots
Graphs
Requests
Responses
Files
Expected Outcome
Evidence automatically included in reports.

Deliverable 19 — Retention Policies
Assessment Level
retention_period
Policies

90 Days

180 Days

365 Days
Forever
Archive Workflow
Temporal activity.
Expected Outcome
Storage remains manageable.

Deliverable 20 — Neo4j Evidence Graph
Nodes
Evidence
Finding
Assessment
Relationships
Assessment
    ↓ CONTAINS
Evidence
Evidence
    ↓ SUPPORTS
Finding
Expected Outcome
Graph-backed evidence intelligence.

Deliverable 21 — WebSocket Events
Emit
evidence_created
evidence_linked
evidence_archived
evidence_deleted
Frontend updates live.
No polling.

Deliverable 22 — Security Requirements
Every access validates:
Workspace
Assessment
RBAC
Signed URLs
Expiration:

5 Minutes
Never expose storage paths.
Expected Outcome
Tenant-safe evidence handling.

Deliverable 23 — Observability
Metrics
Evidence Count
Storage Utilization
Upload Failures
Integrity Failures
Evidence Retrieval Time
Export
Prometheus
OpenTelemetry

Deliverable 24 — Testing Requirements
Unit Tests
Storage providers
Hashing
Validation
Integration Tests
Upload
Retrieval
Linking
Security Tests
RBAC
Path traversal
MIME spoofing
Load Tests
Validate:

100k+ evidence objects
without performance degradation.
Acceptance Criteria

Phase 3 is complete when:
✅ Evidence is a first-class entity
✅ Storage abstraction implemented
✅ Files stored outside DB
✅ SHA256 integrity verification implemented
✅ Chain-of-custody auditing implemented
✅ Screenshot evidence operational
✅ HTTP evidence capture operational
✅ Graph snapshot evidence operational
✅ React evidence explorer complete
✅ Findings link to evidence
✅ Versioning operational
✅ Retention policies operational
✅ Signed URL downloads implemented
✅ RBAC enforced
✅ WebSocket updates operational
✅ Neo4j relationships operational
✅ Full test suite passing
✅ Report integration operational

Expected End State
After Phase 3:
Assessment
    ├── Assets
    ├── Workflows
    ├── Findings
    ├── Evidence
    │      ├── Screenshots
    │      ├── Requests
    │      ├── Responses
    │      ├── Graphs
    │      ├── Files
    │      └── Notes
    └── Reports
Every finding becomes defensible, reproducible, auditable, and report-ready. This phase establishes the foundation required for analyst verification workflows, enterprise reporting, quality assurance gates, and long-term assessment record retention.