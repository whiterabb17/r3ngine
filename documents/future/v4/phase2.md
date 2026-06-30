Phase 2 — Assessment Orchestration Platform
Production-Ready Temporal Assessment Workflow Architecture for r3ngine v4
ALL WORK MUST BE DONE IN A v4 BRANCH

Phase 2 Goal
Phase 1 introduced:

Client
    ↓
Engagement
    ↓
Assessment
Phase 2 introduces:
Assessment
    ↓
Workflow Orchestration
    ↓
Discovery
    ↓
Enumeration
    ↓
Analysis
    ↓
Verification
    ↓
Reporting

The purpose is not merely workflow tracking.
The purpose is to transform assessments into:
Long-lived,
resumable,
auditable,
stateful operations
managed by Temporal.

At the end of Phase 2:
Assessments become Temporal-native entities.
Every stage is auditable.
Workflow failures are recoverable.
Progress is streamed to the React frontend.
Scan execution is orchestrated through workflow state.
SLA tracking becomes possible.
Future Evidence and Reporting modules have workflow integration points.

Critical Architectural Requirements
Absolutely No Celery Concepts

Forbidden:
task.delay()
chain()
group()
chord()

Assessment orchestration must be:
Temporal Workflow
    ↓
Activities
    ↓
Child Workflows
Assessment Workflow Is Top-Level

Current:
Scan
    ↓
Temporal Workflow
Future:
Assessment Workflow
    ↓
Discovery Workflow
    ↓
Enumeration Workflow
    ↓
Analysis Workflow
    ↓
Reporting Workflow
Scans become implementation details.
Every Workflow Must Be Recoverable

Must survive:
worker restarts
backend restarts
docker restarts
node failures
No in-memory state.

Deliverable 1 — Assessment State Machine
Create Explicit Assessment Lifecycle

Backend enum:
class AssessmentStatus(Enum):
    DRAFT
    READY
    DISCOVERY
    ENUMERATION
    ANALYSIS
    VALIDATION
    REPORTING
    REVIEW
    COMPLETE
    FAILED
    CANCELLED

Requirements
State transitions must be validated.
Example:
Valid:
READY
 ↓
DISCOVERY
Invalid:
READY
 ↓
REPORTING

Implementation
Create:
AssessmentStateMachine
Responsibilities:
Validate transitions
Emit events
Persist changes
Audit changes

Deliverable 2 — Temporal Workflow Domain Model
Create:
AssessmentWorkflow
Workflow Input
@dataclass
class AssessmentInput:
    assessment_id: UUID
    engagement_id: UUID
    assessment_type: str
    scope_ids: List[UUID]
Workflow Output
@dataclass
class AssessmentResult:
    assessment_id: UUID
    status: str
    findings_count: int
    evidence_count: int

Deliverable 3 — Workflow Stages
AssessmentWorkflow becomes orchestrator.

Stage 1
Discovery
Child workflow:
DiscoveryWorkflow
Responsibilities:
Target validation
Scope validation
Asset discovery
Asset enrichment
Outputs:
Assets
Technologies
Applications
Services

Stage 2
Enumeration
Child workflow:
EnumerationWorkflow
Responsibilities:
Web enumeration
API enumeration
Technology fingerprinting
Parameter discovery
Outputs:
Endpoints
Parameters
Applications

Stage 3
Analysis
Child workflow:
AnalysisWorkflow
Responsibilities:
Vulnerability execution
Correlation
Risk generation
Outputs:
Raw findings

Stage 4
Validation
Child workflow:
ValidationWorkflow
Responsibilities:
Verification queue generation
False-positive reduction
Outputs:
Validated findings

Stage 5
Reporting
Child workflow:
ReportingWorkflow
Responsibilities:
Coverage metrics
Assessment summaries
Report generation triggers

Deliverable 4 — Temporal Signals
Assessment workflow must support signals.
Pause Assessment
pause_assessment()
Resume Assessment
resume_assessment()
Cancel Assessment
cancel_assessment()
Add Assets
add_asset(asset_id)
Remove Assets
remove_asset(asset_id)
Update Scope
update_scope(scope_data)
Expected Outcome
Assessment changes without restarting workflow.

Deliverable 5 — Temporal Queries
Frontend must query live workflow state.
Create queries:
get_status()
get_progress()
get_current_stage()
get_assets_processed()
get_findings_count()
get_elapsed_time()

Deliverable 6 — Workflow Progress Persistence
Never rely solely on Temporal history.
Create:
AssessmentWorkflowState
Table.
Store:
workflow_id
run_id
current_stage
progress_percent
asset_count
finding_count
updated_at
Purpose:
Frontend performance.

Deliverable 7 — WebSocket Event System
Create:
AssessmentEventPublisher
Emit:
assessment_started
assessment_progress
assessment_paused
assessment_resumed
assessment_failed
assessment_completed
Payload:
{
  "assessment_id": "...",
  "stage": "enumeration",
  "progress": 47,
  "timestamp": "..."
}
Frontend subscribes via websocket.
No polling.

Deliverable 8 — React Assessment Execution Dashboard
New route:
/assessments/:id/execution
Sections:
Current Stage
Discovery
Enumeration
Analysis
Validation
Reporting
Progress
ECharts:
Stage completion
Asset Processing
Assets processed
Assets remaining
Findings
Raw findings
Validated findings
Runtime
Elapsed
ETA

Deliverable 9 — Workflow Control UI
Buttons:
Pause
Resume
Cancel
Requirements:
Role-based access.
Must display:
Pending signal
Signal acknowledged

Deliverable 10 — Scan Workflow Integration
Current scans must become children.
Current:
Target
 ↓
Scan
Future:
Assessment
 ↓
Enumeration Workflow
 ↓
Scan Workflow
Implementation:
Create:
ScanOrchestratorActivity
Responsibilities:
Launch existing scan workflows.
Must not rewrite scan engine.

Deliverable 11 — Workflow Audit Trail
Create:
AssessmentEvent
Store:
Assessment Started
Stage Changed
Workflow Failed
Workflow Resumed
Workflow Completed
Fields:
assessment_id
user_id
event_type
event_data
timestamp

Deliverable 12 — Retry Architecture
Every activity requires:
RetryPolicy(
    initial_interval=5,
    backoff_coefficient=2,
    maximum_interval=300,
    maximum_attempts=5
)
Workflow-level retries prohibited.
Only activities retry.

Deliverable 13 — Failure Isolation
Failure in:
Technology Fingerprinting
must not fail:
Entire Assessment
Use:
ApplicationError
with categorized severity.
Create:
RecoverableFailure
NonRecoverableFailure

Deliverable 14 — SLA Tracking Hooks
Assessment workflow must record:
Created
Started
Paused
Resumed
Completed
Store:
active_duration
paused_duration
total_duration
Future SLA dashboards depend on this.

Deliverable 15 — Metrics Collection
Create:
AssessmentMetricsService
Collect:
Assets discovered
Assets processed
Endpoints discovered
Parameters discovered
Findings generated
Findings validated
Persist periodically.

Deliverable 16 — Security Requirements
Workflow operations require:
Assessment Lead
Assessment Manager
roles.
Signals must validate:
Assessment ownership
Workspace access
RBAC permissions
No direct workflow IDs exposed externally.
Use:
assessment_uuid
mapping.

Deliverable 17 — Observability
Create dashboard endpoints.
Metrics:
Workflow duration
Failure rates
Activity retries
Assessment throughput
Expose:
Prometheus
OpenTelemetry
integration points.

Deliverable 18 — Testing Requirements
Must include:
Workflow Tests
Stage transitions
Signal handling
Query handling
Integration Tests
Database persistence
Websocket streaming
RBAC enforcement
Failure Tests
Worker restart
Activity timeout
Retry exhaustion
Load Tests

Validate:
100+ concurrent assessments
without workflow starvation.
Acceptance Criteria

Phase 2 is complete when:
✅ Assessments launch Temporal workflows
✅ Workflow state survives restarts
✅ Stages are tracked and validated
✅ Child workflows execute correctly
✅ Existing scan workflows integrate as children
✅ Frontend receives live updates
✅ Pause/Resume/Cancel works
✅ Audit events are generated
✅ SLA metrics are captured
✅ Activity retries function correctly
✅ RBAC enforced
✅ Websocket streaming operational
✅ Observability metrics exposed
✅ Full test coverage implemented
✅ No regression in existing scan execution

Expected End State
After Phase 2, r3ngine evolves from:
Assessment
 ↓
Manual Scan Launches
to:
Assessment
    ↓
Temporal Assessment Workflow
        ├── Discovery
        ├── Enumeration
        ├── Analysis
        ├── Validation
        └── Reporting
with every action tracked, recoverable, auditable, observable, and ready for the subsequent phases of evidence management, correlation, verification, and enterprise reporting.