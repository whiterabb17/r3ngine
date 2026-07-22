# Phase 4: Finding Lifecycle Engine Implementation Plan

## 1. Purpose & Goals
The objective of Phase 4 is to eliminate false-positive chaos by standardizing finding states and introducing a rigorous Verification Queue. This ensures that the final deliverable (the report) only contains validated and verified findings.

**Target Flow:** 
`Tool Finding` → `Verification Queue` → `Analyst Review` → `Finding (Verified)`

## 2. Django Model Modifications (`startScan.models.Vulnerability`)
Currently, `validation_status` relies on a mix of states (`unverified`, `verified`, `not_working`, `patched`, `closed`). These will be replaced by the strict Phase 4 states.

### 2.1 Schema Updates
- Update `VULNERABILITY_STATUS_CHOICES` to strictly conform to the new states:
  - `new`: Initial state for all tool-generated findings.
  - `verified`: Finding has been confirmed via automated exploitation or analyst review.
  - `needs_review`: Automated validation failed or lacked confidence, requiring human verification.
  - `false_positive`: Finding is invalid.
  - `accepted_risk`: Finding is valid but the client accepts the risk (excluded from standard remediation reports but kept in system).
  - `resolved`: Finding was valid but has been remediated and confirmed closed.
- Set default `validation_status` to `new`.

### 2.2 Data Migration Strategy
Create a Django data migration to translate existing records:
- `unverified` → `new`
- `verified` → `verified`
- `not_working` → `false_positive`
- `patched` → `resolved`
- `closed` → `resolved`

## 3. Workflow Integration (Temporal)
### 3.1 Automated Validation Workflow
The `ValidationWorkflow` (introduced in Phase 2) will act as the first gatekeeper.
- **High Confidence**: If automated tools (e.g., active exploitation, LLM confirmation) confirm the vulnerability with high confidence (`validation_confidence > 0.8`), transition status from `new` to `verified`.
- **Low Confidence/Failure**: If automated tools cannot confirm it, transition from `new` to `needs_review`.
- **Negative Confirmation**: If validation proves it is a false positive, set to `false_positive`.

## 4. Verification Queue (Analyst Review)
### 4.1 API Endpoints
- **GET `/api/v1/vulnerabilities/queue/`**: Returns all findings where `validation_status` is `needs_review` or `new`, sorted by CVSS/severity and correlation score.
- **POST `/api/v1/vulnerabilities/{id}/verify/`**: Analyst transitions finding to `verified`. Requires attaching or confirming `Evidence` (integration with Phase 3).
- **POST `/api/v1/vulnerabilities/{id}/reject/`**: Analyst transitions finding to `false_positive` with a required justification reason.

### 4.2 Frontend (UI) Updates
- **Verification Queue Dashboard**: A new view specifically designed for rapid triage, separating actionable alerts from the general vulnerability list.
- **DataTable Updates**: Update `vuln_datatables.js` to render the new state badges (e.g., Warning Yellow for `Needs Review`, Success Green for `Verified`, Danger Red for `False Positive`).
- **Bulk Actions**: Allow analysts to select multiple findings and mark them as `False Positive` or `Verified` simultaneously.

## 5. Reporting Engine Enforcement
Update the `ReportingWorkflow` and Exporters (e.g., `ai_bundle.py`, PDF/CSV generators).
- **Hard Filter**: Modify querysets in `reNgine/exporters/*` to exclusively filter `validation_status='verified'`. 
- **Accepted Risk Exclusions**: `accepted_risk` and `false_positive` findings must explicitly bypass the final customer-facing report but remain in the APME Graph.

## 6. Execution Steps
1. **Migrations**: Alter the `validation_status` field and execute the data migration mapping.
2. **API/Logic Updates**: Update `startScan/views.py`, `api/views/vulns.py`, and `correlation.py` to utilize the new states.
3. **Temporal Workflows**: Wire `ValidationWorkflow` to categorize findings into the Verification Queue.
4. **UI Refactor**: Build the Verification Queue view and update datatable filters.
5. **Testing**: Add end-to-end unit tests simulating the full Finding Lifecycle (Tool → Queue → Review → Report).
