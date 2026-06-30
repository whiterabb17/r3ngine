Phase 1 Implementation Plan — Assessment Foundation
ALL WORK MUST BE DONE IN A v4 BRANCH

Objective
Transform r3ngine from a scan-centric platform into an assessment-centric platform without breaking any existing functionality.

The goal of Phase 1 is not to change how scanning works.
The goal is to introduce the foundational entities that all future capabilities will build upon:
Engagement Management
Assessment Tracking
SLA Tracking
Scope Management
Asset Association
Assessment-Aware Workflows

At the end of Phase 1:
Client
    ↓
Engagement
    ↓
Assessment
    ↓
Assets
    ↓
Scans
should exist throughout the platform.
Current scan execution must remain fully functional.
Critical Architectural Requirements
Must Not Break Existing Functionality

Current:
Target
    ↓
Scan
must continue to work.
Must Support Gradual Migration

For now:
Assessment
    ↓
Scan
is optional.
Future phases will make assessments primary.
No Data Duplication

Do NOT create:
AssessmentDomain
AssessmentSubdomain
AssessmentEndpoint
tables.
Reuse existing entities through relationships.
Temporal First

All new orchestration should use:
Temporal
Never introduce Celery-specific patterns.
Existing System Analysis Requirements

Before implementation, first perform a complete audit of:
Backend

Identify:
Current Target model
Current Project/Workspace model
Scan model
SubScan model
Scan History model
Organization model (if present)
Permissions model
Audit model
Frontend

Identify:
React routing structure
Navigation architecture
State management
API architecture
Current dashboard implementation
Target management pages
Scan history pages
Temporal

Identify:
Workflow registration
Workflow launch paths
Workflow tracking
Workflow state storage

Deliverable 1 — Domain Model Design
New Entity: Client
Purpose:
Represents the customer.
Backend Model
class Client

Fields:
id
uuid
name
description
primary_contact
email
phone
status
created_by
created_at
updated_at
Status
Active
Inactive
Archived
Expected Outcome
A customer record capable of owning multiple engagements.

Deliverable 2 — Engagement Model
Purpose:
Represents a signed project.
Backend Model
class Engagement

Fields:
id
uuid
client
name
description
engagement_type
start_date
end_date
sla_due_date
status
created_by
created_at
updated_at
Engagement Types
Penetration Test
Vulnerability Assessment
Attack Surface Review
API Assessment
AD Assessment
Hybrid Assessment
Status
Draft
Scheduled
Active
Paused
Completed
Archived
Expected Outcome
Single engagement capable of containing multiple assessments.

Deliverable 3 — Assessment Model
Purpose:
Operational unit of work.
Backend Model
class Assessment

Fields:
id
uuid
engagement
name
description
assessment_type
status
started_at
completed_at
created_by
created_at
updated_at
Assessment Types
External
Internal
Web
API
Mobile
Cloud
AD
Hybrid
Status
Draft
Ready
Running
Review
Completed
Archived
Expected Outcome
All future findings, evidence and reports will belong to an assessment.

Deliverable 4 — Assessment Scope System
Purpose:
Define authorized scope.
Model
AssessmentScope

Supported Scope Types:
Domain
Subdomain
CIDR
IP
URL
Application
Cloud Asset
Relationships
Assessment
    ↓
Scope
Requirements
Support:
In Scope
Out Of Scope
Excluded
Future Use

Will drive:
Workflow authorization
Report scope
Compliance checks

Deliverable 5 — Assessment Asset Mapping
Purpose:
Link existing discovered assets.
DO NOT DUPLICATE EXISTING ASSETS
Reuse:
Domain
Subdomain
Endpoint
IP
Technology
Create mapping tables:
AssessmentAsset

Relationships:
Assessment
    ↓
Asset
Outcome
One asset can belong to multiple assessments.

Deliverable 6 — Assessment Dashboard Backend
New APIs:
List Assessments
GET /api/assessments
Assessment Detail
GET /api/assessments/{id}
Create Assessment
POST /api/assessments
Update Assessment
PATCH /api/assessments/{id}
Assessment Assets
GET /api/assessments/{id}/assets
Assessment Scans
GET /api/assessments/{id}/scans

Deliverable 7 — React Frontend Foundation
New Navigation Section:
Assessments
Routes:
/assessments
/assessments/new
/assessments/:id
/assessments/:id/assets
/assessments/:id/scans
/assessments/:id/settings

Deliverable 8 — Assessment Overview Page
Display:
Summary Cards
Status
Assets
Scans
Findings
Evidence
(Currently findings/evidence can display placeholders until later phases.)
Timeline
Created
Started
Completed
Scope Overview
Domains
IPs
Applications
Progress Indicators
Discovery
Enumeration
Analysis
Reporting

Deliverable 9 — Assessment Creation Wizard
* Should be able to link an existing project and convert all current scan/project data into an assessment.
* Should NOT be required in order to perform a scan. (We should still be able to scan without an assessment.)

Multi-step React Wizard:
Step 1
Client
Engagement
Assessment Type
Step 2
Scope Definition
Step 3
Asset Selection
Step 4
Review

Deliverable 10 — Scan Association Layer
Purpose:
Allow existing scans to be attached to assessments.
Update existing scan models:
Add:
assessment_id
nullable initially.
Requirement:
Existing scans continue working.
New scans launched from assessments:
Assessment
    ↓
Scan

Deliverable 11 — Temporal Assessment Workflow
Create:
AssessmentWorkflow
Responsibilities:
Assessment Created
    ↓
Assessment Ready
    ↓
Assessment Running
    ↓
Assessment Review
    ↓
Assessment Complete
Initially:
Workflow only tracks lifecycle.
DO NOT launch scans yet.
That comes in later phases.

Deliverable 12 — Audit Logging
Every action must generate audit events.
Track:
Assessment Created
Assessment Updated
Scope Changed
Assets Added
Assets Removed
Status Changed
Store:
User
Timestamp
Action
Object

Deliverable 13 — Permissions
New Roles:
Assessment Viewer
Assessment Contributor
Assessment Lead
Assessment Manager

Permissions:
Create Assessment
Edit Assessment
Delete Assessment
Assign Assets
Manage Scope
View Audit Log
Deliverable 14 — Database Migration Strategy

Requirements:
Zero Existing Data Loss

Must preserve:
Targets
Scans
Subscans
Findings
Users
Workspaces
Forward Compatible

Future phases must easily attach:
Evidence
Reports
Graph Intelligence
Identity Intelligence
to Assessment.
Acceptance Criteria

Phase 1 is complete when:
✅ Clients can be created
✅ Engagements can be created
✅ Assessments can be be created
✅ Scope can be defined
✅ Existing assets can be linked
✅ Existing scans can optionally belong to assessments
✅ React UI fully supports assessment management
✅ Temporal tracks assessment lifecycle
✅ Audit logging exists
✅ RBAC exists
✅ Existing scan workflows continue functioning without modification
✅ Database migrations complete successfully
✅ No existing functionality regresses

Final Deliverable Expected:

Full architecture review of existing r3ngine v3 structures.
Database schema design.
Migration plan.
Backend model implementation.
API implementation.
Temporal workflow implementation.
React UI implementation.
Zustand store integration.
TanStack Query integration.
RBAC integration.
Audit logging integration.
Unit and integration tests.
End-to-end validation proving existing scan workflows remain unaffected.
The implementation should establish the assessment layer as a first-class platform capability while remaining fully backward compatible with the current scan-centric operation model.