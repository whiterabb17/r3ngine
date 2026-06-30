r3ngine v4 Assessment Operations Platform Blueprint
ALL WORK MUST BE DONE IN A v4 BRANCH

Vision
Transform r3ngine from:
Reconnaissance Framework
into:
Assessment Operations Platform
capable of supporting the full lifecycle of:
Penetration Tests
Vulnerability Assessments
External Attack Surface Reviews
Active Directory Assessments
API Security Assessments
Identity Exposure Assessments

while maintaining:
Auditability
Evidence Collection
Workflow Tracking
Reporting Quality
SLA Compliance
Analyst Collaboration
Core Architectural Principle

Everything should revolve around a single top-level object:
Client
 └── Engagement
      └── Assessment
           ├── Scope
           ├── Assets
           ├── Workflows
           ├── Evidence
           ├── Findings
           ├── Reports
           └── Audit Trail
Today r3ngine revolves around scans.
Future r3ngine should revolve around assessments.

PHASE 1 – Assessment Foundation
Objective
Introduce assessment-aware architecture.
New Backend Models
Client
id
name
contact_info
notes
status
created_at
Engagement
id
client_id
name
engagement_type
start_date
end_date
sla_deadline
status
Assessment
id
engagement_id
name
assessment_type
scope
status
created_at
completed_at
AssessmentAsset
Links:
Assessment
 ↓
Domain
Assessment
 ↓
Subdomain
Assessment
 ↓
IP
Assessment
 ↓
Application
Expected Outcome
Ability to track work as:
Client
 → Engagement
 → Assessment
 → Assets
instead of:
Random scans

PHASE 2 – Temporal Assessment Orchestration
Purpose
Create assessment-driven workflows.
New Temporal Workflows
AssessmentWorkflow
Top-level orchestrator.
AssessmentWorkflow
 ├── DiscoveryWorkflow
 ├── EnumerationWorkflow
 ├── AnalysisWorkflow
 ├── EvidenceWorkflow
 └── ReportingWorkflow
Where It Fits
Temporal Cluster
Current:
Scan Workflow
Future:
Assessment Workflow
 └── Scan Workflow
Expected Outcome
Scans become tasks inside assessments.

PHASE 3 – Evidence Management System
Purpose
Store proof supporting findings.
New Models
Evidence
id
assessment_id
finding_id
type
source
location
hash
created_at
Evidence Types
Screenshot
Request
Response
Graph Snapshot
Tool Output
File
Console Output
Storage
Prefer:
/object-storage/evidence/
or
/media/evidence/
Outcome
Every finding can be traced back to evidence.

PHASE 4 – Finding Lifecycle Engine
Purpose
Eliminate false-positive chaos.
New Finding States
New
Verified
Needs Review
False Positive
Accepted Risk
Resolved
Workflow
Tool Finding
      ↓
Verification Queue
      ↓
Analyst Review
      ↓
Finding
Expected Outcome
Reports only contain validated findings.

PHASE 5 – Neo4j Assessment Intelligence Layer
Purpose
Turn data into intelligence.
New Graph Nodes
Assessment
(:Assessment)
Finding
(:Finding)
Evidence
(:Evidence)
Application
(:Application)
AuthenticationSystem
(:AuthenticationSystem)
Relationships
Assessment
    ↓ CONTAINS
Finding
Finding
    ↓ SUPPORTED_BY
Evidence
Application
    ↓ USES
AuthenticationSystem
Expected Outcome
Graph becomes assessment-aware.

PHASE 6 – Exposure Correlation Engine
Purpose
Merge findings from all tools.
Current Problem
httpx
nuclei
screenshots
katana
all create separate records.
Future
VPN Gateway
 ├── httpx
 ├── screenshot
 ├── nuclei
 └── technology data
Implementation
Create:
AssetCorrelationService
Outcome
One asset.
Multiple evidence sources.

PHASE 7 – Parameter & API Intelligence
Purpose
Replace Arjun-style guessing.
New Module
ParameterDiscoveryEngine
Pipeline
Katana
 ↓
JS Collection
 ↓
AST Analysis
 ↓
Route Discovery
 ↓
Parameter Discovery
 ↓
GraphQL Discovery
 ↓
Correlation
Neo4j
Endpoint
 ↓ ACCEPTS
Parameter
Outcome
True API inventory.

PHASE 8 – Attack Surface Intelligence
Purpose
Model the client's attack surface.
New Entity Types
Organization
Domain
Subdomain
Application
API
Certificate
Identity Provider
VPN
Email System
Relationships
Organization
 ↓ OWNS
Domain
Domain
 ↓ HOSTS
Application
Outcome
Business-aware attack surface mapping.

PHASE 9 – Identity Intelligence
Purpose
Support AD assessments.
New Plugin
active_directory
Components
Discovery
Identity infrastructure.
Trust Analytics
Trust mapping.
Exposure Analytics
External/internal correlation.
Certificate Analytics
ADCS intelligence.
Outcome
Identity exposure management.

PHASE 10 – Reporting Engine
Purpose
Enterprise-grade deliverables.
Report Types
Executive
Risk-focused.
Technical
Evidence-focused.
Asset Inventory
Coverage-focused.
Exposure Report
Attack-surface focused.
Rendering
Generate:
PDF
HTML
JSON
Expected Outcome
Consultant-ready reports.

PHASE 11 – Quality Assurance Layer
Purpose
Prevent incomplete reports.
QA Checks
Finding Validation
Verified?
Evidence
Evidence attached?
Risk Rating
Assigned?
Remediation
Present?
Screenshot
Present?
Outcome
No report generated until complete.

PHASE 12 – SLA & Engagement Dashboard
Purpose
Operational visibility.
New Dashboard
Engagement Overview
Assessments
Progress
Deadlines
Findings Overview
Open
Verified
Needs Review
Resolved
Evidence Coverage
Attached
Missing
Charts
Use:
Apache ECharts
Primary charting.
React Flow
Workflow visualizations.
Cytoscape.js
Graph intelligence.
Outcome
Management visibility.

PHASE 13 – Consultant Workspace
Purpose
Support real-world engagements.
Features
Notes
Assessment Notes
Bookmarks
Interesting Assets
Tasks
Manual Validation
Remediation Notes
Per Finding
Outcome
Centralized analyst workspace.

PHASE 14 – Mobile Integration
Purpose
Remote assessment management.
Supported
Monitor Assessments
Review Findings
Review Evidence
Approve Findings
Launch Existing Scan Profiles
Not Supported
Complex graph editing.
Large report authoring.
Outcome
Operations companion.

PHASE 15 – Security & Multi-Tenancy
Purpose
Support consulting operations.
RBAC
Admin
Manager
Lead Consultant
Consultant
Read Only
Workspace Isolation
Client
Engagement
Assessment
Audit Logging

Track:
User
Action
Timestamp
Object
Outcome
Enterprise readiness.
Recommended Implementation Order

Sprint 1
Assessment Models
Assessment Dashboard
Assessment Workflow

Sprint 2
Evidence System
Finding Lifecycle
Verification Queue

Sprint 3
Correlation Engine
Neo4j Enhancements
Attack Surface Intelligence

Sprint 4
Parameter Discovery Engine
API Intelligence
Graph Enrichment

Sprint 5
Identity Intelligence Plugin
Trust Analytics
Exposure Correlation

Sprint 6
Reporting Engine
QA Workflow
SLA Dashboards

Sprint 7
Mobile App
Advanced Analytics
Assessment Automation
Expected End State
r3ngine v3
│
├── Assessment Operations
├── Attack Surface Intelligence
├── API Intelligence
├── Identity Intelligence
├── Evidence Management
├── Graph Analytics
├── Workflow Orchestration
├── SLA Management
├── Reporting Platform
└── Mobile Operations