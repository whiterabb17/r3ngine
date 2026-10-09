"""
Temporal Workflow definitions for the r3ngine scan pipeline.

Workflows define the durable orchestration logic — the "what runs when" in the
scan pipeline. All workflows are pure Python and must be deterministic (no I/O,
no random, no datetime.now()). Side-effecting work is delegated to activities.

The Python Orchestrator Worker hosts these workflow classes and listens on the
'python-orchestrator-queue' task queue.

Design principles:
  - Workflows are thin orchestrators: they gather, sequence, and fork activities.
  - All actual scan logic lives in activities (temporal_activities.py).
  - Activities on the 'go-executor-queue' are dispatched to the Go binary
    (web/executor/main.go) for heavy subprocess-based tool execution.
  - Activities on the 'python-orchestrator-queue' are dispatched back to this
    Python worker for Django DB reads/writes and Neo4j sync.

The workflow classes are split across flat sibling modules and re-exported here
so ``reNgine.temporal.workflows`` (and the ``reNgine.temporal_workflows`` shim)
keeps exposing every name:

  - ``_common.py``      retry policy presets and shared helper coroutines
  - ``master_scan.py``  MasterScanWorkflow, NucleiPlannerWorkflow
  - ``subscan.py``      _SUBSCAN_DISPATCH, _STANDALONE_SUBSCAN_WORKFLOWS, SubScanWorkflow
  - ``stress.py``       StressTestWorkflow
  - ``jobs.py``         monitoring / scheduling / single-activity / retry / follow-up workflows
  - ``recon.py``        standalone recon and URL workflows
  - ``assessment_workflow.py`` (imported directly by its users; not re-exported)
"""

from reNgine.temporal.workflows._common import (
    _RETRY_INTERNAL,
    _RETRY_LLM,
    _RETRY_LONG_SCAN,
    _RETRY_NETWORK_SCAN,
    _RETRY_SCANNER,
    _dispatch_tier_plugins,
    _fan_out_search_vulns,
)
from reNgine.temporal.workflows.master_scan import (
    MasterScanWorkflow,
    NucleiPlannerWorkflow,
)
from reNgine.temporal.workflows.subscan import (
    _STANDALONE_SUBSCAN_WORKFLOWS,
    _SUBSCAN_DISPATCH,
    SubScanWorkflow,
)
from reNgine.temporal.workflows.stress import StressTestWorkflow
from reNgine.temporal.workflows.jobs import (
    ApmeTaskWorkflow,
    CertificateResyncWorkflow,
    FollowupPlanWorkflow,
    GeoLocalizeWorkflow,
    GoExecutorTaskWorkflow,
    HackerOneImportWorkflow,
    HackerOneSyncBookmarkedWorkflow,
    IdentityEnrichmentWorkflow,
    MonitoringWorkflow,
    ProxyFetchWorkflow,
    RecalculateApmeWorkflow,
    SafePocWorkflow,
    ScheduledScanWorkflow,
    SingleTaskRetryWorkflow,
    StartupSyncWorkflow,
    ToolProbeWorkflow,
)
from reNgine.temporal.workflows.recon import (
    CIDRReconWorkflow,
    CodeScanWorkflow,
    DomainReconWorkflow,
    HostReconWorkflow,
    SubdomainReconWorkflow,
    URLAuthExtractWorkflow,
    URLBypassWorkflow,
    URLCrawlWorkflow,
    URLDirSearchWorkflow,
    URLFuzzWorkflow,
    URLParamsFuzzWorkflow,
    URLVulnWorkflow,
    UserHuntWorkflow,
    WordPressWorkflow,
)
