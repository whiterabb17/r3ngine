"""Classify a failed timeline entry into an operator-facing failure category.

``ScanActivity.error_message`` carries whatever the failing layer produced:

* ``repr()`` of the exception raised by ``_run_task``
  (``reNgine/temporal/activities/__init__.py``), which for a task that simply
  gave up reads ``Task <name> execution returned False/failed.`` or
  ``Task <name> failed: <reason from self.error>``;
* the workflow-level text written onto every still-running row by
  ``FinalizeFailedScanActivity`` (``Scan workflow crashed.``);
* the ``ApplicationError`` texts of the abort/delete guards.

That text answers "what broke" only for someone who already knows the codebase.
It does not answer "what kind of failure is this" — which is the question an
operator reading the scan timeline actually has: did the box reboot mid-scan,
was the proxy refused, or did the tool itself exit non-zero?

This module maps the message shapes the codebase really produces onto a small
set of categories, each with a **fixed** hint. The hints are constants on
purpose: ``error_message`` is served to every role by the scan summary API
(only ``traceback`` is restricted to sys_admin/penetration_tester), so a hint
must never echo a URL, host, credential or raw exception text — security
rule 8.1. Nothing that is not recognised is guessed at: it falls through to
``unknown``.
"""

from typing import NamedTuple

CATEGORY_TEMPORAL_CANCELLED = "temporal_cancelled"
CATEGORY_HEARTBEAT_TIMEOUT = "heartbeat_timeout"
CATEGORY_ACTIVITY_TIMEOUT = "activity_timeout"
CATEGORY_WORKER_RESTART = "worker_restart"
CATEGORY_MISSING_CONFIGURATION = "missing_configuration"
CATEGORY_PROXY_FAILURE = "proxy_failure"
CATEGORY_DATABASE_ERROR = "database_error"
CATEGORY_NETWORK_ERROR = "network_error"
CATEGORY_TOOL_FAILURE = "tool_failure"
CATEGORY_UNKNOWN = "unknown"

# One short sentence per category, safe for every role. Never interpolate.
CATEGORY_HINTS: dict[str, str] = {
    CATEGORY_TEMPORAL_CANCELLED: (
        "The scan was aborted, deleted or cancelled while this task was "
        "running; start a new scan to collect this step."
    ),
    CATEGORY_HEARTBEAT_TIMEOUT: (
        "The task stopped reporting progress and Temporal stopped it; check "
        "the worker logs for this task."
    ),
    CATEGORY_ACTIVITY_TIMEOUT: (
        "The task ran past its Temporal time limit and was stopped; raise the "
        "timeout or narrow the scope."
    ),
    CATEGORY_WORKER_RESTART: (
        "The worker running this task went away mid-execution, typically a "
        "restart or a crash; re-run the task."
    ),
    CATEGORY_MISSING_CONFIGURATION: (
        "A required API key or feature flag is not configured, so the task "
        "could not run; check the integration settings."
    ),
    CATEGORY_PROXY_FAILURE: (
        "The configured proxy refused or dropped the connection; review the "
        "proxy pool in the OpSec settings."
    ),
    CATEGORY_DATABASE_ERROR: (
        "The task could not reach or write to a backing datastore; check the "
        "database service and its logs."
    ),
    CATEGORY_NETWORK_ERROR: (
        "The task could not reach the target or an upstream service over the "
        "network."
    ),
    CATEGORY_TOOL_FAILURE: (
        "The tool itself did not complete successfully; open the task details "
        "for its command output."
    ),
    CATEGORY_UNKNOWN: (
        "No known failure pattern matched this message; open the task details "
        "for the full text."
    ),
}


class _Rule(NamedTuple):
    """One category and the lowercase substrings that select it.

    ``message_keywords`` are matched against ``error_message``, which is
    curated text. ``traceback_keywords`` are matched against the traceback and
    are deliberately narrower — a traceback names internal symbols (for
    instance ``TemporalTaskProxy``) that would otherwise pull unrelated
    failures into the wrong category.
    """

    category: str
    message_keywords: tuple[str, ...]
    traceback_keywords: tuple[str, ...]


# Ordered: the first rule that matches wins, so a more specific cause is listed
# before the generic one that its message also contains. Notably
# missing_configuration precedes tool_failure ("Task acunetix_scan failed:
# Acunetix API keys not fully configured in vault." matches both), and both
# proxy_failure and database_error precede network_error (a dead proxy and a
# dead database both report "connection refused").
_RULES: tuple[_Rule, ...] = (
    _Rule(
        CATEGORY_TEMPORAL_CANCELLED,
        (
            "was aborted by the user",
            "workflow cancelled",
            "child workflow cancelled",
            "scan was deleted",
            "no longer exists",
            "cancellederror",
            "activity cancelled",
        ),
        ("cancellederror",),
    ),
    _Rule(
        CATEGORY_HEARTBEAT_TIMEOUT,
        (
            "heartbeat timeout",
            "heartbeattimeout",
            "heartbeat timed out",
            "timeout_type_heartbeat",
        ),
        (),
    ),
    _Rule(
        CATEGORY_ACTIVITY_TIMEOUT,
        (
            "starttoclose",
            "start_to_close",
            "scheduletoclose",
            "schedule_to_close",
            "scheduletostart",
            "schedule_to_start",
            "activity task timed out",
            "activity timeout",
        ),
        ("temporalio.exceptions.timeouterror",),
    ),
    _Rule(
        CATEGORY_WORKER_RESTART,
        (
            "scan workflow crashed",
            "worker shutting down",
            "worker shutdown",
            "worker restart",
            "activity task not found",
            "workflow execution already completed",
            "interrupted by a server restart",
            "workflow task timed out",
        ),
        (),
    ),
    _Rule(
        CATEGORY_MISSING_CONFIGURATION,
        (
            "not fully configured in vault",
            "api key not set",
            "api key not found",
            "api keys not found",
            "api key not configured",
            "api keys not configured",
            "no api key configured",
            "api key doesn't exist",
            "invalid netlas api key",
            "llm disabled",
            "llm_enabled unset",
            "not configured — add it in settings",
        ),
        (),
    ),
    _Rule(
        CATEGORY_PROXY_FAILURE,
        (
            "proxyerror",
            "proxy error",
            "proxychains",
            "cannot connect to proxy",
            "unable to connect to proxy",
            "failed to connect to proxy",
            "proxy connection",
            "proxy authentication",
            "proxy is transparent",
            "proxy pool",
            "no valid proxy",
            "no working proxy",
            "all proxies are dead",
            "tunnel connection failed",
            "socks5",
            "socks4",
        ),
        ("proxyerror", "proxychains", "socksconnectionerror"),
    ),
    _Rule(
        CATEGORY_DATABASE_ERROR,
        (
            "operationalerror",
            "interfaceerror",
            "integrityerror",
            "databaseerror",
            "psycopg2",
            "django.db.utils",
            "could not connect to server",
            "server closed the connection unexpectedly",
            "too many connections",
            "deadlock detected",
            "serviceunavailable",
            "sessionexpired",
            "neo4j",
            "redis",
        ),
        (
            "operationalerror",
            "interfaceerror",
            "integrityerror",
            "databaseerror",
            "psycopg2",
            "django.db.utils",
            "neo4j",
            "redis.exceptions",
        ),
    ),
    _Rule(
        CATEGORY_NETWORK_ERROR,
        # The connection-phase wording mirrors _PROXY_DEAD_KEYWORDS in
        # reNgine/common_func.py, which is this codebase's own list of the
        # strings a dead endpoint produces.
        (
            "connectionerror",
            "connecttimeout",
            "readtimeout",
            "connectionreseterror",
            "newconnectionerror",
            "maxretryerror",
            "max retries exceeded",
            "sslerror",
            "certificate verify failed",
            "connection refused",
            "connection reset",
            "connection aborted",
            "network is unreachable",
            "no route to host",
            "name or service not known",
            "temporary failure in name resolution",
            "nodename nor servname",
            "httpconnectionpool",
            "httpsconnectionpool",
        ),
        (
            "connectionerror",
            "connecttimeout",
            "readtimeout",
            "newconnectionerror",
            "maxretryerror",
            "sslerror",
            "gaierror",
            "socket.timeout",
        ),
    ),
    _Rule(
        CATEGORY_TOOL_FAILURE,
        (
            "execution returned false/failed",
            "returned false",
            "exit status",
            "exit code",
            "non-zero exit",
            "command not found",
            "signal: killed",
            "timed out after",
            # Last: _run_task wraps every self.error reason as
            # "Task <name> failed: <reason>", so anything still unmatched here
            # is the task reporting its own tool-level failure.
            "failed:",
        ),
        (),
    ),
)


def _result(category: str) -> dict[str, str]:
    return {"category": category, "hint": CATEGORY_HINTS[category]}


def classify_failure(
    error_message: str | None,
    traceback_text: str | None,
) -> dict[str, str] | None:
    """Classify a task failure into a category and a role-safe hint.

    Args:
        error_message: ``ScanActivity.error_message`` for the failed row.
        traceback_text: ``ScanActivity.traceback`` for the same row. Used only
            as a fallback signal when the message classifies nothing.

    Returns:
        ``{'category': <slug>, 'hint': <fixed sentence>}``, or ``None`` when
        both inputs are empty and there is nothing to classify. Unrecognised
        text yields the ``unknown`` category rather than a guessed cause. The
        hint is a constant from ``CATEGORY_HINTS`` and never contains any part
        of the inputs.
    """
    message = (error_message or "").strip().lower()
    trace = (traceback_text or "").strip().lower()
    if not message and not trace:
        return None

    # The message is curated text, so it decides on its own whenever it can.
    for rule in _RULES:
        if any(keyword in message for keyword in rule.message_keywords):
            return _result(rule.category)

    for rule in _RULES:
        if any(keyword in trace for keyword in rule.traceback_keywords):
            return _result(rule.category)

    return _result(CATEGORY_UNKNOWN)
