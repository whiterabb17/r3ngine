"""
Intelligence activities: certificate, identity and API intel, identity
enrichment, geo-localisation, certificate resync and email security.
"""

from temporalio import activity
from reNgine.temporal.heartbeat import keep_alive

from reNgine.utils.logger import get_module_logger, format_exception_for_log
from reNgine.temporal.activities.core import _start_scan_task_proxy

logger = get_module_logger(__name__)


@activity.defn(name="run_certificate_intel_activity")
def run_certificate_intel_activity(scan_history_id: int, job_id: str = None) -> dict:
    """
    Collect TLS/certificate intelligence for all live subdomains.
    Runs tlsx -json, parses output, writes CertificateIntelligence records.
    Must run before APME so ingest_certificates() has data to read.
    """
    import os
    import re
    from reNgine.tasks.certificate import run_certificate_intel
    from reNgine.settings import RENGINE_RESULTS
    from reNgine.utils.logger import format_exception_for_log

    logger.log_line("[SCAN]", "START", "task=cert_intel scan_id=%s" % scan_history_id)

    try:
        from startScan.models import ScanHistory
        scan = ScanHistory.objects.select_related("domain").get(id=scan_history_id)

        # Sanitize domain name: allow only alphanumeric, hyphens, and dots (Rule 1.4).
        raw_domain = scan.domain.name or ""
        safe_domain = re.sub(r"[^a-zA-Z0-9.\-]", "_", raw_domain)

        # Build path, then verify it stays within RENGINE_RESULTS (Rule 1.2).
        base = os.path.realpath(RENGINE_RESULTS)
        candidate = os.path.join(RENGINE_RESULTS, "%s_%s" % (safe_domain, scan_history_id))
        results_dir = os.path.realpath(candidate)
        if not results_dir.startswith(base + os.sep) and results_dir != base:
            raise ValueError(
                "cert_intel results_dir escapes RENGINE_RESULTS: %s" % results_dir
            )

        activity.heartbeat("cert_intel: starting tlsx for scan_id=%s" % scan_history_id)
        os.makedirs(results_dir, exist_ok=True)
        certs = run_certificate_intel(scan_history_id, results_dir)
        activity.heartbeat("cert_intel: tlsx complete, certs=%d" % len(certs))

        logger.log_line(
            "[SCAN]", "COMPLETE",
            "task=cert_intel scan_id=%s certs=%d" % (scan_history_id, len(certs)),
        )
        return {"status": "ok", "count": len(certs)}
    except Exception as e:
        logger.log_line(
            "[SCAN]", "ERROR",
            "task=cert_intel scan_id=%s error=%s" % (scan_history_id, format_exception_for_log(e)),
            level="error",
        )
        return {"status": "error", "count": 0, "error": format_exception_for_log(e)}


@activity.defn(name="run_identity_infra_activity")
def run_identity_infra_activity(scan_history_id: int, job_id: str = None) -> dict:
    """
    Detect identity infrastructure (ADFS, OWA, Exchange, LDAP, SSO) from existing
    scan data. No tool subprocess — reads only from PostgreSQL.
    Must run before APME so ingest_identity_infra() has data to read.
    """
    from reNgine.tasks.identity import run_identity_intel
    from reNgine.utils.logger import format_exception_for_log

    logger.log_line("[SCAN]", "START", "task=identity_infra scan_id=%s" % scan_history_id)

    try:
        records = run_identity_intel(scan_history_id)
        logger.log_line(
            "[SCAN]", "COMPLETE",
            "task=identity_infra scan_id=%s records=%d" % (scan_history_id, len(records)),
        )
        return {"status": "ok", "count": len(records)}
    except Exception as e:
        logger.log_line(
            "[SCAN]", "ERROR",
            "task=identity_infra scan_id=%s error=%s" % (scan_history_id, format_exception_for_log(e)),
            level="error",
        )
        return {"status": "error", "count": 0, "error": format_exception_for_log(e)}


@activity.defn(name="run_api_intel_activity")
def run_api_intel_activity(scan_history_id: int, job_id: str = None) -> dict:
    """
    Cluster EndPoint records into APIIntelligenceProfile records.
    No tool subprocess — reads only from PostgreSQL.
    Must run before APME so ingest_api_intelligence() has profiles to read.
    """
    from apme.ingestion.api_intelligence import collect_api_intelligence
    from reNgine.utils.logger import format_exception_for_log

    logger.log_line("[SCAN]", "START", "task=api_intel scan_id=%s" % scan_history_id)
    try:
        profiles = collect_api_intelligence(scan_history_id)
        logger.log_line(
            "[SCAN]", "COMPLETE",
            "task=api_intel scan_id=%s profiles=%d" % (scan_history_id, len(profiles)),
        )
        return {"status": "ok", "count": len(profiles)}
    except Exception as e:
        logger.log_line(
            "[SCAN]", "ERROR",
            "task=api_intel scan_id=%s error=%s" % (scan_history_id, format_exception_for_log(e)),
            level="error",
        )
        return {"status": "error", "count": 0}


@activity.defn(name="EnrichIdentitiesActivity")
@keep_alive
def enrich_identities_activity(identity: str, identity_type: str, scan_history_id: int, ctx: dict) -> str:
    from reNgine.tasks.osint import enrich_identities_task
    logger.log_line("[TEMPORAL]", "START", "task=enrich_identities type=%s scan_id=%s" % (identity_type, scan_history_id))
    activity.logger.info("[EnrichIdentitiesActivity] identity_type=%s scan_id=%s", identity_type, scan_history_id)
    # Run synchronously inside the Django threadpool executor worker
    result = enrich_identities_task(identity, identity_type, scan_history_id, ctx)
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=enrich_identities type=%s scan_id=%s" % (identity_type, scan_history_id))
    return result


@activity.defn(name="GeoLocalizeActivity")
def geo_localize_activity(host: str, ip_id: int, scan_id: int = None, activity_id: int = None) -> None:
    from reNgine.tasks import geo_localize
    logger.log_line("[TEMPORAL]", "START", "task=geo_localize host=%s ip_id=%s scan_id=%s" % (host, ip_id, scan_id))
    activity.logger.info("[GeoLocalizeActivity] host=%s ip_id=%s scan_id=%s", host, ip_id, scan_id)
    geo_localize(host, ip_id=ip_id, scan_id=scan_id, activity_id=activity_id)
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=geo_localize host=%s ip_id=%s scan_id=%s" % (host, ip_id, scan_id))


@activity.defn(name="resync_certificate_activity")
def resync_certificate_activity(cert_id: int, job_id: str = None) -> dict:
    """
    Re-probe a single CertificateIntelligence record's host via tlsx.

    Called by CertificateResyncWorkflow in response to mobile resync requests.
    Idempotent: re-running produces at most one DB write per tlsx result line.
    """
    from reNgine.tasks.certificate import resync_single_certificate
    from reNgine.utils.logger import format_exception_for_log

    logger.log_line("[SCAN]", "START", "task=cert_resync cert_id=%s" % cert_id)

    try:
        activity.heartbeat("cert_resync: probing cert_id=%s" % cert_id)
        result = resync_single_certificate(cert_id)
        activity.heartbeat("cert_resync: complete cert_id=%s" % cert_id)

        if result is None:
            logger.log_line(
                "[SCAN]", "COMPLETE",
                "task=cert_resync cert_id=%s result=no_data" % cert_id,
            )
            return {"status": "ok", "updated": False}

        logger.log_line(
            "[SCAN]", "COMPLETE",
            "task=cert_resync cert_id=%s result=updated" % cert_id,
        )
        return {"status": "ok", "updated": True}

    except Exception as e:
        logger.log_line(
            "[SCAN]", "ERROR",
            "task=cert_resync cert_id=%s error=%s" % (cert_id, format_exception_for_log(e)),
            level="error",
            exc_info=True,
        )
        raise


# ---------------------------------------------------------------------------
# Email Security Activity
# ---------------------------------------------------------------------------

@activity.defn(name="RunEmailSecurityActivity")
def run_email_security_activity(ctx: dict) -> dict:
    """Perform email/SMTP security checks (SPF, DMARC, DKIM, relay, STARTTLS, mailbox verify).

    Runs as a sync activity so Temporal places it in a thread.  A background
    heartbeat thread (copy_context pattern, same as _run_task) sends heartbeats
    every 30 s so the heartbeat_timeout is never tripped by slow swaks /
    check_if_email_exists subprocesses.
    """
    import contextvars
    import time
    import threading
    from temporalio.exceptions import CancelledError as TemporalCancelledError

    scan_id = ctx.get('scan_history_id')
    try:
        workflow_id = activity.info().workflow_id
    except Exception:
        workflow_id = '?'

    _activity_ctx = contextvars.copy_context()
    activity_running = True

    def _heartbeat_loop():
        def _do():
            while activity_running:
                try:
                    activity.heartbeat('email_security running scan_id=%s' % scan_id)
                    logger.log_line(
                        "[TEMPORAL]", "HEARTBEAT",
                        "activity_type=email_security workflow_id=%s scan_id=%s" % (workflow_id, scan_id),
                    )
                except TemporalCancelledError:
                    _cd = activity.cancellation_details()
                    if _cd and _cd.paused:
                        logger.warning('[EMAIL_SECURITY] Activity paused by Temporal for scan_id=%s (will retry when unpaused)', scan_id)
                    else:
                        logger.warning('[EMAIL_SECURITY] Temporal cancellation received for scan_id=%s', scan_id)
                    return
                except Exception as hb_err:
                    logger.log_line(
                        "[TEMPORAL]", "HEARTBEAT_FAIL",
                        "activity_type=email_security workflow_id=%s scan_id=%s error=%s" % (
                            workflow_id, scan_id, hb_err),
                        level="warning",
                    )
                for _ in range(6):  # 6 × 5 s = 30 s, checks flag each tick
                    if not activity_running:
                        break
                    time.sleep(5)
        _activity_ctx.run(_do)

    hb_thread = threading.Thread(target=_heartbeat_loop, daemon=True)
    hb_thread.start()
    try:
        result = _run_email_security_sync(ctx)
        logger.log_line("[TEMPORAL]", "COMPLETE", "task=email_security scan_id=%s" % scan_id)
        return result
    except Exception as exc:
        logger.log_line(
            "[TEMPORAL]", "ERROR",
            "task=email_security scan_id=%s error=%s" % (scan_id, format_exception_for_log(exc)),
            level="error",
        )
        raise
    finally:
        activity_running = False
        hb_thread.join(timeout=5)


def _run_email_security_sync(ctx: dict) -> dict:
    """Synchronous implementation of email security checks."""
    from reNgine.common_func import save_vulnerability
    from startScan.models import ScanHistory, Subdomain
    from reNgine.tasks.email_security import (
        check_spf, check_dmarc, check_dkim, assess_spoofability,
        swaks_relay_test, swaks_starttls_check,
        check_ssl_cert, SMTP_PORTS,
    )
    from reNgine.tasks.email_verification import (
        verify_domain_mailboxes,
        parse_mailbox_config,
        ACTIVITY_START_TO_CLOSE_SECONDS,
    )
    from reNgine.definitions import SUCCESS_TASK, FAILED_TASK, ABORTED_TASK
    from reNgine.task_plan import email_security_enabled
    from django.db.models import Q
    import time

    started = time.monotonic()

    scan_id: int = ctx.get('scan_history_id')
    domain_name: str = ctx.get('domain_name') or ctx.get('domain', '')
    logger.info('[EMAIL_SECURITY] START scan_id=%s domain=%s', scan_id, domain_name)

    if not email_security_enabled(ctx.get('yaml_configuration')):
        # Turned off in the engine config. Checked here rather than in the
        # workflow: the workflow schedules this activity whenever port_scan is
        # in the task list, and adding a branch there would change the command
        # sequence and need a workflow.patched() guard for in-flight scans.
        logger.info('[EMAIL_SECURITY] disabled in engine config — skipping | scan_id=%s', scan_id)
        return {
            'findings_count': 0,
            'smtp_hosts_checked': 0,
            'mailboxes_confirmed': 0,
            'mailboxes_checked': 0,
            'skipped': 'disabled',
        }

    scan = ScanHistory.objects.select_related('domain').get(pk=scan_id)
    if not domain_name:
        domain_name = scan.domain.name

    yaml_cfg = ctx.get('yaml_configuration') or {}
    mailbox_proxy = None
    if parse_mailbox_config(yaml_cfg).get('enabled', True):
        mailbox_proxy = _start_scan_task_proxy(
            ctx, 'check_if_email_exists', 'Mailbox Verification',
        )

    mailbox_status = SUCCESS_TASK
    mailbox_error = None

    findings_count: int = 0

    def _vuln(name: str, severity: int, description: str, url: str = None) -> None:
        nonlocal findings_count
        try:
            save_vulnerability(
                target_domain=scan.domain,
                scan_history=scan,
                name=name,
                severity=severity,
                description=description,
                http_url=url or 'smtp://%s' % domain_name,
                type='SMTP',
                source='email_security',
                dedup_fields=['name', 'http_url', 'scan_history'],
            )
            findings_count += 1
        except Exception as exc:
            logger.error('[EMAIL_SECURITY] save_vulnerability failed for %s: %s', name, exc)

    try:
            # DNS checks (always run against the root domain)
            spf = check_spf(domain_name)
            dmarc = check_dmarc(domain_name)
            dkim = check_dkim(domain_name)

            if not spf['found']:
                _vuln('SPF Record Missing', 3,
                      'No SPF TXT record found for %s.' % domain_name)
            elif spf['weak']:
                _vuln('SPF Weak Policy', 2,
                      'SPF record for %s uses +all or ~all: %s' % (domain_name, spf['record']))

            if not dmarc['found']:
                _vuln('DMARC Record Missing', 3,
                      'No DMARC record found at _dmarc.%s.' % domain_name)
            elif dmarc['policy'] == 'none':
                _vuln('DMARC Policy Not Enforced (p=none)', 2,
                      'DMARC for %s uses p=none — monitoring only.' % domain_name)

            if not dkim['found']:
                _vuln('DKIM Record Missing', 2,
                      'No DKIM record found for %s across common selectors.' % domain_name)

            for spoof in assess_spoofability(spf, dmarc):
                _vuln(spoof['name'], spoof['severity'], spoof['description'])

            # SMTP tool checks — only run if SMTP ports were found during port scan
            try:
                smtp_hosts = list(
                    Subdomain.objects.filter(scan_history_id=scan_id).filter(
                        Q(ip_addresses__ports__number__in=SMTP_PORTS) |
                        Q(ip_addresses__ports__service_name__icontains='smtp')
                    ).values_list('name', 'ip_addresses__address', 'ip_addresses__ports__number')
                    .distinct()
                )
            except Exception as exc:
                logger.error('[EMAIL_SECURITY] DB query failed scan_id=%s: %s', scan_id, exc)
                mailbox_status = FAILED_TASK
                mailbox_error = format_exception_for_log(exc)
                if mailbox_proxy:
                    mailbox_proxy.update_scan_activity(FAILED_TASK, error_message=mailbox_error)
                raise

            checked_pairs: set = set()
            for (subdomain_name, ip_address, port) in smtp_hosts:
                host = subdomain_name or ip_address
                if not host:
                    continue
                pair = (host, port)
                if pair in checked_pairs:
                    continue
                checked_pairs.add(pair)
                host_url = 'smtp://%s:%s' % (host, port)

                relay = swaks_relay_test(host, port, domain_name)
                if relay.get('banner'):
                    _vuln('SMTP Service Banner Disclosure', 0,
                          'SMTP banner on %s:%s: %s' % (host, port, relay['banner']), host_url)
                if relay['open_relay']:
                    _vuln('SMTP Open Relay', 4,
                          'SMTP server at %s:%s accepted a relay attempt.' % (host, port), host_url)

                # Ports 25/587 use opportunistic TLS (STARTTLS) — flag if missing
                if port in (25, 587):
                    tls = swaks_starttls_check(host, port)
                    if not tls['starttls_supported']:
                        _vuln('STARTTLS Not Supported', 3,
                              'SMTP at %s:%s did not advertise STARTTLS.' % (host, port), host_url)

                # Ports 465/993 use implicit TLS (SMTPS/IMAPS) — verify certificate validity
                if port in (465, 993):
                    cert = check_ssl_cert(host, port)
                    if not cert['connected']:
                        _vuln(
                            'Port %d Not Responding to TLS Handshake' % port, 2,
                            'Port %s on %s is expected to use implicit TLS (SMTPS/IMAPS) '
                            'but did not complete the SSL handshake.' % (port, host),
                            host_url,
                        )
                    else:
                        if cert['expired']:
                            _vuln(
                                'Expired SSL/TLS Certificate on SMTP', 3,
                                'The SSL/TLS certificate on %s:%s has expired.' % (host, port),
                                host_url,
                            )
                        if cert['self_signed']:
                            _vuln(
                                'Self-Signed SSL/TLS Certificate on SMTP', 2,
                                'The certificate on %s:%s is self-signed and will not be '
                                'trusted by mail clients.' % (host, port),
                                host_url,
                            )
                        if cert['hostname_mismatch']:
                            _vuln(
                                'SSL/TLS Certificate Hostname Mismatch on SMTP', 3,
                                'The certificate on %s:%s does not match the hostname. '
                                'Clients may refuse the connection.' % (host, port),
                                host_url,
                            )
                        days = cert.get('days_until_expiry')
                        if days is not None and 0 <= days < 30 and not cert['expired']:
                            _vuln(
                                'SSL/TLS Certificate Expiring Soon on SMTP', 1,
                                'The certificate on %s:%s expires in %d day(s). '
                                'Renew before it causes delivery failures.' % (host, port, days),
                                host_url,
                            )

    except Exception as exc:
        logger.error('[EMAIL_SECURITY] pre-mailbox failed scan_id=%s: %s', scan_id, exc)
        mailbox_status = FAILED_TASK
        mailbox_error = format_exception_for_log(exc)
        if mailbox_proxy:
            mailbox_proxy.update_scan_activity(FAILED_TASK, error_message=mailbox_error)
        raise

    proxy_url = None
    try:
        from reNgine.common_func import get_random_proxy
        # Reacher SMTP verify is SOCKS5-only (--proxy-host on the CLI).
        proxy_url = get_random_proxy(socks5_only=True) or None
    except Exception:
        proxy_url = None
    mailbox = {'confirmed': [], 'checked': 0}
    try:
        remaining = ACTIVITY_START_TO_CLOSE_SECONDS - (time.monotonic() - started)
        mailbox = verify_domain_mailboxes(
            domain_name, scan, yaml_cfg, proxy_url=proxy_url,
            remaining_seconds=remaining,
            activity_id=getattr(mailbox_proxy, 'activity_id', None),
        )
        for finding in mailbox.get('findings') or []:
            _vuln(finding['name'], finding['severity'], finding['description'])
        skipped = mailbox.get('skipped_reason')
        if skipped:
            mailbox_status = ABORTED_TASK
            mailbox_error = skipped
    except Exception as exc:
        logger.error('[EMAIL_SECURITY] mailbox verification failed scan_id=%s: %s', scan_id, exc)
        mailbox_status = FAILED_TASK
        mailbox_error = format_exception_for_log(exc)

    if mailbox_proxy:
        mailbox_proxy.update_scan_activity(mailbox_status, error_message=mailbox_error)

    logger.info('[EMAIL_SECURITY] COMPLETE scan_id=%s findings=%d', scan_id, findings_count)
    return {
        'findings_count': findings_count,
        'smtp_hosts_checked': len(checked_pairs),
        'mailboxes_confirmed': len(mailbox.get('confirmed') or []),
        'mailboxes_checked': mailbox.get('checked') or 0,
    }
