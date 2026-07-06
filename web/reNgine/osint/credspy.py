import csv
import logging
import os
import subprocess
from typing import TYPE_CHECKING

from reNgine.common_func import get_random_proxy
from startScan.models import CredResult, DnsRecord, Subdomain

if TYPE_CHECKING:
    from startScan.models import ScanHistory

logger = logging.getLogger(__name__)


def is_microsoft_email_provider(scan_history_id: int) -> bool:
    """Return True if Microsoft is likely the email provider for this scan."""
    mx_microsoft = DnsRecord.objects.filter(
        scan_history_id=scan_history_id,
        record_type='MX',
        value__icontains='microsoft',
    ).exists()
    mx_outlook = DnsRecord.objects.filter(
        scan_history_id=scan_history_id,
        record_type='MX',
        value__icontains='outlook',
    ).exists()
    autodiscover = Subdomain.objects.filter(
        scan_history_id=scan_history_id,
        name__icontains='autodiscover',
    ).exists()
    return mx_microsoft or mx_outlook or autodiscover


def _get_csv_path(results_dir: str) -> str:
    return os.path.join(results_dir, 'credspy_output.csv')


def run_credspy(
    self,
    host: str,
    scan_history: 'ScanHistory',
    results_dir: str,
) -> int:
    """Run CredSpy against all scan emails. Requires a configured proxy (contacts Microsoft
    auth endpoints — running without a proxy exposes the operator's IP).

    Skips if: no proxy configured, no Microsoft MX records detected, or no emails found.
    Returns the number of CredResult rows created.
    """
    logger.info("run_credspy | START | host=%s scan_id=%s", host, scan_history.id)

    # Proxy is mandatory — CredSpy contacts Microsoft authentication endpoints
    proxy_url = get_random_proxy()
    if not proxy_url:
        logger.warning(
            "run_credspy | SKIP | no proxy configured — skipping to protect operator IP (scan_id=%s)",
            scan_history.id,
        )
        return 0

    if not is_microsoft_email_provider(scan_history.id):
        logger.info(
            "run_credspy | SKIP | no Microsoft MX records detected for scan_id=%s",
            scan_history.id,
        )
        return 0

    emails = list(scan_history.emails.values_list('address', flat=True))
    if not emails:
        logger.warning("run_credspy | SKIP | no emails for scan_id=%s", scan_history.id)
        return 0

    emails_file = os.path.join(results_dir, 'credspy_emails.txt')
    with open(emails_file, 'w') as fh:
        fh.write('\n'.join(emails))

    csv_path = _get_csv_path(results_dir)
    cmd = ['credspy', emails_file, '--csv', csv_path, '--proxy', proxy_url]

    try:
        result = subprocess.run(cmd, capture_output=True, timeout=300)
        if result.returncode != 0:
            logger.error(
                "run_credspy | ERROR | credspy returned %d: %s",
                result.returncode, result.stderr.decode('utf-8', errors='replace'),
            )
            return 0
    except Exception as exc:
        logger.error("run_credspy | ERROR | %s", exc, exc_info=True)
        return 0

    created_count = _parse_credspy_csv(csv_path, scan_history)

    logger.info(
        "run_credspy | COMPLETE | scan_id=%s results_created=%d",
        scan_history.id, created_count,
    )
    return created_count


def _parse_credspy_csv(csv_path: str, scan_history: 'ScanHistory') -> int:
    """Parse credspy CSV output and create CredResult rows."""
    if not os.path.exists(csv_path):
        logger.warning("run_credspy | WARN | CSV output not found at %s", csv_path)
        return 0

    created = 0
    with open(csv_path, newline='') as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            email_address = (row.get('Email') or '').strip()
            if not email_address:
                continue
            CredResult.objects.create(
                scan_history=scan_history,
                email_address=email_address,
                tool_name='credspy',
                account_exists=_to_bool(row.get('Exists')),
                exposure_type=(row.get('PreferredType') or '').strip() or None,
                has_password=_to_bool(row.get('HasPassword')),
                remote_ngc=_to_bool(row.get('RemoteNGC')),
                has_fido=_to_bool(row.get('HasFido')),
                has_cert_auth=_to_bool(row.get('HasCertAuth')),
                domain_type=(row.get('DomainType') or '').strip() or None,
                raw_data=dict(row),
            )
            created += 1
    return created


def _to_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    v = value.strip().lower()
    if v in ('true', '1', 'yes'):
        return True
    if v in ('false', '0', 'no'):
        return False
    return None
