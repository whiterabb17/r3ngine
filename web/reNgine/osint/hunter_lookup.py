import logging
from typing import Optional
from urllib.parse import quote

import requests

from reNgine.utils.task import save_email, save_employee
from startScan.models import ScanHistory

logger = logging.getLogger(__name__)

_HUNTER_BASE = "https://api.hunter.io/v2"
_TIMEOUT = 10
_PAGE_SIZE = 100


class HunterQuotaExhausted(Exception):
    """Raised when the Hunter.io API quota is exhausted (HTTP 429)."""


def _hunter_domain_search(
    api_key: str,
    domain: str,
    max_results: int = 500,
) -> tuple[list[dict], str]:
    """Paginate Hunter.io domain-search.

    Returns:
        (emails, pattern) — flat list of raw email dicts and the domain
        email pattern string. Returns ([], "") on auth failure.
    """
    collected: list[dict] = []
    pattern: str = ""
    offset = 0

    while len(collected) < max_results:
        limit = min(_PAGE_SIZE, max_results - len(collected))
        url = (
            f"{_HUNTER_BASE}/domain-search"
            f"?domain={quote(domain)}&api_key={api_key}"
            f"&limit={limit}&offset={offset}"
        )
        try:
            response = requests.get(url, timeout=_TIMEOUT)
        except requests.exceptions.RequestException as exc:
            logger.warning(
                "[HUNTER] Network error during domain-search for %s: %s",
                domain,
                type(exc).__name__,
            )
            break

        if response.status_code == 401:
            logger.error("[HUNTER] Unauthorized — invalid API key")
            return [], ""

        if not response.ok:
            logger.error(
                "[HUNTER] domain-search returned HTTP %s for %s",
                response.status_code,
                domain,
            )
            break

        try:
            body = response.json()
        except ValueError:
            logger.error(
                "[HUNTER] Malformed JSON from domain-search (HTTP %s)",
                response.status_code,
            )
            break

        page_data = body.get("data", {})

        if offset == 0:
            pattern = page_data.get("pattern") or ""

        page_emails: list[dict] = page_data.get("emails", [])
        if not page_emails:
            break

        collected.extend(page_emails)

        total: int = body.get("meta", {}).get("total", 0)
        if total == 0 or len(collected) >= total:
            break

        offset += len(page_emails)

    logger.info(
        "[HUNTER] domain-search complete: %d emails fetched for %s",
        len(collected),
        domain,
    )
    return collected, pattern


def _hunter_email_finder(
    api_key: str,
    domain: str,
    first_name: str,
    last_name: str,
) -> Optional[dict]:
    """Call Hunter.io email-finder for a specific person.

    Returns:
        Hunter data dict on success, None on 404 or non-fatal errors.

    Raises:
        HunterQuotaExhausted: on 429 or usage_limit error code in body.
    """
    url = (
        f"{_HUNTER_BASE}/email-finder"
        f"?domain={quote(domain)}"
        f"&first_name={quote(first_name)}"
        f"&last_name={quote(last_name)}"
        f"&api_key={api_key}"
    )
    try:
        response = requests.get(url, timeout=_TIMEOUT)
    except requests.exceptions.RequestException as exc:
        logger.warning(
            "[HUNTER] Network error during email-finder for %s %s: %s",
            first_name, last_name, type(exc).__name__,
        )
        return None

    if response.status_code == 404:
        return None

    if response.status_code == 429:
        raise HunterQuotaExhausted("Hunter.io email-finder quota exhausted (HTTP 429)")

    if not response.ok:
        logger.warning(
            "[HUNTER] email-finder returned HTTP %s for %s %s",
            response.status_code, first_name, last_name,
        )
        return None

    try:
        body = response.json()
    except ValueError:
        logger.error("[HUNTER] Malformed JSON from email-finder (HTTP %s)", response.status_code)
        return None

    for error in body.get("errors", []):
        if error.get("code") == "usage_limit":
            raise HunterQuotaExhausted("Hunter.io email-finder quota exhausted (usage_limit)")

    data = body.get("data", {})
    if not data.get("email"):
        return None

    return data


_TITLE_WORDS = {"dr", "mr", "mrs", "ms", "prof", "sr", "jr", "ii", "iii", "iv"}


def run_hunter_lookup(domain: str, scan_history_id: int, api_key: str) -> dict:
    """Discover emails via Hunter.io domain-search then enrich employees via email-finder.

    Phase 1 — domain-search: fetches all known emails for the domain and saves
    each one with Hunter metadata in email.metadata['hunter'].

    Phase 2 — email-finder: iterates employees already on the scan (from
    theHarvester/LinkedIn) and resolves their email. Stops on quota exhaustion
    but retains Phase 1 results.

    Returns:
        dict with keys: emails (int saved), employees (int saved), skipped (bool).
    """
    if not api_key:
        logger.info("[HUNTER] No API key — skipping Hunter lookup for %s", domain)
        return {"emails": 0, "employees": 0, "skipped": True}

    scan_history = ScanHistory.objects.get(pk=scan_history_id)
    email_count = 0
    employee_count = 0

    # Phase 1: domain-search
    logger.info("[HUNTER] Phase 1: domain-search for %s", domain)
    domain_emails, _ = _hunter_domain_search(api_key, domain)

    for entry in domain_emails:
        address = (entry.get("value") or "").strip().lower()
        if not address:
            continue

        email, _ = save_email(address, scan_history=scan_history)
        if email:
            existing = email.metadata or {}
            existing["hunter"] = {
                "confidence": entry.get("confidence"),
                "type": entry.get("type"),
                "position": entry.get("position"),
                "department": entry.get("department"),
                "source": "domain_search",
            }
            email.metadata = existing
            email.save(update_fields=["metadata"])
            email_count += 1

        first = (entry.get("first_name") or "").strip()
        last = (entry.get("last_name") or "").strip()
        if first and last:
            emp, created = save_employee(
                f"{first} {last}",
                scan_history=scan_history,
            )
            if emp and entry.get("position"):
                emp.designation = entry["position"]
                emp.save(update_fields=["designation"])
            if created:
                employee_count += 1

    logger.info(
        "[HUNTER] Phase 1 complete: %d emails, %d employees for %s",
        email_count, employee_count, domain,
    )

    # Phase 2: email-finder for employees without a resolved email
    logger.info("[HUNTER] Phase 2: email-finder for %s", domain)
    quota_exhausted = False

    for employee in scan_history.employees.all():
        if quota_exhausted:
            break

        name = (employee.name or "").strip()
        parts = [p for p in name.split() if p.lower().rstrip(".") not in _TITLE_WORDS]
        if len(parts) < 2:
            continue

        first_name = parts[0]
        last_name = parts[-1]

        try:
            result = _hunter_email_finder(api_key, domain, first_name, last_name)
        except HunterQuotaExhausted:
            logger.warning("[HUNTER] email-finder quota exhausted, stopping Phase 2")
            quota_exhausted = True
            break

        if not result:
            continue

        address = (result.get("email") or "").strip().lower()
        if not address:
            continue

        email, _ = save_email(address, scan_history=scan_history)
        if email:
            existing = email.metadata or {}
            existing["hunter"] = {
                "confidence": result.get("score"),
                "type": result.get("type"),
                "position": result.get("position"),
                "department": result.get("department"),
                "source": "email_finder",
            }
            email.metadata = existing
            email.save(update_fields=["metadata"])
            email_count += 1

    logger.info(
        "[HUNTER] Phase 2 complete for %s (quota_exhausted=%s)", domain, quota_exhausted,
    )
    return {"emails": email_count, "employees": employee_count, "skipped": False}
