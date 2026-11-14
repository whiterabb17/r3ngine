"""Email security scanning functions — SPF, DMARC, DKIM, SMTP relay, STARTTLS, certs."""
import logging
import re
import time
from reNgine.utils.task import run_command

logger = logging.getLogger(__name__)

SMTP_PORTS = [25, 587, 465, 993]
DKIM_SELECTORS = ['default', 'google', 'mail', 'email', 'selector1', 'selector2', 'k1', 's1']

# Transient DNS failures must not be treated as "record missing" (scan FP source).
_DNS_RETRY_ATTEMPTS = 3
_DNS_RETRY_SLEEP_SECONDS = 0.4

_TXT_CHUNK_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')


def _decode_txt_rdata(rdata) -> str:
    """Join multi-string TXT rdata into one decoded string.

    DNS TXT RRs may split a single logical record across character-strings.
    Using str(rdata).strip('\"') leaves mid-record quotes and can miss matches.
    """
    strings = getattr(rdata, 'strings', None)
    if strings is not None:
        parts = []
        for chunk in strings:
            if isinstance(chunk, bytes):
                parts.append(chunk.decode('utf-8', errors='replace'))
            else:
                parts.append(str(chunk))
        return ''.join(parts).strip()

    text = rdata.to_text() if hasattr(rdata, 'to_text') else str(rdata)
    chunks = _TXT_CHUNK_RE.findall(text)
    if chunks:
        return ''.join(c.replace('\\"', '"') for c in chunks).strip()
    return text.strip().strip('"').strip()


def _is_transient_dns_error(exc: BaseException) -> bool:
    import dns.exception
    import dns.resolver

    if isinstance(exc, (dns.exception.Timeout, dns.resolver.NoNameservers)):
        return True
    # SERVFAIL / REFUSED / FormError etc. — inconclusive, not "missing"
    if isinstance(exc, dns.exception.DNSException) and not isinstance(
        exc, (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.YXDOMAIN)
    ):
        return True
    return False


def _resolve_txt(name: str, lifetime: float = 10):
    """Resolve TXT with retries. Raises last DNSException if all attempts fail."""
    import dns.resolver
    import dns.exception

    last_exc: BaseException | None = None
    for attempt in range(_DNS_RETRY_ATTEMPTS):
        try:
            return dns.resolver.resolve(name, 'TXT', lifetime=lifetime)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as exc:
            # Confirmed absence — do not retry
            raise exc
        except Exception as exc:
            last_exc = exc
            if _is_transient_dns_error(exc) and attempt < _DNS_RETRY_ATTEMPTS - 1:
                time.sleep(_DNS_RETRY_SLEEP_SECONDS * (attempt + 1))
                continue
            raise
    assert last_exc is not None
    raise last_exc


def check_spf(domain: str) -> dict:
    """Query SPF TXT record for domain.

    Returns:
        {
            "found": bool,
            "record": str | None,
            "weak": bool,   # True if +all or ~all
            "lookup_ok": bool,  # False when DNS was inconclusive (do not raise Missing)
        }
    """
    result: dict = {"found": False, "record": None, "weak": False, "lookup_ok": False}
    try:
        answers = _resolve_txt(domain)
        result["lookup_ok"] = True
        for rdata in answers:
            txt = _decode_txt_rdata(rdata)
            if txt.lower().startswith('v=spf1'):
                result["found"] = True
                result["record"] = txt
                result["weak"] = ('+all' in txt or '~all' in txt)
                break
    except Exception as e:
        import dns.resolver
        if isinstance(e, (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer)):
            # Domain has no TXT / does not exist — confirmed absence
            result["lookup_ok"] = True
        else:
            logger.warning("[check_spf] inconclusive for %s: %s", domain, e)
    return result


def check_dmarc(domain: str) -> dict:
    """Query DMARC TXT record at _dmarc.{domain}.

    Returns:
        {
            "found": bool,
            "record": str | None,
            "policy": str | None,   # "none", "quarantine", "reject"
            "lookup_ok": bool,
        }
    """
    result: dict = {"found": False, "record": None, "policy": None, "lookup_ok": False}
    try:
        answers = _resolve_txt(f'_dmarc.{domain}')
        result["lookup_ok"] = True
        for rdata in answers:
            txt = _decode_txt_rdata(rdata)
            if 'v=dmarc1' in txt.lower().replace(' ', ''):
                result["found"] = True
                result["record"] = txt
                for part in txt.split(';'):
                    part = part.strip()
                    if part.lower().startswith('p='):
                        result["policy"] = part.split('=', 1)[1].strip().lower()
                break
    except Exception as e:
        import dns.resolver
        if isinstance(e, (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer)):
            result["lookup_ok"] = True
        else:
            logger.warning("[check_dmarc] inconclusive for _dmarc.%s: %s", domain, e)
    return result


def check_dkim(domain: str) -> dict:
    """Probe common DKIM selectors at {selector}._domainkey.{domain}.

    Returns:
        {
            "found": bool,
            "selector": str | None,
            "record": str | None,
            "lookup_ok": bool,  # True if at least one selector was conclusively checked
        }
    """
    import dns.resolver

    any_conclusive = False
    saw_transient = False

    for selector in DKIM_SELECTORS:
        name = f'{selector}._domainkey.{domain}'
        try:
            answers = _resolve_txt(name)
            any_conclusive = True
            for rdata in answers:
                txt = _decode_txt_rdata(rdata)
                if 'v=DKIM1' in txt.upper() or 'p=' in txt:
                    return {
                        "found": True,
                        "selector": selector,
                        "record": txt,
                        "lookup_ok": True,
                    }
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            any_conclusive = True
            continue
        except Exception as e:
            saw_transient = True
            logger.debug("[check_dkim] %s: %s", name, e)
            continue

    # Found nothing. Only claim "missing" when at least one selector was
    # conclusively checked. All-timeout runs must not raise DKIM Missing.
    if saw_transient and not any_conclusive:
        logger.warning("[check_dkim] inconclusive for %s (all selectors transient)", domain)
    return {
        "found": False,
        "selector": None,
        "record": None,
        "lookup_ok": any_conclusive,
    }


def assess_spoofability(spf: dict, dmarc: dict) -> list:
    """Return list of spoofability findings based on SPF and DMARC results.

    Each finding: {"name": str, "severity": int, "description": str}

    Skips findings when either DNS lookup was inconclusive — otherwise transient
    resolver failures become High "Direct Email Spoofing Feasible" FPs.
    """
    findings: list = []

    # Default lookup_ok=True for callers/tests that omit the key
    if not spf.get("lookup_ok", True) or not dmarc.get("lookup_ok", True):
        return findings

    no_spf = not spf["found"]
    weak_spf = spf["found"] and spf["weak"]
    no_dmarc = not dmarc["found"]
    dmarc_none = dmarc["found"] and dmarc["policy"] == "none"

    if no_spf and no_dmarc:
        findings.append({
            "name": "Direct Email Spoofing Feasible",
            "severity": 3,
            "description": (
                "No SPF or DMARC records exist for this domain. An attacker can send "
                "email appearing to come from this domain with no technical barrier. "
                "This enables phishing, fraud, and reputational damage."
            ),
        })
    elif weak_spf and (no_dmarc or dmarc_none):
        findings.append({
            "name": "Email Spoofing via SPF Bypass Feasible",
            "severity": 2,
            "description": (
                "SPF policy uses a permissive qualifier (%s) "
                "and DMARC is either absent or set to p=none. Spoofed messages "
                "may still reach recipients." % spf['record']
            ),
        })
    return findings


def dmarc_is_enforcing(dmarc: dict) -> bool:
    """True when DMARC was conclusively found with quarantine or reject."""
    if not dmarc.get("lookup_ok", True) or not dmarc.get("found"):
        return False
    return dmarc.get("policy") in ("reject", "quarantine")


def swaks_relay_test(host: str, port: int, domain: str, timeout: int = 20) -> dict:
    """Test for SMTP open relay using swaks.

    Attempts to send a probe to an external address from a domain-spoofed sender.
    Returns {"open_relay": bool, "banner": str | None, "raw": str}
    """
    cmd = [
        'swaks',
        '--to', 'probe@relay-test-probe.invalid',
        '--from', 'probe@%s' % domain,
        '--server', host,
        '--port', str(port),
        '--quit-after', 'RCPT',
        '--hide-all',
        '--timeout', str(timeout),
    ]
    result: dict = {"open_relay": False, "banner": None, "raw": ""}
    try:
        return_code, output = run_command(cmd, timeout=timeout + 5)
        result["raw"] = output[:2000]

        # swaks exits 0 when RCPT is accepted (--quit-after RCPT), meaning relay allowed
        result["open_relay"] = return_code == 0
        for line in output.splitlines():
            if '<-' in line and '220' in line and result["banner"] is None:
                result["banner"] = line.split('<-', 1)[-1].strip()[:200]
    except Exception as e:
        logger.debug("[swaks_relay_test] %s:%s: %s", host, port, e)
    return result


def check_ssl_cert(host: str, port: int, timeout: int = 10) -> dict:
    """Verify the SSL/TLS certificate on an implicit-TLS port (465 SMTPS, 993 IMAPS).

    Returns:
        {
            "connected": bool,         # True if TLS handshake completed
            "expired": bool,
            "self_signed": bool,
            "hostname_mismatch": bool,
            "days_until_expiry": int | None,
            "subject_cn": str | None,
            "issuer": str | None,
        }
    """
    import ssl
    import socket
    import datetime

    result: dict = {
        "connected": False,
        "expired": False,
        "self_signed": False,
        "hostname_mismatch": False,
        "days_until_expiry": None,
        "subject_cn": None,
        "issuer": None,
    }

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                result["connected"] = True
                cert = ssock.getpeercert()
                subject = dict(x[0] for x in cert.get('subject', []))
                result["subject_cn"] = subject.get('commonName')
                issuer_dict = dict(x[0] for x in cert.get('issuer', []))
                result["issuer"] = issuer_dict.get('organizationName') or issuer_dict.get('commonName')
                not_after = cert.get('notAfter')
                if not_after:
                    expiry = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    delta = expiry - datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
                    result["days_until_expiry"] = delta.days
                    result["expired"] = delta.days < 0
                result["self_signed"] = cert.get('issuer') == cert.get('subject')
    except ssl.SSLCertVerificationError as e:
        result["connected"] = True
        msg = str(e).lower()
        if 'self signed' in msg or 'self-signed' in msg:
            result["self_signed"] = True
        elif 'hostname' in msg or "doesn't match" in msg:
            result["hostname_mismatch"] = True
        else:
            result["expired"] = True
    except Exception as e:
        logger.debug("[check_ssl_cert] %s:%s: %s", host, port, e)

    return result


def swaks_starttls_check(host: str, port: int, timeout: int = 15) -> dict:
    """Check whether STARTTLS is advertised in SMTP EHLO response.

    Returns {"starttls_supported": bool, "ehlo_raw": str}
    """
    cmd = [
        'swaks',
        '--server', host,
        '--port', str(port),
        '--quit-after', 'EHLO',
        '--hide-all',
        '--timeout', str(timeout),
    ]
    result: dict = {"starttls_supported": False, "ehlo_raw": ""}
    try:
        return_code, output = run_command(cmd, timeout=timeout + 5)
        result["ehlo_raw"] = output[:2000]
        result["starttls_supported"] = 'STARTTLS' in output.upper()
    except Exception as e:
        logger.debug("[swaks_starttls_check] %s:%s: %s", host, port, e)
    return result
