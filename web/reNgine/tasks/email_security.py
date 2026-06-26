"""Email security scanning functions — SPF, DMARC, DKIM, SMTP relay, STARTTLS, user enum."""
import logging
import os
import subprocess
from reNgine.utils.task import run_command

logger = logging.getLogger(__name__)

SMTP_PORTS = [25, 587, 465, 993]
DKIM_SELECTORS = ['default', 'google', 'mail', 'email', 'selector1', 'selector2', 'k1', 's1']


def check_spf(domain: str) -> dict:
    """Query SPF TXT record for domain.

    Returns:
        {
            "found": bool,
            "record": str | None,
            "weak": bool,   # True if +all or ~all
        }
    """
    import dns.resolver
    import dns.exception

    result: dict = {"found": False, "record": None, "weak": False}
    try:
        answers = dns.resolver.resolve(domain, 'TXT', lifetime=10)
        for rdata in answers:
            txt = str(rdata).strip('"')
            if txt.startswith('v=spf1'):
                result["found"] = True
                result["record"] = txt
                result["weak"] = ('+all' in txt or '~all' in txt)
                break
    except (Exception,) as e:
        logger.debug("[check_spf] %s: %s", domain, e)
    return result


def check_dmarc(domain: str) -> dict:
    """Query DMARC TXT record at _dmarc.{domain}.

    Returns:
        {
            "found": bool,
            "record": str | None,
            "policy": str | None,   # "none", "quarantine", "reject"
        }
    """
    import dns.resolver
    import dns.exception

    result: dict = {"found": False, "record": None, "policy": None}
    try:
        answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT', lifetime=10)
        for rdata in answers:
            txt = str(rdata).strip('"')
            if 'v=DMARC1' in txt:
                result["found"] = True
                result["record"] = txt
                for part in txt.split(';'):
                    part = part.strip()
                    if part.lower().startswith('p='):
                        result["policy"] = part.split('=', 1)[1].strip().lower()
                break
    except (Exception,) as e:
        logger.debug("[check_dmarc] _dmarc.%s: %s", domain, e)
    return result


def check_dkim(domain: str) -> dict:
    """Probe common DKIM selectors at {selector}._domainkey.{domain}.

    Returns:
        {
            "found": bool,
            "selector": str | None,
            "record": str | None,
        }
    """
    import dns.resolver
    import dns.exception

    for selector in DKIM_SELECTORS:
        try:
            name = f'{selector}._domainkey.{domain}'
            answers = dns.resolver.resolve(name, 'TXT', lifetime=10)
            for rdata in answers:
                txt = str(rdata).strip('"')
                if 'v=DKIM1' in txt or 'p=' in txt:
                    return {"found": True, "selector": selector, "record": txt}
        except (Exception,):
            continue
    return {"found": False, "selector": None, "record": None}


def assess_spoofability(spf: dict, dmarc: dict) -> list:
    """Return list of spoofability findings based on SPF and DMARC results.

    Each finding: {"name": str, "severity": int, "description": str}
    """
    findings: list = []

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
                    delta = expiry - datetime.datetime.utcnow()
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


SMTP_USERNAMES_WORDLIST = '/usr/src/wordlist/smtp-usernames.txt'


def smtp_user_enum(
    targets: list,
    wordlist: str = SMTP_USERNAMES_WORDLIST,
    method: str = 'VRFY',
    timeout: int = 120,
) -> dict:
    """Run smtp-user-enum against each host:port target individually using -t/-p.

    smtp-user-enum v1.2 documents -T (targets file) but does not register it
    in its getopts string, so -T always produces "Unknown option: T". We run
    one subprocess per target using -t host -p port instead.

    Args:
        targets: list of (host, port) tuples
        wordlist: path to usernames wordlist
        method: VRFY, EXPN, or RCPT
        timeout: seconds per target before killing the process

    Returns:
        {"users_found": {"host:port": [usernames]}, "raw": str}
    """
    if not targets:
        return {"users_found": {}, "raw": ""}

    if not os.path.isfile(wordlist):
        logger.warning("[smtp_user_enum] wordlist not found: %s", wordlist)
        return {"users_found": {}, "raw": ""}

    result: dict = {"users_found": {}, "raw": ""}
    all_raw: list = []

    for host, port in targets:
        host_port = "%s:%s" % (host, port)
        cmd = [
            'smtp-user-enum',
            '-M', method,
            '-U', wordlist,
            '-t', host,
            '-p', str(port),
        ]
        try:
            return_code, output = run_command(cmd, timeout=timeout + 10)
            all_raw.append("=== %s ===\n%s" % (host_port, output[:2000]))

            for line in output.splitlines():
                if 'EXISTS' not in line and '250 ' not in line:
                    continue
                user = line.rsplit(':', 1)[-1].replace('EXISTS', '').strip()
                if user and '@' not in user:
                    result["users_found"].setdefault(host_port, [])
                    if user not in result["users_found"][host_port]:
                        result["users_found"][host_port].append(user)

            if return_code != 0:
                logger.warning(
                    "[smtp_user_enum] %s exited %d: %s",
                    host_port,
                    return_code,
                    output[:200],
                )
        except Exception as e:
            logger.debug("[smtp_user_enum] %s error: %s", host_port, e)

    result["raw"] = "\n".join(all_raw)[:10000]
    return result
