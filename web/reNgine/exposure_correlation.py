import logging
from django.db import transaction
from django.db.models import Prefetch, Q
from startScan.models import (
    Subdomain, EndPoint, Screenshot, Vulnerability,
    Exposure, ExposureEvidence
)

logger = logging.getLogger(__name__)

# Asset-type base scores (0–10). Higher = inherently riskier asset.
_ASSET_TYPE_WEIGHTS: dict[str, float] = {
    "VPN Gateway": 9.0,
    "Remote Access Protocol": 8.5,
    "Identity & SSO": 8.0,
    "Database": 8.0,
    "Admin Portal": 7.5,
    "CI/CD & Automation": 7.0,
    "Container / Orchestration": 7.0,
    "Source Code Repository": 7.0,
    "Cloud Storage": 6.0,
    "Email Server": 6.0,
    "File Sharing": 6.0,
    "Message Queue": 5.0,
    "API Endpoint": 5.0,
    "Staging / Dev": 5.0,
    "WAF / Edge": 4.0,
    "VoIP / Communication": 4.0,
    "Web Application": 3.0,
    "Unclassified Asset": 2.0,
}

# Nuclei/r3ngine severity int → 0–10 score.
_SEVERITY_TO_SCORE: dict[int, float] = {
    -1: 0.0,   # unknown
     0: 0.5,   # info
     1: 2.5,   # low
     2: 5.0,   # medium
     3: 7.5,   # high
     4: 10.0,  # critical
}

# Ports that substantially raise exposure risk.
_HIGH_RISK_PORTS: frozenset[int] = frozenset({
    22, 23, 3389, 5900,           # remote access
    3306, 5432, 27017, 1433, 1521, 9200,  # databases
    21, 445,                       # file sharing
})


class ExposureCorrelationEngine:
    """
    Aggregates data from Subdomains, EndPoints, Screenshots, Ports, and
    Vulnerabilities into unified Exposure records representing attack-surface assets.
    """

    def __init__(self, scan_history=None):
        self.scan_history = scan_history

    def correlate_exposures(self):
        if not self.scan_history:
            logger.warning("ExposureCorrelationEngine: No scan_history provided.")
            return

        subdomains = Subdomain.objects.filter(
            scan_history=self.scan_history
        ).prefetch_related(
            'ip_addresses__ports',
            'technologies',
            'screenshots',
            Prefetch(
                'endpoint_set',
                queryset=EndPoint.objects.filter(
                    scan_history=self.scan_history
                ).prefetch_related('techs'),
            ),
            Prefetch(
                'vulnerability_set',
                queryset=Vulnerability.objects.filter(
                    scan_history=self.scan_history
                ),
            ),
        )

        for subdomain in subdomains:
            self._process_subdomain(subdomain)

    def _process_subdomain(self, subdomain):
        endpoints = subdomain.endpoint_set.all()
        screenshots = subdomain.screenshots.all()
        vulns = subdomain.vulnerability_set.all()

        exposure_type = self._classify_exposure(subdomain, endpoints, screenshots)

        try:
            with transaction.atomic():
                exposure, created = Exposure.objects.update_or_create(
                    scan_history=self.scan_history,
                    subdomain=subdomain,
                    target_domain=subdomain.target_domain,
                    defaults={
                        'type': exposure_type,
                    }
                )
                if created:
                    Exposure.objects.filter(pk=exposure.pk).update(status='open')

                risk = self._calculate_risk_score(exposure, subdomain, vulns)
                Exposure.objects.filter(pk=exposure.pk).update(risk_score=risk)

                self._collect_evidence(exposure, subdomain, endpoints, screenshots, vulns)
                vulns.update(exposure=exposure)

        except Exception as e:
            logger.error(
                "Error correlating exposure for subdomain %s: %s",
                subdomain.name, e, exc_info=True,
            )

    @staticmethod
    def _has_keyword(text_corpus: str, keywords: list[str]) -> bool:
        return any(kw in text_corpus for kw in keywords)

    @staticmethod
    def _has_tech(tech_corpus: set[str], candidates: list[str]) -> bool:
        return any(
            candidate in tech
            for tech in tech_corpus
            for candidate in candidates
        )

    def _classify_exposure(self, subdomain, endpoints, screenshots) -> list[str]:
        """
        Classify the exposure using page titles and tech/port signals.

        IMPORTANT: Endpoint HTTP URLs are intentionally excluded from the keyword
        corpus. Including them caused false positives — e.g. a URL containing the
        subdomain name 'dashboardv3' triggering 'Admin Portal' via the 'dashboard'
        keyword. Only page titles carry semantic meaning for keyword-based detection.
        """
        title_corpus = ""   # page titles only — source for keyword-based detection
        tech_corpus: list[str] = []
        ports: set[int] = set()

        if subdomain.page_title:
            title_corpus += f" {subdomain.page_title.lower()}"
        for tech in subdomain.technologies.all():
            tech_corpus.append(tech.name.lower())
        for ip in subdomain.ip_addresses.all():
            for port in ip.ports.all():
                ports.add(port.number)

        for ep in endpoints:
            if ep.page_title:
                title_corpus += f" {ep.page_title.lower()}"
            # ep.http_url is intentionally NOT added — see docstring above
            for tech in ep.techs.all():
                tech_corpus.append(tech.name.lower())

        for sc in screenshots:
            if sc.title:
                title_corpus += f" {sc.title.lower()}"

        tech_corpus_set = set(tech_corpus)
        has_kw = self._has_keyword
        has_tech = self._has_tech
        classifications: list[str] = []

        # 1. Access & Security
        if has_kw(title_corpus, ['vpn', 'fortigate', 'pulse secure', 'cisco anyconnect', 'globalprotect', 'citrix gateway']) or has_tech(tech_corpus_set, ['vpn']):
            classifications.append("VPN Gateway")

        if ports.intersection({22, 3389, 5900, 23, 5985}) or has_tech(tech_corpus_set, ['ssh', 'rdp', 'vnc']):
            classifications.append("Remote Access Protocol")

        if has_kw(title_corpus, ['sso', 'okta', 'keycloak', 'auth0', 'saml', 'single sign-on']):
            classifications.append("Identity & SSO")

        if has_tech(tech_corpus_set, ['cloudflare', 'f5', 'imperva', 'akamai', 'fastly']):
            classifications.append("WAF / Edge")

        # 2. Infrastructure & DevOps
        if has_kw(title_corpus, ['jenkins', 'gitlab', 'bamboo', 'teamcity', 'github actions']) or has_tech(tech_corpus_set, ['jenkins']):
            classifications.append("CI/CD & Automation")

        if has_kw(title_corpus, ['kubernetes', 'rancher', 'portainer']) or has_tech(tech_corpus_set, ['docker', 'kubernetes']):
            classifications.append("Container / Orchestration")

        if has_kw(title_corpus, ['bitbucket', 'gitea', 'svn', 'gitlab']):
            classifications.append("Source Code Repository")

        if has_kw(title_corpus, ['s3', 'minio', 'azure blob', 'bucket']):
            classifications.append("Cloud Storage")

        # 3. Data & Storage
        if ports.intersection({3306, 5432, 27017, 1433, 1521, 9200, 6379, 11211}) or has_tech(tech_corpus_set, ['mysql', 'postgres', 'mongodb', 'redis', 'elasticsearch', 'mssql', 'oracle']):
            classifications.append("Database")

        if ports.intersection({21, 445, 2049, 139}) or has_tech(tech_corpus_set, ['ftp', 'smb', 'nfs', 'owncloud', 'nextcloud']):
            classifications.append("File Sharing")

        if ports.intersection({5672, 9092}) or has_tech(tech_corpus_set, ['rabbitmq', 'kafka']):
            classifications.append("Message Queue")

        # 4. Services
        if ports.intersection({25, 110, 143, 465, 587, 993, 995}) or has_tech(tech_corpus_set, ['exchange', 'postfix', 'zimbra']):
            classifications.append("Email Server")

        if ports.intersection({5060, 5061}) or has_tech(tech_corpus_set, ['sip', 'asterisk']):
            classifications.append("VoIP / Communication")

        # 5. Web Applications — keyword detection uses title_corpus ONLY
        if has_kw(title_corpus, ['admin', 'dashboard', 'control panel', 'cpanel', 'plesk']):
            classifications.append("Admin Portal")

        if has_kw(title_corpus, ['graphql', 'swagger', 'openapi']) or has_tech(tech_corpus_set, ['graphql', 'swagger', 'openapi']):
            classifications.append("API Endpoint")

        # Staging/Dev: subdomain name prefix only (not title, not URL)
        subdomain_name = subdomain.name.lower() if subdomain.name else ""
        staging_prefixes = ['dev.', 'staging.', 'test.', 'uat.', 'sandbox.', 'stg.', 'qa.']
        if any(subdomain_name.startswith(p) or f".{p}" in subdomain_name for p in staging_prefixes):
            classifications.append("Staging / Dev")

        if not classifications:
            web_ports = {80, 443, 8080, 8443}
            if ports.intersection(web_ports) or tech_corpus_set or title_corpus.strip():
                classifications.append("Web Application")

        if not classifications:
            classifications.append("Unclassified Asset")

        return classifications

    def _calculate_risk_score(self, exposure: 'Exposure', subdomain, vulns) -> float:
        """
        Combined risk score on a 0–10 scale.

        Weights:
          50% — max vulnerability severity linked to this exposure
          35% — asset-type base weight (higher-risk assets start higher)
          15% — presence of high-risk ports

        A prior false_positive on the same subdomain name (across any scan on the
        same target domain) applies a 0.7× confidence damper to reflect that a
        human reviewer previously dismissed this asset type as a false alarm.
        """
        # Asset type component
        type_base = max(
            (_ASSET_TYPE_WEIGHTS.get(t, 3.0) for t in (exposure.type or [])),
            default=3.0,
        )

        # Vulnerability severity component
        max_sev = max(
            (_SEVERITY_TO_SCORE.get(v.severity, 0.0) for v in vulns),
            default=0.0,
        )

        # Port exposure component
        ports: set[int] = set()
        for ip in subdomain.ip_addresses.all():
            for port in ip.ports.all():
                ports.add(port.number)
        port_count = len(ports & _HIGH_RISK_PORTS)
        port_score = min(port_count * 2.0, 10.0)

        raw = 0.50 * max_sev + 0.35 * type_base + 0.15 * port_score
        score = round(min(raw, 10.0), 2)

        # False-positive history damper — look across all scans for this subdomain name
        had_fp = Exposure.objects.filter(
            target_domain=subdomain.target_domain,
            subdomain__name=subdomain.name,
            status='false_positive',
        ).exclude(pk=exposure.pk).exists()
        if had_fp:
            score = round(score * 0.7, 2)

        return score

    def _collect_evidence(self, exposure, subdomain, endpoints, screenshots, vulns):
        """
        Rebuild ExposureEvidence records for an exposure.
        Deletes stale evidence and bulk-creates fresh records to avoid
        JSONField-based get_or_create duplicates on re-scans.
        """
        ExposureEvidence.objects.filter(exposure=exposure).delete()

        evidence_batch = []

        if subdomain.http_status:
            evidence_batch.append(ExposureEvidence(
                exposure=exposure,
                source_tool="HTTP Probe",
                evidence_data={
                    'url': subdomain.http_url,
                    'status': subdomain.http_status,
                    'title': subdomain.page_title,
                    'webserver': subdomain.webserver,
                },
            ))

        for ep in endpoints[:5]:
            evidence_batch.append(ExposureEvidence(
                exposure=exposure,
                source_tool="Crawler",
                evidence_data={
                    'url': ep.http_url,
                    'status': ep.http_status,
                    'title': ep.page_title,
                },
            ))

        for sc in screenshots[:3]:
            evidence_batch.append(ExposureEvidence(
                exposure=exposure,
                source_tool="Screenshot",
                evidence_data={
                    'url': sc.url,
                    'screenshot_path': sc.screenshot_path,
                    'title': sc.title,
                },
            ))

        for vuln in [v for v in vulns if v.severity == 0][:5]:
            evidence_batch.append(ExposureEvidence(
                exposure=exposure,
                source_tool="Vulnerability Scanner (Info)",
                evidence_data={
                    'name': vuln.name,
                    'template': vuln.template_id,
                    'matched_at': vuln.http_url,
                },
            ))

        if evidence_batch:
            ExposureEvidence.objects.bulk_create(evidence_batch)
