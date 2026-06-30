from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from api.views import _WORKFLOW_REGISTRY

# Human-readable labels only — required_fields come from _WORKFLOW_REGISTRY.
_WORKFLOW_DESCRIPTIONS: dict[str, tuple[str, str]] = {
    'user-hunt':       ('User Hunt',          'Enumerate users across social platforms and data sources'),
    'url-bypass':      ('URL Bypass',         'Attempt WAF/auth bypass against target URLs'),
    'wordpress':       ('WordPress Recon',    'Deep reconnaissance of WordPress installations'),
    'host-recon':      ('Host Recon',         'Full host-level recon including ports and services'),
    'cidr-recon':      ('CIDR Recon',         'Recon across an entire CIDR network block'),
    'code-scan':       ('Code Scan',          'Static analysis via Vigolium scanner'),
    'domain-recon':    ('Domain Recon',       'Full domain reconnaissance (subdomains, DNS, OSINT)'),
    'subdomain-recon': ('Subdomain Recon',    'Subdomain enumeration and takeover checks'),
    'url-crawl':       ('URL Crawl',          'Deep crawl of target URLs collecting endpoints'),
    'url-dirsearch':   ('Directory Search',   'Directory and file fuzzing against target URLs'),
    'url-fuzz':        ('URL Fuzz',           'Parameter fuzzing against target URLs'),
    'url-params-fuzz': ('URL Params Fuzz',    'CPDE-powered injectable parameter discovery'),
    'url-vuln':        ('Vulnerability Scan', 'Nuclei-powered vulnerability scan against target URLs'),
}


class WorkflowMobileListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request) -> Response:
        workflows = [
            {
                'slug': slug,
                'name': _WORKFLOW_DESCRIPTIONS[slug][0],
                'description': _WORKFLOW_DESCRIPTIONS[slug][1],
                'required_fields': required_fields,
            }
            for slug, (_workflow_class, required_fields) in _WORKFLOW_REGISTRY.items()
            if slug in _WORKFLOW_DESCRIPTIONS
        ]
        return Response({'workflows': workflows})
