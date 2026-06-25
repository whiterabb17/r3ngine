import logging
import requests
import socket
import ssl
from django.db.models import Q
from django.utils import timezone
from startScan.models import Subdomain, WafBypassFinding
from dashboard.models import ShodanAPIKey, CensysAPIKey
from reNgine.utils.opsec import get_opsec_manager

logger = logging.getLogger(__name__)

class OriginDiscoveryManager:
    """
    Manager for discovering the original IP of a WAF-protected domain.
    """
    def __init__(self, subdomain_obj):
        self.subdomain = subdomain_obj
        self.domain = subdomain_obj.name
        self.shodan_key = self._get_shodan_key()
        self.censys_key = self._get_censys_key()
        self.opsec = get_opsec_manager()

    def _get_shodan_key(self):
        key_obj = ShodanAPIKey.objects.first()
        return key_obj.key if key_obj else None

    def _get_censys_key(self):
        key_obj = CensysAPIKey.objects.first()
        return key_obj.api_key if key_obj else None

    def find_origin(self, use_shodan=True, use_censys=True, use_heuristics=True):
        results = set()
        
        if use_shodan and self.shodan_key:
            results.update(self._query_shodan())
            
        if use_censys and self.censys_key:
            results.update(self._query_censys())
            
        if use_heuristics:
            results.update(self._internal_heuristics())
            
        # Filter out known WAF/CDN IPs if possible
        # (For now we just return all found IPs)
        return list(results)

    def _query_shodan(self):
        ips = []
        try:
            # Query by hostname
            url = f"https://api.shodan.io/shodan/host/search?key={self.shodan_key}&query=hostname:{self.domain}"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                for match in data.get('matches', []):
                    ips.append(match.get('ip_str'))
            
            # Query by SSL serial if available
            cert_serial = self._get_ssl_serial()
            if cert_serial:
                url = f"https://api.shodan.io/shodan/host/search?key={self.shodan_key}&query=ssl.cert.serial:{cert_serial}"
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    for match in data.get('matches', []):
                        ips.append(match.get('ip_str'))
        except Exception as e:
            logger.error(f"Shodan query failed for {self.domain}: {str(e)}")
        return ips

    def _query_censys(self):
        ips = []
        try:
            from censys_platform import SDK, SearchQueryInputBody
            sdk = SDK(personal_access_token=self.censys_key)
            query = "services.tls.certificates.leaf_data.names: %s" % self.domain
            response = sdk.global_data.search(
                SearchQueryInputBody(query=query, page_size=100)
            )
            for hit in (response.result.hits or []):
                host = getattr(hit, 'host_v1', None)
                if host:
                    resource = getattr(host, 'resource', None) or {}
                    ip = getattr(resource, 'ip', None) or resource.get('ip')
                    if ip:
                        ips.append(ip)
        except Exception as e:
            logger.error("Censys query failed for %s: %s", self.domain, e)
        return ips

    def _internal_heuristics(self):
        ips = []
        # 1. Check for common 'origin' subdomains in the same project
        common_prefixes = ['direct', 'origin', 'dev', 'stage', 'backend', 'vps']
        base_domain = '.'.join(self.domain.split('.')[-2:])
        
        related_subdomains = Subdomain.objects.filter(
            Q(name__icontains='direct') | 
            Q(name__icontains='origin') | 
            Q(name__icontains='dev'),
            name__endswith=base_domain
        ).exclude(id=self.subdomain.id)
        
        for sub in related_subdomains:
            # Get IP addresses for these subdomains
            for ip_obj in sub.ip_addresses.all():
                ips.append(ip_obj.address)
                
        return ips

    def _get_ssl_serial(self):
        """
        Retrieves the SSL certificate serial number for the target domain.
        Used for origin discovery via Shodan.
        """
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            
            hostname = self.domain
            ctx = ssl.create_default_context()
            # Disable verification as we only need the serial metadata
            # Origin IPs often have self-signed or expired certificates
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(cert_der, default_backend())
                    return cert.serial_number
        except Exception as e:
            logger.debug(f"SSL serial retrieval failed for {self.domain}: {str(e)}")
            return None

class WafBypassOrchestrator:
    """
    Orchestrator for testing WAF bypass techniques.
    """
    def __init__(self, subdomain_obj):
        self.subdomain = subdomain_obj
        self.target_url = f"https://{subdomain_obj.name}"
        self.opsec = get_opsec_manager()

    def run_all_tests(self, use_nuclei=True, use_benchmarking=True):
        findings = []
        if use_benchmarking:
            findings.extend(self._test_headers())
        
        if use_nuclei:
            findings.extend(self._run_nuclei_bypass())
            
        return findings

    def _test_headers(self):
        """
        Test susceptibility to various HTTP headers used for WAF bypass.
        """
        bypass_headers = {
            'X-Forwarded-For': '127.0.0.1',
            'X-Originating-IP': '127.0.0.1',
            'X-Remote-IP': '127.0.0.1',
            'X-Remote-Addr': '127.0.0.1',
            'X-Client-IP': '127.0.0.1',
            'X-Real-IP': '127.0.0.1',
            'True-Client-IP': '127.0.0.1',
            'Client-IP': '127.0.0.1',
            'Forwarded': 'for=127.0.0.1;proto=http'
        }
        
        findings = []
        # Get scan/activity context if possible
        scan_history = self.subdomain.scan_history
        # Try to find a relevant ScanActivity if none was passed (this is a bit hacky but works for timeline)
        from startScan.models import ScanActivity, Command
        activity = ScanActivity.objects.filter(scan_of=scan_history, name='waf_bypass').last()

        for header, value in bypass_headers.items():
            try:
                # Send a "suspicious" payload with and without the header
                payload = "/etc/passwd"
                headers = {header: value}
                url = f"{self.target_url}?file={payload}"
                
                # Record command for timeline
                cmd_text = f"GET {url} [Header: {header}: {value}]"
                Command.objects.create(
                    command=cmd_text,
                    time=timezone.now(),
                    scan_history=scan_history,
                    activity=activity
                )
                
                # We check if the response status or body changes significantly
                r = requests.get(url, headers=headers, timeout=10, verify=False)
                
                # If we get a 200 or something that isn't a 403/406, it might be a bypass
                if r.status_code not in [403, 406, 429]:
                    finding = WafBypassFinding.objects.create(
                        subdomain=self.subdomain,
                        technique=f"Header Injection: {header}",
                        is_successful=True,
                        payload_evidence=f"Request with {header}: {value} returned {r.status_code}"
                    )
                    findings.append(finding)
            except Exception as e:
                logger.error(f"Header bypass test failed for {header}: {str(e)}")
                
        return findings

    def _run_nuclei_bypass(self):
        """
        Placeholder for Nuclei bypass execution. 
        In reNgine, this is usually handled by calling the nuclei binary.
        """
        # This will be implemented in the Celery task to use the existing Nuclei infrastructure
        return []
