"""
CVE Enrichment Service

Fetches vulnerability metadata from official sources (NVD, EPSS, CISA KEV)
and updates the local CveId database with enriched data.

Supports:
- NVD API v2.0 for CVSS scores and metadata
- FIRST EPSS API for exploitation probability scores
- CISA KEV catalog for known exploited vulnerabilities
"""

import logging
import re
import requests
from typing import Optional, Dict, List
from datetime import timedelta
from functools import lru_cache

from django.conf import settings
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.utils.timezone import is_naive, make_aware
from django.core.cache import cache

from startScan.models import CveId

logger = logging.getLogger(__name__)


class CVEEnrichmentService:
    """
    Service for enriching CVE records with official metadata.
    
    Caches API responses to minimize external API calls.
    Gracefully degrades if external services are unavailable.
    """
    
    # API Endpoints
    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    EPSS_API_BASE = "https://api.first.org/data/v1/epss"
    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    EPSS_FEED_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
    
    # Cache TTLs (seconds)
    CACHE_TTL_CVE = 86400 * 7  # 7 days for individual CVEs
    CACHE_TTL_KEV = 3600  # 1 hour for KEV catalog
    
    # Request settings
    REQUEST_TIMEOUT = 10
    MAX_RETRIES = 2
    
    def __init__(self):
        """Initialize the enrichment service."""
        self.nvd_api_key = getattr(settings, 'NVD_API_KEY', None)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'r3ngine/1.0 (+https://github.com/whiterabb17/r3ngine)'
        })
    
    # ==================== Public API ====================
    
    def enrich_cve(self, cve_name: str) -> Optional[CveId]:
        """
        Fetch and store CVE metadata from NVD and EPSS APIs.
        
        This is the primary entry point for CVE enrichment.
        
        Args:
            cve_name (str): CVE identifier, e.g., 'CVE-2024-1234'
        
        Returns:
            CveId: Updated or created CveId object, or None if enrichment fails
        
        Example:
            >>> service = CVEEnrichmentService()
            >>> cve = service.enrich_cve('CVE-2024-1234')
            >>> print(f"CVSS: {cve.cvss_v31_base_score}")
        """
        # Normalize CVE name
        cve_name = cve_name.upper().strip()
        is_valid_cve = False
        
        if cve_name.startswith('CVE-'):
            if re.match(r'^CVE-\d{4}-\d+$', cve_name):
                is_valid_cve = True
            else:
                logger.debug("Non-CVE format detected: %s, skipping external database lookups", cve_name)
        else:
            # Accept bare YYYY-NNNNN format and prepend the required prefix
            if re.match(r'^\d{4}-\d+$', cve_name):
                cve_name = 'CVE-' + cve_name
                is_valid_cve = True
            else:
                logger.debug("Non-CVE format detected: %s, skipping external database lookups", cve_name)
        
        # Get or create CVE record
        cve_obj, created = CveId.objects.get_or_create(name=cve_name)

        if not is_valid_cve:
            # We don't perform external enrichment for non-CVE strings, just return
            return cve_obj
        
        # Skip re-enrichment if recently updated (within 7 days)
        if not created and cve_obj.last_modified_date:
            days_old = (timezone.now() - cve_obj.last_modified_date).days
            if days_old < 7 and cve_obj.cvss_v31_base_score is not None:
                logger.debug(f"CVE {cve_name} recently enriched, skipping")
                return cve_obj
        
        # 1. Official NVD API (Primary Source)
        try:
            self._enrich_from_nvd(cve_obj)
        except Exception as e:
            if "404" in str(e):
                logger.debug(f"NVD enrichment not found for {cve_name}")
            else:
                logger.warning(f"NVD enrichment failed for {cve_name}: {e}")
        
        try:
            self._enrich_from_epss(cve_obj)
        except Exception as e:
            logger.warning(f"EPSS enrichment failed for {cve_name}: {e}")

        try:
            self._enrich_from_vulnx(cve_obj)
        except Exception as e:
            logger.warning(f"vulnx enrichment failed for {cve_name}: {e}")

        try:
            self._enrich_from_sploitscan(cve_obj)
        except Exception as e:
            logger.warning(f"SploitScan enrichment failed for {cve_name}: {e}")

        try:
            self._generate_cve_ai_analysis(cve_obj)
        except Exception as e:
            logger.warning(f"AI risk assessment failed for {cve_name}: {e}")

        # Save and return
        cve_obj.save()
        return cve_obj
    
    def enrich_multiple_cves(self, cve_names: List[str]) -> Dict[str, CveId]:
        """
        Batch enrich multiple CVEs.
        
        Args:
            cve_names (List[str]): List of CVE identifiers
        
        Returns:
            Dict[str, CveId]: Mapping of CVE name to enriched object
        """
        results = {}
        print(f"DEBUG: enrich_multiple_cves called with {cve_names}")
        for cve_name in cve_names:
            try:
                cve_obj = self.enrich_cve(cve_name)
                print(f"DEBUG: enrich_cve returned {cve_obj}")
                if cve_obj:
                    results[cve_name] = cve_obj
            except Exception as e:
                print(f"DEBUG: Exception in enrich_cve: {e}")
                logger.error(f"Failed to enrich {cve_name}: {e}", exc_info=True)
        
        print(f"DEBUG: enrich_multiple_cves returning {len(results)} results")
        return results
    
    def sync_cisa_kev_catalog(self) -> Dict[str, int]:
        """
        Synchronize local CveId records with official CISA Known Exploited 
        Vulnerabilities (KEV) catalog.
        
        This should be called periodically (e.g., daily) to keep KEV status 
        up-to-date.
        
        Returns:
            Dict with keys 'updated', 'new', 'errors'
        
        Example:
            >>> service = CVEEnrichmentService()
            >>> result = service.sync_cisa_kev_catalog()
            >>> print(f"Updated {result['updated']} CVEs as KEV")
        """
        logger.info("Synchronizing CISA KEV catalog...")
        
        try:
            # Check cache first
            cache_key = 'cisa_kev_catalog'
            kev_data = cache.get(cache_key)
            
            if not kev_data:
                # Fetch from official source
                response = requests.get(
                    self.CISA_KEV_URL, 
                    timeout=self.REQUEST_TIMEOUT
                )
                response.raise_for_status()
                kev_data = response.json()
                
                # Cache for 1 hour
                cache.set(cache_key, kev_data, self.CACHE_TTL_KEV)
            
            # Extract CVE names from catalog
            vulns = kev_data.get("vulnerabilities", [])
            cve_names = [v["cveID"] for v in vulns if "cveID" in v]
            
            logger.info(f"CISA KEV catalog contains {len(cve_names)} vulnerabilities")
            
            # Batch update all matching CveIds
            updated_count = CveId.objects.filter(
                name__in=cve_names
            ).update(is_cisa_kev=True)
            
            # Count new KEV entries (not yet in database)
            existing_names = set(
                CveId.objects.filter(name__in=cve_names).values_list('name', flat=True)
            )
            new_count = len([c for c in cve_names if c not in existing_names])
            
            logger.info(f"CISA KEV sync: {updated_count} updated, {new_count} new")
            
            return {
                'updated': updated_count,
                'new': new_count,
                'total': len(cve_names),
                'errors': 0
            }
        
        except Exception as e:
            logger.error(f"Failed to synchronize CISA KEV catalog: {e}")
            return {
                'updated': 0,
                'new': 0,
                'total': 0,
                'errors': 1
            }

    def sync_epss_catalog(self) -> Dict[str, int]:
        """
        Synchronize local EpssFeedData records with the official EPSS data feed.
        Downloads the gzipped CSV from FIRST/Cyentia, drops the old table, and inserts
        the fresh batch.
        """
        logger.info("Synchronizing EPSS catalog...")
        from startScan.models import EpssFeedData
        import gzip
        import csv
        import io

        try:
            response = requests.get(self.EPSS_FEED_URL, timeout=30)
            response.raise_for_status()

            # Read and decompress
            with gzip.GzipFile(fileobj=io.BytesIO(response.content)) as gz:
                content = gz.read().decode('utf-8')

            # The EPSS CSV has a few metadata lines starting with '#', so filter them out
            lines = content.splitlines()
            data_lines = [line for line in lines if not line.startswith('#')]

            if not data_lines:
                logger.error("EPSS CSV feed is empty or invalid.")
                return {'inserted': 0, 'errors': 1}

            # Typically the first non-comment line is the header: cve,epss,percentile
            # Ensure we are skipping the header by checking the first line
            if "cve" in data_lines[0].lower():
                data_lines.pop(0)

            # Parse rows
            reader = csv.reader(data_lines)
            batch = []
            batch_size = 10000

            # Truncate old data
            EpssFeedData.objects.all().delete()
            
            inserted_count = 0

            for row in reader:
                if len(row) >= 3:
                    cve_id = row[0].strip()
                    try:
                        epss_score = float(row[1])
                        epss_percentile = float(row[2]) * 100.0  # Convert to percentage format like API
                        batch.append(EpssFeedData(
                            cve_id=cve_id,
                            epss_score=epss_score,
                            epss_percentile=epss_percentile
                        ))
                    except ValueError:
                        continue

                if len(batch) >= batch_size:
                    EpssFeedData.objects.bulk_create(batch, ignore_conflicts=True)
                    inserted_count += len(batch)
                    batch = []

            if batch:
                EpssFeedData.objects.bulk_create(batch, ignore_conflicts=True)
                inserted_count += len(batch)

            logger.info(f"EPSS catalog sync complete: {inserted_count} records inserted.")
            return {'inserted': inserted_count, 'errors': 0}

        except Exception as e:
            logger.error(f"Failed to synchronize EPSS catalog: {e}")
            return {'inserted': 0, 'errors': 1}
    
    # ==================== Private Methods ====================
    
    def _enrich_from_nvd(self, cve_obj: CveId) -> None:
        """
        Fetch CVE metadata from NVD API v2.0.
        
        Args:
            cve_obj (CveId): CVE object to enrich in-place
        
        Raises:
            requests.RequestException: If API call fails
            ValueError: If response format is unexpected
        """
        # Circuit breaker to prevent 429s from flooding
        if cache.get('nvd_api_unavailable'):
            logger.debug(f"NVD API paused, skipping enrichment for {cve_obj.name}")
            return

        # Build request with API key if available
        headers = {}
        if self.nvd_api_key:
            headers['apiKey'] = self.nvd_api_key
        
        params = {'cveId': cve_obj.name}
        
        logger.debug(f"Fetching NVD data for {cve_obj.name}...")
        
        response = requests.get(
            self.NVD_API_BASE,
            params=params,
            headers=headers,
            timeout=self.REQUEST_TIMEOUT
        )
        
        if response.status_code in [429, 502, 503, 504]:
            logger.warning(f"NVD API unavailable ({response.status_code}), pausing requests for 15 minutes")
            cache.set('nvd_api_unavailable', True, 900)
            
        response.raise_for_status()
        
        data = response.json()
        vulns = data.get("vulnerabilities", [])
        
        if not vulns:
            logger.debug(f"No NVD data found for {cve_obj.name}")
            return
        
        # Extract CVE data from first result
        cve_data = vulns[0].get("cve", {})
        
        # Parse dates
        if cve_data.get("published"):
            cve_obj.published_date = self._parse_timezone_aware(cve_data["published"])
        
        if cve_data.get("lastModified"):
            cve_obj.last_modified_date = self._parse_timezone_aware(cve_data["lastModified"])
        
        # Parse CVSS v3.1 metrics
        metrics = cve_data.get("metrics", {})
        cvss_v31_list = metrics.get("cvssMetricV31", [])
        
        if cvss_v31_list:
            cvss_data = cvss_v31_list[0].get("cvssData", {})
            cve_obj.cvss_v31_base_score = cvss_data.get("baseScore")
            cve_obj.attack_vector = cvss_data.get("attackVector")
            cve_obj.attack_complexity = cvss_data.get("attackComplexity")
            cve_obj.privileges_required = cvss_data.get("privilegesRequired")
            cve_obj.user_interaction = cvss_data.get("userInteraction")
            cve_obj.confidentiality_impact = cvss_data.get("confidentialityImpact")
            cve_obj.integrity_impact = cvss_data.get("integrityImpact")
            cve_obj.availability_impact = cvss_data.get("availabilityImpact")
            
            logger.debug(
                f"NVD enrichment successful: {cve_obj.name} "
                f"CVSS={cve_obj.cvss_v31_base_score}"
            )
    
    def _enrich_from_epss(self, cve_obj: CveId) -> None:
        """
        Fetch EPSS (Exploit Prediction Scoring System) data from local EpssFeedData.
        
        EPSS provides a probability score of a vulnerability being exploited
        in the wild (0-1 scale, higher = more likely to be exploited).
        
        Args:
            cve_obj (CveId): CVE object to enrich in-place
        """
        from startScan.models import EpssFeedData

        feed_data = EpssFeedData.objects.filter(cve_id=cve_obj.name).first()
        if not feed_data:
            logger.debug(f"No local EPSS data found for {cve_obj.name}")
            return

        cve_obj.epss_score = feed_data.epss_score
        cve_obj.epss_percentile = feed_data.epss_percentile

        logger.debug(
            f"EPSS enrichment successful: {cve_obj.name} "
            f"EPSS={cve_obj.epss_score} percentile={cve_obj.epss_percentile}"
        )
    
    def _enrich_from_vulnx(self, cve_obj: CveId) -> None:
        """
        Fetch CVE metadata from vulnx (ProjectDiscovery Cloud Platform).

        Populates is_poc, is_template, and additional CVSS/EPSS fields if
        the PDCP API key is configured in the database.
        """
        import subprocess
        import json
        import os
        from dashboard.models import ProjectDiscoveryAPIKey

        pdcp_key_obj = ProjectDiscoveryAPIKey.objects.first()
        pdcp_key = pdcp_key_obj.key if pdcp_key_obj else None
        ensureAuthCmd = ["vulnx", "auth", "--api-key", pdcp_key] if pdcp_key else None
        logger.debug("Ensuring authentication: %s", ensureAuthCmd)
        if ensureAuthCmd:
            result = subprocess.run(
                ensureAuthCmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode != 0:
                logger.warning("vulnx authentication failed with code %d: %s", result.returncode, result.stderr)
                return

        cmd = ["vulnx", "id", "--json", cve_obj.name]
        env = os.environ.copy()
        if pdcp_key:
            env["PDCP_API_KEY"] = pdcp_key

        logger.debug("Running vulnx command: %s", " ".join(cmd))

        try:
            result = subprocess.run(
                cmd,
                env=env,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                error_lines = [line.strip() for line in result.stderr.split('\n') if line.strip().startswith('[FTL]') or line.strip().startswith('[ERR]')]
                if error_lines:
                    logger.warning("%s", " | ".join(error_lines))
                else:
                    logger.debug("vulnx command failed with code %d", result.returncode)
                return

            if not result.stdout.strip():
                logger.debug("vulnx returned empty output for %s", cve_obj.name)
                return

            try:
                data = json.loads(result.stdout)
            except json.JSONDecodeError:
                lines = [line.strip() for line in result.stdout.split('\n') if line.strip()]
                data = None
                for line in lines:
                    if line.startswith('{') or line.startswith('['):
                        try:
                            data = json.loads(line)
                            break
                        except json.JSONDecodeError:
                            continue
                if not data:
                    logger.warning("Failed to parse JSON from vulnx output for %s", cve_obj.name)
                    return

            vuln_data = None
            if isinstance(data, dict):
                vuln_data = data.get("data") if isinstance(data.get("data"), dict) else data
            elif isinstance(data, list) and data:
                vuln_data = data[0]

            if not vuln_data or not isinstance(vuln_data, dict):
                logger.debug("No valid vulnerability data in vulnx response for %s", cve_obj.name)
                return

            cvss = vuln_data.get("cvss_score")
            if cvss is not None:
                cve_obj.cvss_v31_base_score = float(cvss)

            epss_score = vuln_data.get("epss_score")
            if epss_score is not None:
                cve_obj.epss_score = float(epss_score)

            epss_perc = vuln_data.get("epss_percentile")
            if epss_perc is not None:
                cve_obj.epss_percentile = float(epss_perc)

            is_kev = vuln_data.get("is_kev")
            if is_kev is not None:
                cve_obj.is_cisa_kev = bool(is_kev)

            is_poc = vuln_data.get("is_poc")
            if is_poc is not None:
                cve_obj.is_poc = bool(is_poc)

            is_template = vuln_data.get("is_template")
            if is_template is not None:
                cve_obj.is_template = bool(is_template)

            published = vuln_data.get("cve_created_at")
            if published:
                cve_obj.published_date = self._parse_timezone_aware(published)

            modified = vuln_data.get("cve_updated_at")
            if modified:
                cve_obj.last_modified_date = self._parse_timezone_aware(modified)

            logger.info("vulnx enrichment successful for %s", cve_obj.name)

        except subprocess.TimeoutExpired:
            logger.warning("vulnx request timed out for %s", cve_obj.name)
        except Exception as e:
            logger.error("Error enriching %s from vulnx: %s", cve_obj.name, e)

    def _parse_timezone_aware(self, date_str: str) -> Optional[timezone.datetime]:
        """
        Parse ISO 8601 datetime string and ensure timezone awareness.
        
        Args:
            date_str (str): ISO 8601 formatted datetime
        
        Returns:
            datetime: Timezone-aware datetime, or None if parsing fails
        """
        if not date_str:
            return None
        
        try:
            dt = parse_datetime(date_str)
            if dt and is_naive(dt):
                return make_aware(dt)
            return dt
        except (ValueError, TypeError) as e:
            logger.warning(f"Failed to parse datetime '{date_str}': {e}")
            return None

    def _enrich_from_sploitscan(self, cve_obj: CveId) -> None:
        """
        Fetch exploits and hackerone metadata using sploitscan.
        """
        import subprocess
        import json
        import os
        import tempfile
        import glob
        
        logger.debug(f"Fetching SploitScan data for {cve_obj.name}...")
        
        with tempfile.TemporaryDirectory() as tmpdir:
            cmd = ["sploitscan", cve_obj.name, "-e", "json"]
            try:
                result = subprocess.run(
                    cmd,
                    cwd=tmpdir,
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                
                json_files = glob.glob(os.path.join(tmpdir, "*.json"))
                if not json_files:
                    logger.debug(f"SploitScan failed to produce JSON for {cve_obj.name}")
                    return
                
                with open(json_files[0], 'r') as f:
                    data = json.load(f)
                    
                if not isinstance(data, list) or len(data) == 0:
                    return
                
                cve_data = data[0]
                
                # Public exploits
                public_exploits = []
                # ExploitDB
                edb_data = cve_data.get("ExploitDB Data") or []
                if isinstance(edb_data, list):
                    for e in edb_data:
                        if isinstance(e, dict):
                            public_exploits.append({"source": "ExploitDB", "exploit": e.get("id")})
                
                # Metasploit
                msf_data = (cve_data.get("Metasploit Data") or {}).get("modules") or []
                if isinstance(msf_data, list):
                    for m in msf_data:
                        public_exploits.append({"source": "Metasploit", "exploit": m})
                
                # GitHub
                github_data = (cve_data.get("GitHub Data") or {}).get("pocs") or []
                if isinstance(github_data, list):
                    for g in github_data:
                        public_exploits.append({"source": "GitHub", "exploit": g})
                    
                if public_exploits:
                    cve_obj.public_exploits = public_exploits
                    
                # HackerOne data
                h1_entry = cve_data.get("HackerOne Data") or {}
                h1_data = None
                if isinstance(h1_entry, dict):
                    h1_data = (h1_entry.get("data") or {}).get("cve_entry")
                if h1_data:
                    cve_obj.hackerone_data = h1_data
                    
                # Priority
                priority_dict = cve_data.get("Priority") or {}
                priority = None
                if isinstance(priority_dict, dict):
                    priority = priority_dict.get("Priority")
                if priority:
                    cve_obj.patching_priority = priority
                    
                logger.info(f"SploitScan enrichment successful for {cve_obj.name}")
                
            except subprocess.TimeoutExpired:
                logger.warning(f"SploitScan request timed out for {cve_obj.name}")
            except Exception as e:
                logger.error(f"Error enriching {cve_obj.name} from SploitScan: {e}")

    def _generate_cve_ai_analysis(self, cve_obj: CveId) -> None:
        """
        Generate AI risk assessment using the internal LLM module.
        """
        from reNgine.llm import LLMVulnerabilityReportGenerator
        
        # We only generate if we don't have it yet
        if cve_obj.ai_risk_assessment:
            return
            
        logger.debug(f"Generating AI risk assessment for {cve_obj.name}...")
        try:
            # We can use the existing report generator
            report_gen = LLMVulnerabilityReportGenerator(logger=logger)
            
            # Create a simple description prompt
            prompt = f"Analyze the CVE {cve_obj.name}. "
            if cve_obj.cvss_v31_base_score:
                prompt += f"It has a CVSS v3.1 base score of {cve_obj.cvss_v31_base_score}. "
            if cve_obj.public_exploits:
                prompt += f"Public exploits exist in {len(cve_obj.public_exploits)} sources. "
            if cve_obj.patching_priority:
                prompt += f"Patching priority is {cve_obj.patching_priority}. "
                
            prompt += "Provide a detailed risk assessment, potential impact, and mitigation ideas."
            
            response = report_gen.get_vulnerability_description(prompt)
            if response and response.get('status'):
                desc = response.get('description', '')
                impact = response.get('impact', '')
                remediation = response.get('remediation', '')
                
                assessment = f"**Description**:\n{desc}\n\n**Impact**:\n{impact}\n\n**Mitigation**:\n{remediation}"
                cve_obj.ai_risk_assessment = assessment
                cve_obj.mitigation_ideas = remediation
                logger.info(f"AI risk assessment generated for {cve_obj.name}")
            else:
                logger.warning(f"AI risk assessment failed for {cve_obj.name}: {response.get('error') if response else 'Unknown'}")
        except Exception as e:
            logger.error(f"Error generating AI risk assessment for {cve_obj.name}: {e}")


class CVEBatchEnricher:
    """
    Utility for background enrichment of CVEs in batches.
    
    Useful for periodic synchronization tasks.
    """
    
    def __init__(self):
        self.service = CVEEnrichmentService()
    
    def enrich_unenriched_cves(self, limit: int = 100) -> int:
        """
        Enrich CVEs that haven't been enriched yet.
        
        Args:
            limit (int): Maximum number to enrich in this run
        
        Returns:
            int: Number of CVEs successfully enriched
        """
        # Find CVEs with no enrichment data
        cves_to_enrich = CveId.objects.filter(
            cvss_v31_base_score__isnull=True
        ).order_by('name')[:limit]
        
        count = 0
        for cve in cves_to_enrich:
            try:
                self.service.enrich_cve(cve.name)
                count += 1
            except Exception as e:
                logger.error(f"Failed to enrich {cve.name}: {e}")
        
        logger.info(f"Batch enrichment completed: {count}/{len(list(cves_to_enrich))} successful")
        return count
    
    def refresh_recent_cves(self, days: int = 30) -> int:
        """
        Re-enrich CVEs modified in last N days to get latest data.
        
        Args:
            days (int): Lookback period in days
        
        Returns:
            int: Number of CVEs re-enriched
        """
        cutoff = timezone.now() - timedelta(days=days)
        
        cves_to_refresh = CveId.objects.filter(
            last_modified_date__gte=cutoff
        ).order_by('-last_modified_date')
        
        count = 0
        for cve in cves_to_refresh:
            try:
                self.service.enrich_cve(cve.name)
                count += 1
            except Exception as e:
                logger.error(f"Failed to refresh {cve.name}: {e}")
        
        logger.info(f"Refresh completed: {count} CVEs")
        return count
