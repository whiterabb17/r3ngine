"""OSINT entry points: the osint task, its discovery phase and the post-crawl phase.

Split out of the former reNgine/tasks/osint.py; re-exported by
reNgine.tasks.osint for backward compatibility.
"""
import logging
import shutil
import os
import yaml

from reNgine.common_func import *  # noqa: F401,F403
from reNgine.definitions import *  # noqa: F401,F403
from startScan.models import *  # noqa: F401,F403
from reNgine.utils.opsec import get_opsec_manager
from reNgine.tasks.persistence import save_metadata_info
from reNgine.tasks.scan_init import finish_osint, finish_osint_discovery
from reNgine.osint.email_leaks import run_emailfinder, run_leaksearch
from reNgine.osint.cloud_recon import run_msftrecon
from reNgine.osint.api_leaks import (
    run_porch_pirate,
    run_postleaks,
    run_swaggerspy_internet,
    run_swaggerspy_path_mode,
)
from reNgine.osint.post_crawl_metadata import run_post_crawl_exifray
from reNgine.osint.github_analysis import run_github_analysis
from reNgine.osint.misconfig import run_misconfig_mapper
from reNgine.osint.domain_security import run_spoofcheck
from dashboard.models import HunterIOAPIKey
from reNgine.tasks.osint.dorks import dorking
from reNgine.tasks.osint.people import theHarvester, osint_orchestrator
from reNgine.tasks.osint.breach_intel import h8mail, leaklookup
from reNgine.tasks.osint.secret_leaks import secret_scanning

logger = logging.getLogger(__name__)

def osint(self, host=None, ctx={}, description=None):
    """Run Open-Source Intelligence tools on selected domain.

    Args:
            host (str): Hostname to scan.

    Returns:
            dict: Results from osint discovery and dorking.
    """
    # Copy theHarvester api-keys.yaml to /root/.theHarvester/api-keys.yaml
    source_api_keys = "/usr/src/github/theHarvester/api-keys.yaml"
    target_dir = "/root/.theHarvester"
    target_api_keys = f"{target_dir}/api-keys.yaml"
    try:
        if os.path.exists(source_api_keys):
            os.makedirs(target_dir, exist_ok=True)
            shutil.copyfile(source_api_keys, target_api_keys)
            logger.info(
                "Copied theHarvester api-keys.yaml to /root/.theHarvester/api-keys.yaml"
            )
    except Exception as e:
        logger.error("Failed to copy theHarvester api-keys.yaml: %s", e)

    # Inject stored Hunter API key so theHarvester -b all uses Hunter as a source.
    try:
        hunter_key_obj = HunterIOAPIKey.objects.first()
        if hunter_key_obj and hunter_key_obj.key and os.path.exists(target_api_keys):
            with open(target_api_keys, "r") as _f:
                _yaml_data = yaml.safe_load(_f)
            if not isinstance(_yaml_data, dict):
                _yaml_data = {}
            if not isinstance(_yaml_data.get("apikeys"), dict):
                _yaml_data["apikeys"] = {}
            if not isinstance(_yaml_data["apikeys"].get("hunter"), dict):
                _yaml_data["apikeys"]["hunter"] = {}

            _yaml_data["apikeys"]["hunter"]["key"] = hunter_key_obj.key

            with open(target_api_keys, "w") as _f:
                yaml.dump(_yaml_data, _f)
            logger.info(
                "[HUNTER] Injected Hunter API key into theHarvester api-keys.yaml"
            )
    except Exception as e:
        logger.error("Failed to inject Hunter key into theHarvester YAML: %s", e)

    config = self.yaml_configuration.get(OSINT) or OSINT_DEFAULT_CONFIG
    results = {}

    results = []
    osint_host = (
        (ctx.get('subdomain_name') or '').strip()
        or (self.scan.domain.name if self.scan and self.scan.domain else '')
    )
    if ctx.get('singular_tool_run') and not osint_host:
        osint_host = self.scan.domain.name if self.scan and self.scan.domain else ''

    if "discover" in config:
        ctx["track"] = False
        results.append(
            osint_discovery(
                self,
                config=config,
                host=osint_host,
                scan_history_id=self.scan.id,
                activity_id=self.activity_id,
                results_dir=self.results_dir,
                ctx=ctx,
            )
        )

    if (
        OSINT_DORK in config
        or OSINT_CUSTOM_DORK in config
        or self.scan.cfg_custom_dorks
    ):
        results.append(
            dorking(
                config=config,
                host=osint_host,
                scan_history_id=self.scan.id,
                activity_id=self.activity_id,
                results_dir=self.results_dir,
                raw_dorks=self.scan.cfg_custom_dorks,
            )
        )

    if results:
        finish_osint(results, scan_history_id=self.scan.id)

    logger.info("Standard OSINT Tasks finished...")

    # Deep Pursuit OSINT Pipeline (holehe, maigret, LinkedInt)
    logger.info("Starting Deep Pursuit OSINT Pipeline...")
    osint_orchestrator(scan_history_id=self.scan.id)

    # Run h8mail after all OSINT tasks are finished
    osint_lookup = config.get(OSINT_DISCOVER, [])
    if "emails" in osint_lookup:
        h8mail(
            self,
            config=config,
            host=self.scan.domain.name,
            scan_history_id=self.scan.id,
            activity_id=self.activity_id,
            results_dir=self.results_dir,
            ctx=ctx,
        )

        # Run HaveIBeenPwned checks sequentially for all found emails
        logger.info("Starting HaveIBeenPwned playwright check for found emails...")
        from reNgine.osint.hibp_scraper import check_hibp_for_email_task

        for email_obj in self.scan.emails.all():
            check_hibp_for_email_task(email_obj.address, self.scan.id, email_obj.id)

    # WhatBreach: multi-source breach lookup using Hunter.io key
    wb_val = config.get(WHATBREACH, True)
    if wb_val:
        from reNgine.osint.whatbreach import run_whatbreach
        wb_config = wb_val if isinstance(wb_val, dict) else {}
        run_whatbreach(
            self, host, self.scan, self.results_dir,
            download_databases=wb_config.get(WHATBREACH_DOWNLOAD_DATABASES, False),
        )

    logger.info("OSINT Tasks finished...")
    return True


    # with open(self.output_path, 'w') as f:
    # 	json.dump(results, f, indent=4)
    #
    # return results


def osint_discovery(
    self, config, host, scan_history_id, activity_id, results_dir, ctx={}
):
    """Run OSINT discovery.

    Args:
            config (dict): yaml_configuration
            host (str): target name
            scan_history_id (startScan.ScanHistory): Scan History ID
            results_dir (str): Path to store scan results

    Returns:
            dict: osint metadata and theHarvester and h8mail results.
    """
    scan_history = ScanHistory.objects.get(pk=scan_history_id)
    osint_lookup = config.get(OSINT_DISCOVER, [])
    osint_intensity = config.get(INTENSITY, "normal")
    documents_limit = config.get(OSINT_DOCUMENTS_LIMIT, 50)
    results = {}
    meta_info = []
    emails = []
    creds = []

    # Get and save meta info
    if "metainfo" in osint_lookup:
        if osint_intensity == "normal":
            meta_dict = DottedDict(
                {
                    "osint_target": host,
                    "domain": host,
                    "scan_id": scan_history_id,
                    "documents_limit": documents_limit,
                }
            )
            meta_info.append(save_metadata_info(meta_dict))

        # TODO: disabled for now
        # elif osint_intensity == 'deep':
        # 	subdomains = Subdomain.objects
        # 	if self.scan:
        # 		subdomains = subdomains.filter(scan_history=self.scan)
        # 	for subdomain in subdomains:
        # 		meta_dict = DottedDict({
        # 			'osint_target': subdomain.name,
        # 			'domain': self.domain,
        # 			'scan_id': self.scan_id,
        # 			'documents_limit': documents_limit
        # 		})
        # 		meta_info.append(save_metadata_info(meta_dict))

    if "employees" in osint_lookup:
        ctx["track"] = False
        theHarvester(
            self,
            config=config,
            host=host,
            scan_history_id=scan_history_id,
            activity_id=activity_id,
            results_dir=results_dir,
            ctx=ctx,
        )

    if "emails" in osint_lookup and config.get(EMAILFINDER, True):
        run_emailfinder(self, host, scan_history, results_dir)

    leaks_config = config.get(LEAKS_AND_SECRETS, {})
    if leaks_config:
        if leaks_config.get(LEAKLOOKUP):
            leaklookup(
                self,
                host=host,
                scan_history_id=scan_history_id,
                activity_id=activity_id,
                results_dir=results_dir,
                ctx=ctx,
            )

        if leaks_config.get(LEAKSEARCH):
            run_leaksearch(self, host, scan_history, results_dir)

        if leaks_config.get(GITLEAKS) or leaks_config.get(TRUFFLEHOG):
            secret_scanning(
                self,
                config=leaks_config,
                host=host,
                scan_history_id=scan_history_id,
                activity_id=activity_id,
                results_dir=results_dir,
                ctx=ctx,
            )

    if config.get(MICROSOFT_RECON):
        run_msftrecon(self, host, scan_history, results_dir)

    api_leaks_config = config.get(API_LEAKS, {})
    if api_leaks_config:
        if api_leaks_config.get(PORCH_PIRATE):
            run_porch_pirate(self, host, scan_history, results_dir)
        if api_leaks_config.get(POSTLEAKS):
            run_postleaks(self, host, scan_history, results_dir)
        if api_leaks_config.get(SWAGGERSPY):
            run_swaggerspy_internet(self, host, scan_history, results_dir)

    github_config = config.get(GITHUB_ANALYSIS, {})
    if github_config:
        run_github_analysis(self, host, scan_history, results_dir, config)

    if config.get(MISCONFIG):
        run_misconfig_mapper(self, host, scan_history, results_dir)

    domain_security_config = config.get(DOMAIN_SECURITY, {})
    if domain_security_config and domain_security_config.get(SPOOFCHECK):
        run_spoofcheck(self, host, scan_history, results_dir)

    finish_osint_discovery([results], results_dir=results_dir)

    # Strip metadata from OSINT results
    opsec = get_opsec_manager()
    opsec.strip_directory(results_dir)

    return results


def post_crawl_osint(self, ctx={}, description=None):
    """Run OSINT tasks that benefit from post-fuzz data (discovered documents, live subdomains).

    Runs after dir_file_fuzz (Temporal Tier 4a). Reads fuzz-discovered documents
    from the DB and runs exifray + SwaggerSpy path probe against confirmed live hosts.
    """
    config = self.yaml_configuration.get(POST_CRAWL_OSINT) or {}
    osint_cfg = self.yaml_configuration.get(OSINT) or {}
    if not config and not osint_cfg.get(CREDSPY, False):
        logger.info("post_crawl_osint: no config — skipping for scan_id=%s", self.scan_id)
        return True

    host = self.domain.name if self.domain else ''

    if config.get(METAGOOFIL):
        run_post_crawl_exifray(self, host, ctx, self.results_dir)

    if config.get(SWAGGERSPY):
        run_swaggerspy_path_mode(self, host, self.scan, self.results_dir)

    # CredSpy runs post-crawl so autodiscover subdomains and MX records from
    # the crawl phase are in the DB before the Microsoft provider check runs.
    # Config key lives under osint: (where the UI writes it).
    if osint_cfg.get(CREDSPY, False):
        from reNgine.osint.credspy import run_credspy
        run_credspy(self, host, self.scan, self.results_dir)

    opsec = get_opsec_manager()
    opsec.strip_directory(self.results_dir)

    logger.info("post_crawl_osint finished for scan_id=%s", self.scan_id)
    return True
