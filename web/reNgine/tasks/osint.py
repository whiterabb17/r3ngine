import csv
import logging
import math
import re
import shutil
import subprocess
import threading
import json
import requests
import base64
import os
import yaml
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from django.db import transaction

from reNgine.common_func import *
from reNgine.definitions import *
from reNgine.parsers import SpiderFootBatchParser
from reNgine.utils.task import (
    run_command,
    stream_command,
    save_email,
    save_employee,
    save_subdomain,
    save_endpoint,
)
from reNgine.utils.opsec import get_opsec_manager, OpSecManager, ProxychainsWrapper
from reNgine.tasks.persistence import (
    save_metadata_info,
    save_ip_address,
    save_secret_leak,
)
from reNgine.tasks.geo import query_whois
from reNgine.tasks.scan_init import finish_osint, finish_osint_discovery
from reNgine.tasks.certificate import run_certificate_intel
from reNgine.tasks.vuln import semgrep_scan
from reNgine.osint.hibp_scraper import check_hibp_for_email_task
from reNgine.osint.linkedin_intelligence import LinkedInScraper
from reNgine.osint.hunter_lookup import run_hunter_lookup
from reNgine.osint.email_leaks import run_emailfinder, run_leaksearch
from reNgine.osint.cloud_recon import run_msftrecon
from reNgine.osint.api_leaks import run_porch_pirate, run_postleaks, run_swaggerspy_internet, run_swaggerspy_path_mode
from reNgine.osint.post_crawl_metadata import run_post_crawl_exifray
from reNgine.osint.github_analysis import run_github_analysis
from reNgine.osint.misconfig import run_misconfig_mapper
from reNgine.osint.domain_security import run_spoofcheck
from reNgine.utils.graph import Neo4jManager
from redis import Redis
from scanEngine.models import Proxy
from startScan.models import *
from startScan.models import Email, Employee
from targetApp.models import Domain
from dashboard.models import LinkedInCredentials, HunterIOAPIKey

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

    if "discover" in config:
        ctx["track"] = False
        results.append(
            osint_discovery(
                self,
                config=config,
                host=self.scan.domain.name,
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
                host=self.scan.domain.name,
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
            dict: osint metadat and theHarvester and h8mail results.
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


def dorking(
    config, host, scan_history_id, results_dir, activity_id=None, raw_dorks=None
):
    """Run Google dorks.

    Args:
            config (dict): yaml_configuration
            host (str): target name
            scan_history_id (startScan.ScanHistory): Scan History ID
            results_dir (str): Path to store scan results
            raw_dorks (str): Raw custom dorks list (one per line)

    Returns:
            list: Dorking results for each dork ran.
    """
    # Some dork sources: https://github.com/six2dez/degoogle_hunter/blob/master/degoogle_hunter.sh
    scan_history = ScanHistory.objects.get(pk=scan_history_id)
    dorks = config.get(OSINT_DORK, [])
    custom_dorks = config.get(OSINT_CUSTOM_DORK, [])
    results = []
    # custom dorking has higher priority
    try:
        for custom_dork in custom_dorks:
            if isinstance(custom_dork, str):
                # Handle simple string query from YAML
                query = custom_dork.replace("_target_", host)
                logger.info("Processing YAML custom dork: %s", query)
                get_and_save_dork_results(
                    lookup_target=host,
                    results_dir=results_dir,
                    type="custom_dork_yaml",
                    lookup_keywords=query,
                    scan_history=scan_history,
                    activity_id=activity_id,
                )
            elif isinstance(custom_dork, dict):
                # Handle structured dict from YAML
                lookup_target = custom_dork.get("lookup_site")
                # replace with original host if _target_
                lookup_target = host if lookup_target == "_target_" else lookup_target
                if "lookup_extensions" in custom_dork:
                    results = get_and_save_dork_results(
                        lookup_target=lookup_target,
                        results_dir=results_dir,
                        type="custom_dork",
                        lookup_extensions=custom_dork.get("lookup_extensions"),
                        scan_history=scan_history,
                        activity_id=activity_id,
                    )
                elif "lookup_keywords" in custom_dork:
                    results = get_and_save_dork_results(
                        lookup_target=lookup_target,
                        results_dir=results_dir,
                        type="custom_dork",
                        lookup_keywords=custom_dork.get("lookup_keywords"),
                        scan_history=scan_history,
                        activity_id=activity_id,
                    )
    except Exception as e:
        logger.error("Error processing custom dorks from YAML: %s", e)
        logger.exception(e)

    # Process raw custom dorks from UI/ScanHistory
    if raw_dorks:
        logger.info("Processing raw custom dorks...")
        try:
            custom_dork_list = raw_dorks.split("\n")
            for dork_query in custom_dork_list:
                dork_query = dork_query.strip()
                if dork_query:
                    # We use the raw query as keywords for GooFuzz
                    # Note: If dork_query starts with site:{host}, we strip it.
                    query_to_run = dork_query
                    if dork_query.startswith(f"site:{host} "):
                        query_to_run = dork_query.replace(f"site:{host} ", "", 1)
                    elif dork_query.startswith(f"site:{host}"):
                        query_to_run = dork_query.replace(f"site:{host}", "", 1)

                    get_and_save_dork_results(
                        lookup_target=host,
                        results_dir=results_dir,
                        type="custom_dork_ui",
                        lookup_keywords=query_to_run,
                        scan_history=scan_history,
                        activity_id=activity_id,
                    )
        except Exception as e:
            logger.exception(e)

    # default dorking
    try:
        for dork in dorks:
            logger.info("Getting dork information for %s", dork)
            if dork == "stackoverflow":
                results = get_and_save_dork_results(
                    lookup_target="stackoverflow.com",
                    results_dir=results_dir,
                    type=dork,
                    lookup_keywords=host,
                    scan_history=scan_history,
                )

            elif dork == "login_pages":
                results = get_and_save_dork_results(
                    lookup_target=host,
                    results_dir=results_dir,
                    type=dork,
                    lookup_keywords="/login/,login.html",
                    page_count=5,
                    scan_history=scan_history,
                )

            elif dork == "admin_panels":
                results = get_and_save_dork_results(
                    lookup_target=host,
                    results_dir=results_dir,
                    type=dork,
                    lookup_keywords="/admin/,admin.html",
                    page_count=5,
                    scan_history=scan_history,
                )

            elif dork == "dashboard_pages":
                results = get_and_save_dork_results(
                    lookup_target=host,
                    results_dir=results_dir,
                    type=dork,
                    lookup_keywords="/dashboard/,dashboard.html",
                    page_count=5,
                    scan_history=scan_history,
                )

            elif dork == "social_media":
                social_websites = [
                    "tiktok.com",
                    "facebook.com",
                    "twitter.com",
                    "youtube.com",
                    "reddit.com",
                ]
                for site in social_websites:
                    results = get_and_save_dork_results(
                        lookup_target=site,
                        results_dir=results_dir,
                        type=dork,
                        lookup_keywords=host,
                        scan_history=scan_history,
                    )

            elif dork == "project_management":
                project_websites = ["trello.com", "atlassian.net"]
                for site in project_websites:
                    results = get_and_save_dork_results(
                        lookup_target=site,
                        results_dir=results_dir,
                        type=dork,
                        lookup_keywords=host,
                        scan_history=scan_history,
                    )

            elif dork == "code_sharing":
                project_websites = ["github.com", "gitlab.com", "bitbucket.org"]
                for site in project_websites:
                    results = get_and_save_dork_results(
                        lookup_target=site,
                        results_dir=results_dir,
                        type=dork,
                        lookup_keywords=host,
                        scan_history=scan_history,
                    )

            elif dork == "config_files":
                config_file_exts = [
                    "env",
                    "xml",
                    "conf",
                    "toml",
                    "yml",
                    "yaml",
                    "cnf",
                    "inf",
                    "rdp",
                    "ora",
                    "txt",
                    "cfg",
                    "ini",
                ]
                results = get_and_save_dork_results(
                    lookup_target=host,
                    results_dir=results_dir,
                    type=dork,
                    lookup_extensions=",".join(config_file_exts),
                    page_count=4,
                    scan_history=scan_history,
                )

            elif dork == "jenkins":
                lookup_keyword = "Jenkins"
                results = get_and_save_dork_results(
                    lookup_target=host,
                    results_dir=results_dir,
                    type=dork,
                    lookup_keywords=lookup_keyword,
                    page_count=1,
                    scan_history=scan_history,
                )

            elif dork == "wordpress_files":
                lookup_keywords = ["/wp-content/", "/wp-includes/"]
                results = get_and_save_dork_results(
                    lookup_target=host,
                    results_dir=results_dir,
                    type=dork,
                    lookup_keywords=",".join(lookup_keywords),
                    page_count=5,
                    scan_history=scan_history,
                )

            elif dork == "php_error":
                lookup_keywords = ["PHP Parse error", "PHP Warning", "PHP Error"]
                results = get_and_save_dork_results(
                    lookup_target=host,
                    results_dir=results_dir,
                    type=dork,
                    lookup_keywords=",".join(lookup_keywords),
                    page_count=5,
                    scan_history=scan_history,
                )

            elif dork == "jenkins":
                lookup_keywords = ["PHP Parse error", "PHP Warning", "PHP Error"]
                results = get_and_save_dork_results(
                    lookup_target=host,
                    results_dir=results_dir,
                    type=dork,
                    lookup_keywords=",".join(lookup_keywords),
                    page_count=5,
                    scan_history=scan_history,
                )

            elif dork == "exposed_documents":
                docs_file_ext = [
                    "doc",
                    "docx",
                    "odt",
                    "pdf",
                    "rtf",
                    "sxw",
                    "psw",
                    "ppt",
                    "pptx",
                    "pps",
                    "csv",
                ]
                results = get_and_save_dork_results(
                    lookup_target=host,
                    results_dir=results_dir,
                    type=dork,
                    lookup_extensions=",".join(docs_file_ext),
                    page_count=7,
                    scan_history=scan_history,
                )

            elif dork == "db_files":
                file_ext = ["sql", "db", "dbf", "mdb"]
                results = get_and_save_dork_results(
                    lookup_target=host,
                    results_dir=results_dir,
                    type=dork,
                    lookup_extensions=",".join(file_ext),
                    page_count=1,
                    scan_history=scan_history,
                )

            elif dork == "git_exposed":
                file_ext = [
                    "git",
                ]
                results = get_and_save_dork_results(
                    lookup_target=host,
                    results_dir=results_dir,
                    type=dork,
                    lookup_extensions=",".join(file_ext),
                    page_count=1,
                    scan_history=scan_history,
                )

    except Exception as e:
        logger.exception(e)

    # --- Extended dork engines ---
    _DORKS_HUNTER_PYTHON = '/usr/src/github/dorks_hunter/.venv/bin/python3'
    _DORKS_HUNTER_SCRIPT = '/usr/src/github/dorks_hunter/dorks_hunter.py'
    dork_engines = config.get(DORK_ENGINES, [])

    if 'dorks_hunter' in dork_engines:
        dorks_output_file = f'{results_dir}/dorks_hunter_{host}.txt'
        cmd = [_DORKS_HUNTER_PYTHON, _DORKS_HUNTER_SCRIPT, '-d', host, '-o', dorks_output_file]
        proxy_obj = Proxy.objects.first()
        proxy = get_random_proxy() if proxy_obj and proxy_obj.use_proxy else None
        if proxy:
            cmd = ['proxychains4', '-q'] + cmd
        return_code, output = run_command(cmd, cwd=results_dir)
        try:
            with open(dorks_output_file, 'r') as _f:
                file_output = _f.read()
        except OSError:
            file_output = output or ''
        for line in file_output.splitlines():
            url = line.strip()
            if url.startswith('http'):
                dork, _ = Dork.objects.get_or_create(type='dorks_hunter', url=url)
                scan_history.dorks.add(dork)
                results.append(url)

    if 'xnldorker' in dork_engines:
        cmd = ['xnldorker', '-i', f'site:{host}', '-nb']
        proxy_obj = Proxy.objects.first()
        proxy = get_random_proxy() if proxy_obj and proxy_obj.use_proxy else None
        if proxy:
            cmd = ['proxychains4', '-q'] + cmd
        return_code, output = run_command(cmd, cwd=results_dir)
        for line in (output or '').splitlines():
            url = line.strip()
            if url.startswith('http'):
                dork, _ = Dork.objects.get_or_create(type='xnldorker', url=url)
                scan_history.dorks.add(dork)
                results.append(url)

    return results


def theHarvester(self, config, host, scan_history_id, activity_id, results_dir, ctx={}):
    """Run theHarvester to get save emails, hosts, employees found in domain.

    Args:
            config (dict): yaml_configuration
            host (str): target name
            scan_history_id (startScan.ScanHistory): Scan History ID
            activity_id: ScanActivity ID
            results_dir (str): Path to store scan results
            ctx (dict): context of scan

    Returns:
            dict: Dict of emails, employees, hosts and ips found during crawling.
    """
    scan_history = ScanHistory.objects.get(pk=scan_history_id)
    enable_http_crawl = config.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)
    output_path_json = f"{results_dir}/theHarvester.json"
    theHarvester_dir = "/usr/src/github/theHarvester"
    history_file = f"{results_dir}/commands.txt"

    # Update proxies.yaml
    proxy_query = Proxy.objects.all()
    if proxy_query.exists():
        proxy = proxy_query.first()
        if proxy.use_proxy:
            proxy_list = proxy.proxies.splitlines()
            yaml_data = {"http": proxy_list}
            with open(f"{theHarvester_dir}/proxies.yaml", "w") as file:
                yaml.dump(yaml_data, file)

    # Run cmd
    logger.info("theHarvester started")
    cmd = f"uv run theHarvester -d {host} -b all -f {output_path_json}"
    logger.warning("TheHarvester command: %s", cmd)
    run_command(
        cmd,
        shell=True,
        cwd=theHarvester_dir,
        history_file=history_file,
        scan_id=scan_history_id,
        activity_id=activity_id,
    )

    # Get file location
    if not os.path.isfile(output_path_json):
        logger.error("Could not open %s", output_path_json)
        return {}

    # Load theHarvester results
    with open(output_path_json, "r") as f:
        data = json.load(f)

    # Re-indent theHarvester JSON
    with open(output_path_json, "w") as f:
        json.dump(data, f, indent=4)

    emails = data.get("emails", [])
    for email_address in emails:
        email, _ = save_email(email_address, scan_history=scan_history)
        if email:
            self.notify(fields={"Emails": f"• `{email.address}`"})

    linkedin_people = data.get("linkedin_people", [])
    for people in linkedin_people:
        employee, _ = save_employee(
            people, designation="linkedin", scan_history=scan_history
        )
        if employee:
            self.notify(fields={"LinkedIn people": f"• {employee.name}"})

    twitter_people = data.get("twitter_people", [])
    for people in twitter_people:
        employee, _ = save_employee(
            people, designation="twitter", scan_history=scan_history
        )
        if employee:
            self.notify(fields={"Twitter people": f"• {employee.name}"})

    hosts = data.get("hosts", [])
    urls = []
    for host in hosts:
        split = tuple(host.split(":"))
        http_url = split[0]
        subdomain_name = get_subdomain_from_url(http_url)
        subdomain, _ = save_subdomain(subdomain_name, ctx=ctx)
        endpoint, _ = save_endpoint(http_url, crawl=False, ctx=ctx, subdomain=subdomain)
        if endpoint:
            urls.append(endpoint.http_url)
            self.notify(fields={"Hosts": f"• {endpoint.http_url}"})

    # if enable_http_crawl:
    # 	ctx['track'] = False
    # 	http_crawl(urls, ctx=ctx)

    # TODO: Lots of ips unrelated with our domain are found, disabling
    # this for now.
    # ips = data.get('ips', [])
    # for ip_address in ips:
    # 	ip, created = save_ip_address(
    # 		ip_address,
    # 		subscan=subscan)
    # 	if ip:
    # 		send_task_notif.delay(
    # 			'osint',
    # 			scan_history_id=scan_history_id,
    # 			subscan_id=subscan_id,
    # 			severity='success',
    # 			update_fields={'IPs': f'{ip.address}'})
    return data


def h8mail(self, config, host, scan_history_id, activity_id, results_dir, ctx={}):
    """Run h8mail.

    Args:
            config (dict): yaml_configuration
            host (str): target name
            scan_history_id (startScan.ScanHistory): Scan History ID
            activity_id: ScanActivity ID
            results_dir (str): Path to store scan results
            ctx (dict): context of scan

    Returns:
            list[dict]: List of credentials info.
    """
    logger.warning("Getting leaked credentials")
    scan_history = ScanHistory.objects.get(pk=scan_history_id)
    input_path = f"{results_dir}/emails.txt"
    output_file = f"{results_dir}/h8mail.json"

    # Retrieve all emails from DB and create emails.txt if not exists or update it
    emails = scan_history.emails.all()
    emails_list = [email.address for email in emails]

    target = ctx.get("target")
    if target and target not in emails_list:
        emails_list.append(target)

    if not emails_list:
        logger.warning("No emails found to run h8mail against. Skipping.")
        return []

    with open(input_path, "w") as f:
        for email in set(emails_list):
            f.write(f"{email}\n")

    cmd = f"h8mail -t {input_path} --json {output_file}"
    history_file = f"{results_dir}/commands.txt"

    run_command(
        cmd, history_file=history_file, scan_id=scan_history_id, activity_id=activity_id
    )

    if os.path.exists(output_file):
        try:
            with open(output_file) as f:
                data = json.load(f)
                creds = data.get("targets", [])
        except Exception as e:
            logger.error("Error reading h8mail output: %s", e)
            creds = []
    else:
        logger.warning("h8mail output file %s not found.", output_file)
        creds = []

    # TODO: go through h8mail output and save emails to DB
    for cred in creds:
        logger.warning(cred)
        email_address = cred["target"]
        pwn_num = cred["pwn_num"]
        pwn_data = cred.get("data", [])
        email, created = save_email(email_address, scan_history=scan_history)
        # if email:
        # 	self.notify(fields={'Emails': f'• `{email.address}`'})
    return creds


def leaklookup(self, host=None, ctx=None, **kwargs):
    """Run LeakLookup and ProjectDiscovery query."""
    leaklookup_api_key = get_leaklookup_key()
    chaos_api_key = get_chaos_api_key()

    if not leaklookup_api_key and not chaos_api_key:
        return "LeakLookup and ProjectDiscovery API keys not found. Skipping."

    results_summary = []

    # LeakLookup
    if leaklookup_api_key:
        try:
            url = "https://leak-lookup.com/api/search"
            params = {"key": leaklookup_api_key, "type": "domain", "query": host}
            response = requests.post(url, data=params, timeout=30)
            if response.status_code == 200:
                data = response.json()
                if data.get("error") == "false":
                    leaks = data.get("message") or {}
                    leak_count = 0
                    for db_name, contents in leaks.items():
                        for match in contents:
                            save_secret_leak(
                                scan_history=self.scan,
                                tool_name=LEAKLOOKUP,
                                secret_type="Data Leak",
                                source_url=db_name,
                                match_content=match,
                                status="unverified",
                            )
                            leak_count += 1
                    results_summary.append(
                        f"LeakLookup: Found {leak_count} leaks in {len(leaks)} databases"
                    )
                else:
                    results_summary.append(f"LeakLookup error: {data.get('message')}")
            else:
                results_summary.append(f"LeakLookup HTTP error: {response.status_code}")
        except Exception as e:
            logger.error("Error in LeakLookup: %s", e)
            results_summary.append("LeakLookup error: %s" % e)

    # ProjectDiscovery
    if chaos_api_key:
        try:
            pd_url = f"https://api.projectdiscovery.io/v1/leaks?type=all&time_range=all_time&domain={host}"
            headers = {"X-API-Key": chaos_api_key}
            response = requests.get(pd_url, headers=headers, timeout=30)
            if response.status_code == 200:
                data = response.json()
                leaks = data.get("data") or []
                leak_count = 0
                for match in leaks:
                    source_url = (
                        match.get("url") or match.get("url_domain") or "Unknown"
                    )
                    match_content = ""
                    if match.get("username"):
                        match_content += f"Username: {match.get('username')} "
                    if match.get("password"):
                        match_content += f"Password: {match.get('password')} "
                    if match.get("device_ip"):
                        match_content += f"IP: {match.get('device_ip')} "

                    save_secret_leak(
                        scan_history=self.scan,
                        tool_name=PROJECTDISCOVERY,
                        secret_type="Data Leak",
                        source_url=source_url,
                        match_content=match_content.strip(),
                        status="unverified",
                    )
                    leak_count += 1
                results_summary.append(f"ProjectDiscovery: Found {leak_count} leaks")
            else:
                results_summary.append(
                    f"ProjectDiscovery HTTP error: {response.status_code}"
                )
        except Exception as e:
            logger.error("Error in ProjectDiscovery: %s", e)
            results_summary.append("ProjectDiscovery error: %s" % e)

    return " | ".join(results_summary)


def secret_scanning(self, config=None, host=None, ctx=None, **kwargs):
    """Scan for secrets in JS files and potentially other sources.

    Args:
            config (dict, optional): Leaks and secrets configuration dictionary.
            host (str, optional): Target hostname.
            ctx (dict, optional): Scan activity context.
    """
    if not self.scan:
        return "No scan history found."

    if config is None:
        config = (
            self.yaml_configuration.get("secret_scanning")
            or self.yaml_configuration.get("leaks_and_secrets")
            or self.yaml_configuration.get("osint", {}).get("leaks_and_secrets")
            or {}
        )

    endpoints = EndPoint.objects.filter(scan_history=self.scan)
    # Sensitive extensions to scan
    SENSITIVE_EXTENSIONS = (
        ".js",
        ".env",
        ".php",
        ".asp",
        ".aspx",
        ".jsp",
        ".jspx",
        ".txt",
        ".log",
        ".conf",
        ".config",
        ".bak",
        ".old",
        ".json",
        ".yaml",
        ".yml",
    )
    target_endpoints = [
        e for e in endpoints if e.http_url.lower().endswith(SENSITIVE_EXTENSIONS)
    ]

    if not target_endpoints:
        return "No sensitive files found to scan."

    # Cap at 70% to bound download time on large scans.
    total_found = len(target_endpoints)
    cap = max(1, math.ceil(total_found * 0.70))
    target_endpoints = target_endpoints[:cap]
    logger.info(
        "secret_scanning: downloading %d / %d sensitive endpoints (70%% cap)",
        cap,
        total_found,
    )

    temp_dir = f"{self.results_dir}/secrets_temp"
    os.makedirs(temp_dir, exist_ok=True)

    def _download_one(js):
        filename = "".join([c if c.isalnum() else "_" for c in js.http_url]) + ".js"
        filepath = os.path.join(temp_dir, filename)
        try:
            resp = requests.get(js.http_url, timeout=10, verify=False)
            if resp.status_code == 200:
                with open(filepath, "w") as f:
                    f.write(resp.text)
        except Exception as e:
            logger.error("Failed to download %s: %s", js.http_url, e)

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(_download_one, js) for js in target_endpoints]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logger.error("Download thread error: %s", e)

    findings_count = 0

    # Run Gitleaks
    if config.get(GITLEAKS):
        report_path = f"{temp_dir}/gitleaks_report.json"
        # Gitleaks v8+ detect command
        subprocess.run(
            [
                "gitleaks",
                "detect",
                "--source",
                temp_dir,
                "--report-format",
                "json",
                "--report-path",
                report_path,
                "--exit-code",
                "0",
            ],
            check=False,
        )

        if os.path.exists(report_path):
            try:
                with open(report_path, "r") as f:
                    findings = json.load(f)
                    for finding in findings:
                        # Map finding to SecretLeak
                        save_secret_leak(
                            scan_history=self.scan,
                            tool_name=GITLEAKS,
                            secret_type=finding.get("Description", "Secret"),
                            source_url=finding.get("File", "Unknown"),
                            match_content=finding.get("Secret", ""),
                            status="unverified",
                        )
                        findings_count += 1
            except Exception as e:
                logger.error("Error parsing Gitleaks report: %s", e)

    # Run Trufflehog
    if config.get(TRUFFLEHOG):
        # Trufflehog v3 filesystem command
        process = subprocess.Popen(
            ["trufflehog", "filesystem", temp_dir, "--json"],
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = process.communicate()

        for line in stdout.decode().splitlines():
            if not line:
                continue
            try:
                finding = json.loads(line)
                # Trufflehog v3 output format varies, but usually has 'SourceMetadata' or 'DetectorName'
                save_secret_leak(
                    scan_history=self.scan,
                    tool_name=TRUFFLEHOG,
                    secret_type=finding.get("DetectorName", "Secret"),
                    source_url=finding.get("SourceMetadata", {})
                    .get("Data", {})
                    .get("Filesystem", {})
                    .get("file", "Unknown"),
                    match_content=finding.get("Raw", ""),
                    status="unverified",
                )
                findings_count += 1
            except Exception as e:
                logger.error("Error parsing Trufflehog finding: %s", e)

    # Run Betterleaks
    if config.get(BETTERLEAKS):
        # Betterleaks is typically run against files or a directory
        # It's good for finding secrets like API keys, passwords, etc.
        # Command: betterleaks -p {temp_dir}
        logger.info("Running Betterleaks on %s", temp_dir)
        process = subprocess.Popen(
            ["betterleaks", "-p", temp_dir],
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        stdout, stderr = process.communicate()
        logger.info("Betterleaks output: %s", stdout)
        for line in stdout.splitlines():
            if line.strip():
                # Assuming betterleaks outputs findings in a recognizable format
                # For now, let's just log it and save if it looks like a finding
                if any(
                    keyword in line.lower()
                    for keyword in ["key", "password", "secret", "token", "found"]
                ):
                    save_secret_leak(
                        scan_history=self.scan,
                        tool_name=BETTERLEAKS,
                        secret_type="Potential Secret",
                        source_url="Discovered Files",
                        match_content=line.strip(),
                        status="unverified",
                    )
                    findings_count += 1

    # Run Semgrep Secret Scan (Default)
    try:
        logger.info("Running Semgrep Secret Scan...")
        semgrep_scan(self, ctx=ctx, mode="secret", description="Semgrep Secret Scan")
    except Exception as e:
        logger.error("Semgrep secret scan failed: %s", e)

    # Cleanup
    shutil.rmtree(temp_dir, ignore_errors=True)

    return f"Secret scanning completed. Found {findings_count} findings."


def spiderfoot_scan(self, host=None, ctx={}, description=None):
    """Run SpiderFoot scan on selected domain with real-time batch parsing."""
    # host selection logic based on user rules
    if not host:
        if self.subscan_id and self.subdomain:
            host = self.subdomain.name
        else:
            host = self.domain.name

    logger.warning(
        "[SPIDERFOOT] Starting scan for target: %s (Scan ID: %s, Subscan ID: %s)",
        host,
        self.scan_id,
        self.subscan_id,
    )

    if not self.yaml_configuration:
        # yaml_configuration may be empty when the engine YAML was not correctly passed
        # through ctx (e.g. Temporal replay edge-case, or test proxy with empty dict).
        # Fall back to loading the engine YAML directly from the DB via self.engine.
        if self.engine:
            import yaml as _yaml

            _raw = self.engine.yaml_configuration or ""
            self.yaml_configuration = _yaml.safe_load(_raw) or {}
            logger.warning(
                "[SPIDERFOOT] yaml_configuration was empty — reloaded from engine '%s' (id=%s)",
                self.engine.engine_name,
                self.engine.id,
            )
        else:
            logger.error(
                "[SPIDERFOOT] yaml_configuration is empty and no engine found! Check engine config."
            )

    config = self.yaml_configuration.get(SPIDERFOOT_SCAN) or {}
    modules = config.get("modules", "all")
    threads = config.get("threads") or self.yaml_configuration.get("threads", 5)
    intensity = config.get("intensity", "normal")  # normal, fast, deep

    # Spiderfoot CLI intensity mapping (profiles)
    profile_cmd = ""
    if intensity == "fast":
        profile_cmd = "-u footprint"
    elif intensity == "deep":
        profile_cmd = "-u all"

    if modules != "all":
        profile_cmd = f"-m {modules}"
    elif not profile_cmd:
        profile_cmd = "-u investigate"

    # Use global SF config
    sf_config_path = "/usr/src/github/spiderfoot/spiderfoot.cfg"
    sf_exec_path = "/usr/src/github/spiderfoot/sf.py"

    if not os.path.exists(sf_exec_path):
        logger.error(
            "[SPIDERFOOT] SpiderFoot executable not found at %s!", sf_exec_path
        )
        return

    if not os.path.exists(sf_config_path):
        logger.error(
            "[SPIDERFOOT] SpiderFoot config not found at %s. Task may fail or use defaults.",
            sf_config_path,
        )

    # Use CSV output for streaming. -r includes source data, -n strips newlines.
    cmd = f"python3 {sf_exec_path} -s {host} {profile_cmd} -max-threads {threads} -o csv -r -n"
    logger.warning("[SPIDERFOOT] Executing command: %s", cmd)

    # Check for custom spiderfoot keys and write to spiderfoot.cfg
    try:
        from dashboard.models import SpiderfootAPIKey

        sf_keys = SpiderfootAPIKey.objects.all()
        if sf_keys.exists() and os.path.exists(sf_config_path):
            with open(sf_config_path, "r") as f:
                original_lines = f.readlines()

            key_dict = {
                f"{k.module_name}:{k.key_name}": k.key_value
                for k in sf_keys
                if k.key_value
            }
            new_lines = []
            changed = False

            for line in original_lines:
                if "=" in line:
                    prefix = line.split("=")[0].strip()
                    if prefix in key_dict:
                        new_val = key_dict.pop(prefix)
                        expected_line = f"{prefix}={new_val}\n"
                        if line != expected_line:
                            new_lines.append(expected_line)
                            changed = True
                        else:
                            new_lines.append(line)
                    else:
                        new_lines.append(line)
                else:
                    new_lines.append(line)

            if key_dict:
                changed = True
                for k, v in key_dict.items():
                    new_lines.append(f"{k}={v}\n")

            if changed:
                with open(sf_config_path, "w") as f:
                    f.writelines(new_lines)
    except Exception as e:
        logger.error("[SPIDERFOOT] Failed to write API keys: %s", e)

    # Initialize stateful parser with Redis dedup
    from django.conf import settings

    redis_client = Redis(
        host=settings.REDIS_HOST,
        port=settings.REDIS_PORT,
        password=settings.REDIS_PASSWORD,
        decode_responses=True,
    )
    parser = SpiderFootBatchParser(
        dedup_backend=redis_client, scan_id=self.scan_id, target_domain=self.domain.name
    )

    # Proxy List Integration
    proxy_str = None
    try:
        proxies = get_proxy_list()
        if proxies:
            proxy_str = "\n".join(proxies)
    except Exception as e:
        logger.debug("[SPIDERFOOT] Failed to fetch proxy list: %s", e)

    batch: list = []
    batch_size = 50  # keep transactions small for large scans

    # Stream output line-by-line via Popen — run_command buffers ALL stdout into a
    # DB field before returning, which causes a PostgreSQL allocation error when
    # SpiderFoot produces >~100 MB of CSV output.
    try:
        proc = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        try:
            for raw_line in proc.stdout:
                event = parser.parse_line(raw_line.rstrip("\n\r"))
                if not event:
                    continue
                batch.append(event)
                if len(batch) >= batch_size:
                    _process_spiderfoot_batch(self, batch, ctx, host)
                    batch = []

            if batch:
                _process_spiderfoot_batch(self, batch, ctx, host)

        finally:
            proc.stdout.close()
            return_code = proc.wait()
            if return_code != 0:
                stderr_tail = proc.stderr.read(2000)
                if stderr_tail:
                    logger.warning("[SPIDERFOOT] Process exited %s: %s", return_code, stderr_tail)
            proc.stderr.close()

    except Exception as e:
        logger.error("[SPIDERFOOT] Execution failed: %s", e)

    # Sync to Neo4j
    graph = Neo4jManager()
    graph.sync_scan_results(self.scan_id)
    graph.close()


# ---------------------------------------------------------------------------
# Per-type persistence handlers — called by TYPE_ROUTER
# ---------------------------------------------------------------------------


def _handle_subdomain(
    scan_history, domain, e_data, source_data, ctx, activity_id, metadata
):
    save_subdomain(e_data.lower(), ctx=ctx)


def _handle_email(
    scan_history, domain, e_data, source_data, ctx, activity_id, metadata
):
    save_email(e_data.lower(), scan_history=scan_history)


def _handle_employee(
    scan_history, domain, e_data, source_data, ctx, activity_id, metadata
):
    save_employee(e_data, scan_history=scan_history)


def _handle_url(scan_history, domain, e_data, source_data, ctx, activity_id, metadata):
    if is_valid_url(e_data):
        save_endpoint(e_data, ctx=ctx)


def _handle_ip(scan_history, domain, e_data, source_data, ctx, activity_id, metadata):
    save_ip_address(e_data, scan_id=scan_history.id, activity_id=activity_id)


def _handle_port(scan_history, domain, e_data, source_data, ctx, activity_id, metadata):
    if ":" in e_data:
        ip_part, port_part = e_data.split(":", 1)
        if port_part.isdigit():
            port_num = int(port_part)
            res = get_port_service_description(port_num)
            port_obj, _ = update_or_create_port(
                port_num,
                service_name=res.get("service_name"),
                description=res.get("description"),
            )
            ip_obj, _ = save_ip_address(
                ip_part, scan_id=scan_history.id, activity_id=activity_id
            )
            if ip_obj:
                ip_obj.ports.add(port_obj)
    elif e_data.isdigit():
        update_or_create_port(int(e_data))


def _handle_tech(scan_history, domain, e_data, source_data, ctx, activity_id, metadata):
    from django.core.exceptions import MultipleObjectsReturned

    try:
        tech_obj, _ = Technology.objects.get_or_create(name=e_data)
    except MultipleObjectsReturned:
        tech_obj = Technology.objects.filter(name=e_data).first()
    if source_data:
        subdomain = Subdomain.objects.filter(
            name=source_data, scan_history=scan_history
        ).first()
        if subdomain:
            subdomain.technologies.add(tech_obj)


def _handle_leak(scan_history, domain, e_data, source_data, ctx, activity_id, metadata):
    save_secret_leak(
        scan_history=scan_history,
        tool_name="SpiderFoot",
        secret_type=metadata.get("sf_type") or "Sensitive Data",
        source_url=source_data or "SpiderFoot Findings",
        match_content=e_data,
    )


def _handle_ssl(
    scan_history,
    domain,
    e_data: str,
    source_data: str,
    ctx,
    activity_id,
    metadata: dict,
) -> None:
    from startScan.models import CertificateIntelligence

    source_host = metadata.get("host") or source_data or ""
    results_dir = getattr(scan_history, "results_dir", None) or (ctx or {}).get(
        "results_dir", ""
    )

    if source_host and results_dir:
        try:
            logger.info(
                "[SSL] Running cert intel for scan %s via staging confirm",
                scan_history.id,
            )
            # run_certificate_intel rescans ALL live subdomains for this scan (not just source_host).
            # This is intentional — tlsx is idempotent and enriches the full cert intel for the scan.
            run_certificate_intel(scan_history.id, results_dir)
            return
        except Exception as exc:
            logger.error(
                "[SSL] cert intel failed for scan %s: %s", scan_history.id, exc
            )

    # Fallback: partial record with available fields
    logger.debug(
        "[SSL] Creating partial cert record for host %s", source_host or e_data
    )
    CertificateIntelligence.objects.get_or_create(
        target_domain=domain,
        host=source_host or e_data,
        defaults={
            "scan_history": scan_history,
            "subject_cn": metadata.get("subject_cn"),
            "issuer_cn": metadata.get("issuer"),
        },
    )


def _handle_dns(
    scan_history,
    domain,
    e_data: str,
    source_data: str,
    ctx,
    activity_id,
    metadata: dict,
) -> None:
    from startScan.models import DnsRecord, Subdomain

    record_type = metadata.get("record_type", "TXT")
    hostname = metadata.get("hostname") or source_data or ""

    subdomain_obj = None
    if hostname:
        subdomain_obj = Subdomain.objects.filter(
            name=hostname, scan_history=scan_history
        ).first()

    DnsRecord.objects.update_or_create(
        scan_history=scan_history,
        record_type=record_type,
        value=e_data,
        defaults={
            "target_domain": domain,
            "subdomain": subdomain_obj,
            "source": source_data or "",
            "raw_metadata": metadata,
        },
    )


def _handle_phone(
    scan_history,
    domain,
    e_data: str,
    source_data: str,
    ctx,
    activity_id,
    metadata: dict,
) -> None:
    from startScan.models import Employee

    employee = Employee.objects.create(
        name=None,
        metadata={
            "type": "phone",
            "phone": metadata.get("phone_number") or e_data,
            "source_url": source_data or "",
            "discovered_by": "SpiderFoot",
        },
    )
    if scan_history:
        scan_history.employees.add(employee)


def _handle_social(
    scan_history,
    domain,
    e_data: str,
    source_data: str,
    ctx,
    activity_id,
    metadata: dict,
) -> None:
    from startScan.models import Employee

    employee = Employee.objects.create(
        name=None,
        metadata={
            "type": "social",
            "social_url": metadata.get("profile_url") or e_data,
            "platform": metadata.get("platform", "Unknown"),
            "source": source_data or "",
            "discovered_by": "SpiderFoot",
        },
    )
    if scan_history:
        scan_history.employees.add(employee)


def _handle_os(
    scan_history,
    domain,
    e_data: str,
    source_data: str,
    ctx,
    activity_id,
    metadata: dict,
) -> None:
    from django.core.exceptions import MultipleObjectsReturned

    os_name = metadata.get("os_name") or e_data
    source_host = metadata.get("source_host") or source_data or ""

    try:
        tech_obj, _ = Technology.objects.get_or_create(name=os_name)
    except MultipleObjectsReturned:
        tech_obj = Technology.objects.filter(name=os_name).first()

    if source_host:
        subdomain = Subdomain.objects.filter(
            name=source_host, scan_history=scan_history
        ).first()
        if subdomain:
            subdomain.technologies.add(tech_obj)
        else:
            logger.debug(
                "[OSINT] OS handler: no subdomain found for host %s", source_host
            )


def _handle_crypto(
    scan_history,
    domain,
    e_data: str,
    source_data: str,
    ctx,
    activity_id,
    metadata: dict,
) -> None:
    address_type = metadata.get("address_type", "Unknown")
    logger.info(
        "[OSINT] Validated crypto address: %s %s (scan=%s)",
        address_type,
        e_data,
        scan_history.id,
    )


def _handle_hosting(
    scan_history,
    domain,
    e_data: str,
    source_data: str,
    ctx,
    activity_id,
    metadata: dict,
) -> None:
    co_domain = (metadata.get("co_hosted_domain") or e_data).lower()
    save_subdomain(co_domain, ctx=ctx)


# Populated with new handlers after Tasks 4-6; entries added incrementally.
TYPE_ROUTER: dict = {
    "Subdomain": _handle_subdomain,
    "Email": _handle_email,
    "Employee": _handle_employee,
    "URL": _handle_url,
    "IP": _handle_ip,
    "Port": _handle_port,
    "Tech": _handle_tech,
    "Leak": _handle_leak,
    "SSL": _handle_ssl,
    "DNS": _handle_dns,
    "Phone": _handle_phone,
    "Social": _handle_social,
    "OS": _handle_os,
    "Crypto": _handle_crypto,
    "Hosting": _handle_hosting,
}


def persist_osint_item(
    scan_history,
    domain,
    osint_type: str,
    e_data: str,
    confidence: int,
    source_data: str = None,
    event_type: str = None,  # deprecated — unused; handlers read metadata.get('sf_type') instead
    ctx: dict = None,
    activity_id=None,
    metadata: dict = None,
) -> None:
    """Route an OSINT item to the correct persistence handler via TYPE_ROUTER."""
    handler = TYPE_ROUTER.get(osint_type)
    if handler:
        handler(
            scan_history, domain, e_data, source_data, ctx, activity_id, metadata or {}
        )
    else:
        logger.debug("[OSINT] No handler for osint_type %s", osint_type)


_DNS_SF_TYPE_TO_RECORD = {
    "DNS_TXT_RECORD": "TXT",
    "DNS_MX_RECORD": "MX",
    "DNS_NS_RECORD": "NS",
    "NAME_SERVER_(DNS_NS_RECORDS)": "NS",
    "EMAIL_GATEWAY_(DNS_MX_RECORDS)": "MX",
    "RAW_DNS_RECORDS": "TXT",
    "PROVIDER_DNS": "NS",
}


def _enrich_metadata(event: dict, base_metadata: dict) -> dict:
    """Add type-specific structured keys to OsintStaging metadata for frontend rendering."""
    osint_type = event.get("osint_type", "")
    e_data = event.get("data", "")
    source_data = event.get("source_data", "")
    sf_type = event.get("type", "")

    extra: dict = {}

    if osint_type == "SSL":
        subject_cn = None
        issuer = None
        if "CN=" in e_data:
            parts = {}
            for segment in e_data.split(","):
                segment = segment.strip()
                if "=" in segment:
                    k, _, v = segment.partition("=")
                    parts[k.strip()] = v.strip()
            subject_cn = parts.get("CN")
            issuer = parts.get("O")
        extra = {
            "host": subject_cn or source_data or "",
            "subject_cn": subject_cn,
            "issuer": issuer,
        }

    elif osint_type == "DNS":
        extra = {
            "record_type": _DNS_SF_TYPE_TO_RECORD.get(sf_type, "TXT"),
            "hostname": source_data or "",
            "value": e_data,
        }

    elif osint_type == "Phone":
        extra = {
            "phone_number": e_data,
            "source_url": source_data or "",
        }

    elif osint_type == "Social":
        url_lower = e_data.lower()
        if "linkedin.com" in url_lower:
            platform = "LinkedIn"
        elif "twitter.com" in url_lower or "x.com" in url_lower:
            platform = "Twitter/X"
        elif "facebook.com" in url_lower:
            platform = "Facebook"
        elif "instagram.com" in url_lower:
            platform = "Instagram"
        elif "github.com" in url_lower:
            platform = "GitHub"
        else:
            platform = "Unknown"
        extra = {
            "platform": platform,
            "profile_url": e_data,
        }

    elif osint_type == "OS":
        extra = {
            "os_name": e_data,
            "source_host": source_data or "",
        }

    elif osint_type == "Crypto":
        extra = {
            "address_type": "ETH" if e_data.startswith("0x") else "BTC",
            "address": e_data,
        }

    elif osint_type == "Hosting":
        extra = {
            "co_hosted_domain": e_data,
        }

    return {**base_metadata, **extra}


def _process_spiderfoot_batch(self, batch, ctx, host):
    """Internal helper to process a batch of SpiderFoot findings with tiered validation."""
    try:
        with transaction.atomic():
            for event in batch:
                e_type = event.get("type")
                e_data = event.get("data")
                osint_type = event.get("osint_type")
                confidence = event.get("confidence", 0)

                if not osint_type or not e_data:
                    continue

                # Automated Persistence (High Confidence)
                if confidence > 80:
                    auto_meta = _enrich_metadata(
                        event,
                        {
                            "sf_type": e_type,
                            "source_data": event.get("source_data"),
                            "iocs": event.get("iocs"),
                        },
                    )
                    persist_osint_item(
                        scan_history=self.scan,
                        domain=self.domain,
                        osint_type=osint_type,
                        e_data=e_data,
                        confidence=confidence,
                        source_data=event.get("source_data"),
                        event_type=e_type,
                        ctx=ctx,
                        activity_id=self.activity_id,
                        metadata=auto_meta,
                    )

                # Staging Area (Moderate Confidence: 50% -> 80%)
                elif 50 <= confidence <= 80:
                    base_meta = {
                        "sf_type": e_type,
                        "source_data": event.get("source_data"),
                        "iocs": event.get("iocs"),
                    }
                    enriched_meta = _enrich_metadata(event, base_meta)
                    OsintStaging.objects.update_or_create(
                        scan_history=self.scan,
                        target_domain=self.domain,
                        content=e_data,
                        osint_type=osint_type,
                        defaults={
                            "source": event.get("source", "SpiderFoot"),
                            "confidence": confidence,
                            "metadata": enriched_meta,
                            "status": "pending",
                        },
                    )
                else:
                    # Discard low confidence noise
                    logger.debug(
                        "[SPIDERFOOT] Discarding low confidence finding: %s - %s (%s%%)",
                        osint_type,
                        e_data,
                        confidence,
                    )

        logger.warning(
            "Processed batch of %d SpiderFoot findings with validation.", len(batch)
        )
    except Exception as e:
        logger.error("Error processing SpiderFoot batch: %s", e)


def get_and_save_dork_results(
    lookup_target,
    results_dir,
    type,
    lookup_keywords=None,
    lookup_extensions=None,
    delay=3,
    page_count=2,
    scan_history=None,
    activity_id=None,
):
    """
    Uses gofuzz to dork and store information

    Args:
            lookup_target (str): target to look into such as stackoverflow or even the target itself
            results_dir (str): Results directory
            type (str): Dork Type Title
            lookup_keywords (str): comma separated keywords or paths to look for
            lookup_extensions (str): comma separated extensions to look for
            delay (int): delay between each requests
            page_count (int): pages in google to extract information
            scan_history (startScan.ScanHistory): Scan History Object
    """
    results = []
    # Use quotes around arguments to handle spaces and special characters safely in the shell
    gofuzz_command = (
        f'{GOFUZZ_EXEC_PATH} -t "{lookup_target}" -d {delay} -p {page_count}'
    )
    proxy = get_random_proxy()

    if lookup_extensions:
        gofuzz_command += f' -e "{lookup_extensions}"'
    elif lookup_keywords:
        # Double quote keywords to preserve complex dork queries, escaping any inner quotes
        escaped_keywords = lookup_keywords.replace('"', '\\"')
        gofuzz_command += f' -w "{escaped_keywords}"'

    if proxy:
        gofuzz_command += f' -r "{proxy}"'

    output_file = f"{results_dir}/gofuzz.txt"
    gofuzz_command += f' -o "{output_file}"'
    history_file = f"{results_dir}/commands.txt"

    try:
        # proxy already embedded via -r flag above; don't also pass proxy= kwarg
        # or run_command would double-wrap with proxychains when use_proxychains=True
        run_command(
            gofuzz_command,
            shell=True,  # Use shell=True to handle quoted arguments correctly
            history_file=history_file,
            scan_id=scan_history.id if scan_history else None,
            activity_id=activity_id,
        )

        if not os.path.isfile(output_file):
            return

        with open(output_file) as f:
            for line in f.readlines():
                url = line.strip()
                if url:
                    results.append(url)
                    dork, created = Dork.objects.get_or_create(type=type, url=url)
                    if scan_history:
                        scan_history.dorks.add(dork)

        # remove output file
        os.remove(output_file)

    except Exception as e:
        logger.exception(e)

    return results


def run_holehe(email_address, scan_history_id):
    """
    Run holehe for a specific email address to find associated social media accounts.
    """
    try:
        scan_history = ScanHistory.objects.get(pk=scan_history_id)
        proxy_obj = Proxy.objects.first()
        proxy = get_random_proxy() if proxy_obj and proxy_obj.use_proxy else None

        cmd = ['holehe', email_address, '--only-used']

        # holehe doesn't have a direct JSON output to file via CLI easily in some versions,
        # but we can capture stdout or check if we can use it as a library.
        # For now, let's run it and capture the output.

        if proxy:
            # Wrap with proxychains if needed or use holehe's proxy support if available
            # holehe doesn't have native proxy flags in all versions
            cmd = ['proxychains4', '-q'] + cmd

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()

        # Simple parsing of holehe output
        found_sites = []
        for line in stdout.splitlines():
            if '[+]' in line:
                site = line.split('[+]')[1].strip()
                found_sites.append(site)

        if found_sites:
            email, _ = save_email(email_address, scan_history=scan_history)
            metadata = email.metadata or {}
            metadata['holehe'] = found_sites
            email.metadata = metadata
            email.save()

        return found_sites
    except Exception as e:
        logger.error("Error running holehe for %s: %s", email_address, str(e))
        return []


def run_maigret(username, scan_history_id):
    """
    Run maigret to find social media profiles for a given username.
    """
    try:
        scan_history = ScanHistory.objects.get(pk=scan_history_id)
        results_dir = "%s/osint/maigret" % scan_history.results_dir
        os.makedirs(results_dir, exist_ok=True)

        output_file = "%s/%s.json" % (results_dir, username)

        proxy_obj = Proxy.objects.first()
        proxy = get_random_proxy() if proxy_obj and proxy_obj.use_proxy else None

        cmd = ['maigret', username, '--json', output_file]

        if proxy:
            # maigret supports --proxy
            cmd += ['--proxy', proxy]

        subprocess.run(cmd, capture_output=True, text=True)

        profiles = []
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                data = json.load(f)
                # maigret JSON structure varies, but we want the list of sites found
                for site, info in data.get('results', {}).items():
                    if info.get('status') == 'CLAIMED':
                        profiles.append({
                            'site': site,
                            'url': info.get('url_user')
                        })

        if profiles:
            employee, _ = save_employee(username, scan_history=scan_history)
            metadata = employee.metadata or {}
            metadata['maigret'] = profiles
            employee.metadata = metadata
            employee.save()

        return profiles
    except Exception as e:
        logger.error("Error running maigret for %s: %s", username, str(e))
        return []


def run_linkedint(company_name, scan_history_id):
    """
    Run LinkedIn Scraper (Playwright) to scrape employees for a company.
    Returns a list of result strings. Never raises — logs notes on auth failure.
    """
    try:
        scan_history = ScanHistory.objects.get(pk=scan_history_id)
        domain = scan_history.domain.name

        session = LinkedInCredentials.objects.first()
        hunter_key = HunterIOAPIKey.objects.first()

        if not session:
            logger.warning("LinkedIn session not configured for %s. Skipping.", company_name)
            return []

        if not hunter_key or not hunter_key.key:
            logger.warning("Hunter.io API key not configured for %s. Skipping.", company_name)
            return []

        with LinkedInScraper(session=session, hunter_key=hunter_key.key) as scraper:
            employees = scraper.discover_employees(company_name, domain, scan_history)

            for note in scraper.notes:
                logger.warning("%s", note)

            if employees:
                for emp_data in employees:
                    emp, _ = save_employee(emp_data['name'], scan_history=scan_history)
                    emp.designation = emp_data['designation']
                    emp.save()
                    if 'email' in emp_data:
                        save_email(emp_data['email'], scan_history=scan_history)

            return ["LinkedIn Intelligence processed %d employees for %s" % (len(employees), company_name)]

    except Exception as exc:
        logger.error("Error running LinkedIn Intelligence for %s: %s", company_name, type(exc).__name__)
        return []


def enrich_identities_task(identity, identity_type, scan_history_id, ctx={}):
    """
    Enrich identities using username-anarchy and gosearch.
    identity: Email or Name
    identity_type: 'email' or 'employee'
    """
    from startScan.models import OsintStaging, Domain
    try:
        scan_history = ScanHistory.objects.get(pk=scan_history_id)
    except ScanHistory.DoesNotExist:
        logger.warning(f"ScanHistory {scan_history_id} not found in enrich_identities_task. Aborting.")
        return
    domain = scan_history.domain

    results_dir = "%s/osint/gosearch" % scan_history.results_dir
    os.makedirs(results_dir, exist_ok=True)

    full_name = identity
    if identity_type == 'email':
        # Logic: mark.person@email.com -> Mark Person
        user_part = identity.split('@')[0]
        if '.' in user_part:
            full_name = ' '.join([p.capitalize() for p in user_part.split('.')])
        else:
            # If no dot, just use the username part
            full_name = user_part

    logger.info("Enriching identity: %s (%s)", full_name, identity_type)

    # 1. Generate Top 5 usernames using username-anarchy
    # Command: username-anarchy "First Last"
    # We'll take the top 5 results
    ua_cmd = 'username-anarchy'
    if not shutil.which(ua_cmd):
        ua_cmd = '/usr/src/github/username-anarchy/username-anarchy'
        if not os.path.exists(ua_cmd):
            logger.error("username-anarchy not found")
            return

    cmd_ua = [ua_cmd, full_name]
    process_ua = subprocess.Popen(cmd_ua, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout_ua, _ = process_ua.communicate()

    usernames = [line.strip() for line in stdout_ua.splitlines() if line.strip()][:5]

    if not usernames and identity_type == 'email':
        # Fallback to the actual username from email
        usernames = [identity.split('@')[0]]

    logger.info("Generated usernames for %s: %s", full_name, usernames)

    # 2. Run gosearch for each username
    for username in usernames:
        if not username:
            continue

        # gosearch -u <username> --no-false-positives
        # We'll run it and parse output. gosearch output can be noisy.
        # It usually outputs discovered URLs.

        cmd_gs = ['gosearch', '-u', username, '--no-false-positives', '-o', results_dir]

        # Check for proxy in ctx or global
        proxy_obj = Proxy.objects.first()
        proxy = get_random_proxy() if proxy_obj and proxy_obj.use_proxy else None
        if proxy:
            cmd_gs = ['proxychains4', '-q'] + cmd_gs

        process_gs = subprocess.Popen(cmd_gs, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout_gs, _ = process_gs.communicate()

        findings = []
        for line in stdout_gs.splitlines():
            if 'http' in line:
                # Extract URL
                urls = re.findall(r'(https?://[^\s]+)', line)
                findings.extend(urls)

        if findings:
            for url in set(findings):
                OsintStaging.objects.get_or_create(
                    scan_history=scan_history,
                    target_domain=domain,
                    osint_type='Social/Web Presence',
                    content=url,
                    defaults={
                        'source': 'gosearch',
                        'confidence': 80,
                        'metadata': {
                            'username': username,
                            'identity': full_name,
                            'original_identity': identity
                        }
                    }
                )

    return "Enrichment completed for %s" % full_name


def db_conn_safe_wrapper(target_func, *args, **kwargs):
    from django.db import connections
    try:
        return target_func(*args, **kwargs)
    finally:
        connections.close_all()


def osint_orchestrator(scan_history_id):
    """
    Orchestrate the OSINT pipeline.
    """
    scan_history = ScanHistory.objects.get(pk=scan_history_id)
    domain = scan_history.domain.name

    # Run Hunter.io lookup synchronously first so discovered emails and
    # employees are in the DB before holehe/maigret/LinkedIn threads spawn.
    hunter_key_obj = HunterIOAPIKey.objects.first()
    if hunter_key_obj and hunter_key_obj.key:
        run_hunter_lookup(domain, scan_history_id, hunter_key_obj.key)

    threads = []

    # 1. Get already discovered emails
    emails = scan_history.emails.all()
    for email in emails:
        t1 = threading.Thread(
            target=db_conn_safe_wrapper,
            args=(run_holehe,),
            kwargs={'email_address': email.address, 'scan_history_id': scan_history_id},
            daemon=True
        )
        t1.start()
        threads.append(t1)

        t2 = threading.Thread(
            target=db_conn_safe_wrapper,
            args=(enrich_identities_task,),
            kwargs={'identity': email.address, 'identity_type': 'email', 'scan_history_id': scan_history_id},
            daemon=True
        )
        t2.start()
        threads.append(t2)

    # 2. Get already discovered employees/usernames
    employees = scan_history.employees.all()
    for employee in employees:
        if employee.name:
            if ' ' not in employee.name:
                t3 = threading.Thread(
                    target=db_conn_safe_wrapper,
                    args=(run_maigret,),
                    kwargs={'username': employee.name, 'scan_history_id': scan_history_id},
                    daemon=True
                )
                t3.start()
                threads.append(t3)

            t4 = threading.Thread(
                target=db_conn_safe_wrapper,
                args=(enrich_identities_task,),
                kwargs={'identity': employee.name, 'identity_type': 'employee', 'scan_history_id': scan_history_id},
                daemon=True
            )
            t4.start()
            threads.append(t4)

    # 3. LinkedInt for the domain/company
    company_name = domain.split('.')[0]
    t5 = threading.Thread(
        target=db_conn_safe_wrapper,
        args=(run_linkedint,),
        kwargs={'company_name': company_name, 'scan_history_id': scan_history_id},
        daemon=True
    )
    t5.start()
    threads.append(t5)

    # Wait for all threads to complete to ensure the Temporal activity blocks appropriately
    for t in threads:
        t.join()


def post_crawl_osint(self, ctx={}, description=None):
    """Run OSINT tasks that benefit from post-fuzz data (discovered documents, live subdomains).

    Runs after dir_file_fuzz (Temporal Tier 4a). Reads fuzz-discovered documents
    from the DB and runs exifray + SwaggerSpy path probe against confirmed live hosts.
    """
    config = self.yaml_configuration.get(POST_CRAWL_OSINT, {})
    if not config:
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
    from reNgine.definitions import OSINT, CREDSPY
    osint_cfg = self.yaml_configuration.get(OSINT, {})
    if osint_cfg.get(CREDSPY, False):
        from reNgine.osint.credspy import run_credspy
        run_credspy(self, host, self.scan, self.results_dir)

    opsec = get_opsec_manager()
    opsec.strip_directory(self.results_dir)

    logger.info("post_crawl_osint finished for scan_id=%s", self.scan_id)
    return True
