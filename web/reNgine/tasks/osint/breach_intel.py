"""Breach intelligence: h8mail and the LeakLookup / ProjectDiscovery leak APIs.

Split out of the former reNgine/tasks/osint.py; re-exported by
reNgine.tasks.osint for backward compatibility.
"""
import logging
import json
import requests
import os

from reNgine.common_func import *  # noqa: F401,F403
from reNgine.definitions import *  # noqa: F401,F403
from startScan.models import *  # noqa: F401,F403
from reNgine.utils.task import run_command, save_email
from reNgine.tasks.persistence import save_secret_leak

logger = logging.getLogger(__name__)

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
