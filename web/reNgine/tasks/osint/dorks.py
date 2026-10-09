"""Google dorking: GooFuzz and the extended dork engines.

Split out of the former reNgine/tasks/osint.py; re-exported by
reNgine.tasks.osint for backward compatibility.
"""
import logging
import os

from reNgine.common_func import *  # noqa: F401,F403
from reNgine.definitions import *  # noqa: F401,F403
from startScan.models import *  # noqa: F401,F403
from reNgine.utils.task import run_command
from scanEngine.models import Proxy

logger = logging.getLogger(__name__)

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
