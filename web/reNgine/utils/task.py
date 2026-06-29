import os
import re
import signal
import subprocess
import threading
import logging
import validators
import json
from django.utils import timezone
from django.db import IntegrityError

from urllib.parse import urlparse
from reNgine.utils.opsec import ProxychainsWrapper
import redis
from django.conf import settings
from startScan.models import ScanHistory, Email, Employee, Command, Subdomain, EndPoint, Parameter
from dashboard.models import SOCConfiguration
from targetApp.models import Domain
from reNgine.definitions import (
    COLOR_RESET, COLOR_WHITE, COLOR_RED, TOOL_COLORS
)
from reNgine.common_func import (
    get_subdomain_from_url,
    remove_ansi_escape_sequences,
    sanitize_url,
)
from reNgine.utilities import SubdomainScopeChecker, replace_nulls
from reNgine.settings import RENGINE_RESULTS

logger = logging.getLogger(__name__)

FETCH_URL_PERSIST_BATCH_SIZE = 2000
_COMMAND_OUTPUT_MAX_CHARS = 512_000
PRECRAWL_MAX_URLS = 500

ROUTED_TOOLS = {
    'semgrep', 'nuclei', 'ffuf', 'naabu', 'amass', 'subfinder', 'httpx',
    'dalfox', 'crlfuzz', 's3scanner', 'dirsearch', 'gospider', 'gau',
    'waybackurls', 'hakrawler', 'tlsx', 'katana', 'aquatone', 'nmap', 'vigolium',
    'sslscan', 'ike-scan', 'hping3', 'wrk', 'k6', 'brutus', 'wpscan'
}


def _execute_go_workflow(cmd, scan_id, command_obj_id, tool):
    """Start a GoExecutorTaskWorkflow and wait for it, cancelling on scan abort.

    Polls ScanHistory.scan_status every 5 s in the background. If the scan is
    marked ABORTED_TASK the child GoExecutorTaskWorkflow is cancelled (which
    sends SIGKILL to the tool subprocess inside the Go executor) and this
    function returns an aborted result dict instead of blocking forever.

    Args:
        cmd: Full command string to execute.
        scan_id: ScanHistory pk for abort polling (may be None).
        command_obj_id: Command record pk used to build the Temporal workflow ID.
        tool: Binary name used as part of the workflow ID.

    Returns:
        dict with keys 'exit_code', 'stdout', 'stderr'.

    Raises:
        Exception: If the workflow fails for any reason other than an abort.
    """
    import asyncio
    import time

    wf_id = f"go-exec-{tool}-{command_obj_id or int(time.time())}"

    async def _start():
        from reNgine.temporal_client import TemporalClientProvider
        client = await TemporalClientProvider.get_client()
        await client.start_workflow(
            "GoExecutorTaskWorkflow",
            {"command": [cmd], "scan_id": scan_id or 0, "command_id": command_obj_id or 0},
            id=wf_id,
            task_queue="python-orchestrator-queue",
        )

    async def _fetch_result():
        from reNgine.temporal_client import TemporalClientProvider
        client = await TemporalClientProvider.get_client()
        return await client.get_workflow_handle(wf_id).result()

    asyncio.run(_start())

    # Wait for the workflow result in a background thread so the main thread
    # can keep polling for scan abort without blocking the asyncio loop.
    result_box = [None, None]  # [value, error]
    done = threading.Event()

    def _wait():
        try:
            result_box[0] = asyncio.run(_fetch_result())
        except Exception as exc:
            result_box[1] = exc
        finally:
            done.set()

    threading.Thread(target=_wait, daemon=True).start()

    cancelled = False
    while not done.wait(timeout=5.0):
        if scan_id:
            try:
                from reNgine.definitions import ABORTED_TASK
                status = ScanHistory.objects.filter(pk=scan_id).values_list('scan_status', flat=True).first()
                if status == ABORTED_TASK:
                    logger.warning(f"[_execute_go_workflow] Scan {scan_id} aborted — cancelling {wf_id}")
                    from reNgine.temporal_client import TemporalClientProvider
                    TemporalClientProvider.cancel_workflow(wf_id)
                    cancelled = True
                    break
            except Exception as poll_err:
                logger.debug(f"[_execute_go_workflow] Abort poll error: {poll_err}")

    # Allow the result thread time to react to the cancellation before returning.
    done.wait(timeout=15.0)

    if cancelled:
        return {"exit_code": -1, "stdout": "", "stderr": f"Scan {scan_id} aborted"}
    if result_box[1]:
        raise result_box[1]
    return result_box[0] or {"exit_code": -1, "stdout": "", "stderr": "No result returned"}


def _subprocess_abort_watchdog(proc, scan_id):
    """Kill a subprocess process group when its scan is marked ABORTED_TASK.

    Runs in a daemon thread. Checks the DB every 5 s and sends SIGKILL to
    the process group when an abort is detected, so the readline() call in the
    calling thread unblocks and the scan stops promptly.
    """
    import time
    while proc.poll() is None:
        time.sleep(5)
        if proc.poll() is not None:
            break
        if not scan_id:
            continue
        try:
            from reNgine.definitions import ABORTED_TASK
            status = ScanHistory.objects.filter(pk=scan_id).values_list('scan_status', flat=True).first()
            if status == ABORTED_TASK:
                logger.warning(f"[_subprocess_abort_watchdog] Scan {scan_id} aborted — killing subprocess")
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except (ProcessLookupError, OSError):
                    pass
                return
        except Exception as e:
            logger.debug(f"[_subprocess_abort_watchdog] Poll error: {e}")


def get_tool_color(cmd):
    """Returns the ANSI color code for a given command based on the tool name."""
    sanitized = sanitize_command_for_db(cmd)
    if not sanitized:
        return COLOR_RED
    # Get the first part of the command (the binary)
    binary = sanitized.split()[0]
    # Strip path and extension
    tool = os.path.basename(binary).lower()
    if tool.endswith(('.py', '.sh', '.nse')):
        tool = tool.rsplit('.', 1)[0]
    return TOOL_COLORS.get(tool, COLOR_RED)

def sanitize_command_for_db(cmd):
    """
    Strips 'export HTTP_PROXY=... &&' and 'proxychains4 -f ...' from command
    to ensure the UI displays the actual tool name and clean command.
    Accepts both str and list commands.
    """
    if not cmd:
        return cmd
    if isinstance(cmd, list):
        cmd = ' '.join(str(c) for c in cmd)
    if isinstance(cmd, str):
        cmd = cmd.replace('\x00', '')
    # Strip export statements (matches both single and double quotes)
    cmd = re.sub(r'^export\s+.*?\s+&&\s+', '', cmd)
    # Strip proxychains4 wrapper with its config file
    cmd = re.sub(r'^(?:[/\w]*/)?proxychains4\s+-f\s+\S+\s+', '', cmd)
    return cmd


def _publish_to_redis_log(redis_client, soc_config, scan_id, command_id, line):
    """Publish a single line of log output to the Redis stream for scan tracking.

    Args:
        redis_client (redis.StrictRedis): The instantiated Redis client.
        soc_config (SOCConfiguration): The active SOC configuration object.
        scan_id (int): The associated Scan History ID.
        command_id (int): The Command record ID associated with the log.
        line (str): The log line content.
    """
    if not redis_client or not soc_config or not scan_id:
        return
    try:
        stream_key = f"scan:logs:{scan_id}"
        log_payload = {
            "data": json.dumps({
                "line": line,
                "timestamp": str(timezone.now()),
                "command_id": command_id
            })
        }
        redis_client.xadd(stream_key, log_payload)
        redis_client.xtrim(stream_key, maxlen=soc_config.log_retention_count, approximate=True)
    except Exception as e:
        logger.error(f"Failed to publish log to Redis: {e}")


def _init_redis_logging(scan_id):
    """Retrieve the SOC configuration and initialize a Redis client for log streaming if enabled.

    Args:
        scan_id (int): Associated Scan History ID.

    Returns:
        tuple: (redis_client, soc_config) if log streaming is enabled, otherwise (None, None).
    """
    if not scan_id:
        return None, None
    try:
        soc_config, _ = SOCConfiguration.objects.get_or_create(id=1)
        if soc_config.enable_live_log_streaming:
            r = redis.StrictRedis(
                host=settings.REDIS_HOST,
                port=settings.REDIS_PORT,
                password=settings.REDIS_PASSWORD,
                db=0
            )
            return r, soc_config
    except Exception as e:
        logger.error(f"Failed to initialize Redis logging configuration: {e}")
    return None, None


def run_command(
        cmd, 
        cwd=None, 
        shell=False, 
        history_file=None, 
        scan_id=None, 
        activity_id=None,
        remove_ansi_sequence=False,
        proxy=None,
        timeout=7200,
        env=None
    ):
    """Run a given command using subprocess module.

    Args:
        cmd (str): Command to run.
        cwd (str): Current working directory.
        echo (bool): Log command.
        shell (bool): Run within separate shell if True.
        history_file (str): Write command + output to history file.
        remove_ansi_sequence (bool): Used to remove ANSI escape sequences from output such as color coding
        proxy (str): If provided, may be used for proxychains wrapping.
    Returns:
        tuple: Tuple with return_code, output.
    """
    color = get_tool_color(cmd)
    logger.debug(f"{color}{cmd}{COLOR_RESET}")

    conf_path = None
    if proxy:
        proxy_manager = ProxychainsWrapper()
        if proxy_manager.should_wrap():
            cmd, conf_path = proxy_manager.wrap_command(cmd, proxy=proxy)

    # Create a command record in the database
    from django.db import IntegrityError
    try:
        command_obj = Command.objects.create(
            command=sanitize_command_for_db(cmd),
            time=timezone.now(),
            scan_history_id=scan_id,
            activity_id=activity_id)
    except IntegrityError as e:
        logger.warning(f"Could not create Command object in DB (scan or activity may have been deleted/rolled back): {e}")
        command_obj = None

    redis_client, soc_config = _init_redis_logging(scan_id)
    command_obj_id = command_obj.id if command_obj else 0

    # Check if the command is a routed tool (vulnerability or secret scan, etc.)
    should_route = False
    tool = ""
    clean_cmd = sanitize_command_for_db(cmd)
    if clean_cmd:
        binary = clean_cmd.split()[0]
        tool = os.path.basename(binary).lower()
        if tool.endswith(('.py', '.sh', '.nse')):
            tool = tool.rsplit('.', 1)[0]
        if tool in ROUTED_TOOLS:
            should_route = True

    if should_route:
        # Route execution transparently to the temporal-go-executor worker
        logger.info(f"Routing {tool} command execution to Go executor: {cmd}")
        import asyncio
        import time
        from temporalio.client import Client

        async def _execute_remote_command(command_str, scan_history_id, command_rec_id):
            """Asynchronously invoke the Temporal workflow to run a command on the Go executor.

            Args:
                command_str (str): The full command string to execute (e.g. semgrep scan ...)
                scan_history_id (int): Associated Scan History ID
                command_rec_id (int): Database record Command ID to log stdout/stderr to

            Returns:
                dict: The workflow execution result containing exit_code, stdout, and stderr
            """
            from reNgine.temporal_client import TemporalClientProvider
            # Connect to the Temporal cluster
            client = await TemporalClientProvider.get_client()
            # Execute GoExecutorTaskWorkflow on the python-orchestrator task queue which routes
            # the subprocess activity to the go-executor-queue
            result = await client.execute_workflow(
                "GoExecutorTaskWorkflow",
                {
                    "command": [command_str],
                    "scan_id": scan_history_id or 0,
                    "command_id": command_rec_id or 0,
                    "working_dir": cwd or "",
                },
                id=f"go-exec-{tool}-{command_rec_id or int(time.time())}",
                task_queue="python-orchestrator-queue"
            )
            return result

        try:
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

            # Route sync-to-async boundary safely depending on event loop state
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    future = pool.submit(asyncio.run, _execute_remote_command(cmd, scan_id, command_obj_id))
                    exec_res = future.result()
            else:
                exec_res = loop.run_until_complete(_execute_remote_command(cmd, scan_id, command_obj_id))

            return_code = exec_res.get("exit_code", 0)
            stdout = exec_res.get("stdout", "")
            stderr = exec_res.get("stderr", "")
            output = stdout + "\n" + stderr
            if redis_client and soc_config:
                for line in stdout.splitlines():
                    _publish_to_redis_log(redis_client, soc_config, scan_id, command_obj_id, line)
                for line in stderr.splitlines():
                    _publish_to_redis_log(redis_client, soc_config, scan_id, command_obj_id, line)
        except Exception as e:
            logger.error(f"Error executing remote command: {e}")
            output = f"Error executing remote command: {e}"
            return_code = 127
    else:
        # Run the command using subprocess locally for other tools
        popen = None
        try:
            popen = subprocess.Popen(
                cmd if (shell or isinstance(cmd, list)) else cmd.split(),
                shell=shell,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=cwd,
                env=env,
                universal_newlines=True,
                errors='replace',
                preexec_fn=os.setsid)
            output = ''
            _run_cmd_line_count = 0
            _run_cmd_aborted = False
            for stdout_line in iter(popen.stdout.readline, ""):
                item = stdout_line.strip()
                output += '\n' + item
                logger.info(f"{COLOR_WHITE}{item}{COLOR_RESET}")
                if redis_client and soc_config:
                    _publish_to_redis_log(redis_client, soc_config, scan_id, command_obj_id, item)
                _run_cmd_line_count += 1
                if _run_cmd_line_count % 10 == 0:
                    try:
                        from reNgine.utils.task import activity_heartbeat_safe
                        activity_heartbeat_safe(f"Command executing... line {_run_cmd_line_count}")
                    except Exception:
                        pass
                if _run_cmd_line_count % 10 == 0 and scan_id:
                    try:
                        from startScan.models import ScanHistory as _SH
                        from reNgine.definitions import ABORTED_TASK as _ABORTED
                        _s = _SH.objects.filter(pk=scan_id).values_list('scan_status', flat=True).first()
                        if _s == _ABORTED:
                            logger.warning(f"[run_command] Scan {scan_id} aborted — killing subprocess.")
                            try:
                                os.killpg(os.getpgid(popen.pid), signal.SIGKILL)
                            except (ProcessLookupError, OSError):
                                pass
                            _run_cmd_aborted = True
                            break
                    except Exception:
                        pass
            popen.stdout.close()
            if _run_cmd_aborted:
                return_code = -1
            else:
                # Replace bare 7200 s wait with a polling loop so abort is
                # detected even if the process is slow to produce output.
                import time as _time
                _deadline = _time.monotonic() + timeout
                _timed_out = False
                while True:
                    try:
                        popen.wait(timeout=10)
                        break
                    except subprocess.TimeoutExpired:
                        if scan_id:
                            try:
                                from startScan.models import ScanHistory as _SH
                                from reNgine.definitions import ABORTED_TASK as _ABORTED
                                _s = _SH.objects.filter(pk=scan_id).values_list('scan_status', flat=True).first()
                                if _s == _ABORTED:
                                    logger.warning(f"[run_command] Scan {scan_id} aborted during wait — killing.")
                                    try:
                                        os.killpg(os.getpgid(popen.pid), signal.SIGKILL)
                                    except (ProcessLookupError, OSError):
                                        pass
                                    _run_cmd_aborted = True
                                    break
                            except Exception:
                                pass
                        if _time.monotonic() > _deadline:
                            _timed_out = True
                            break
                if _run_cmd_aborted:
                    return_code = -1
                elif _timed_out:
                    try:
                        os.killpg(os.getpgid(popen.pid), signal.SIGKILL)
                    except (ProcessLookupError, OSError):
                        pass
                    return_code = 124  # Timeout
                    output += "\nCommand timed out."
                else:
                    return_code = popen.returncode
        except Exception as e:
            logger.error(f"Error executing command {cmd}: {str(e)}")
            output = f"Error executing command: {str(e)}"
            return_code = 127 # Command not found / error
        except BaseException as e:
            logger.error(f"BaseException raised during command execution: {str(e)}")
            if popen:
                try:
                    os.killpg(os.getpgid(popen.pid), signal.SIGKILL)
                except (ProcessLookupError, OSError):
                    pass
            raise
        finally:
            if popen:
                try:
                    if popen.stdout:
                        popen.stdout.close()
                except Exception:
                    pass
                try:
                    if popen.poll() is None:
                        try:
                            os.killpg(os.getpgid(popen.pid), signal.SIGTERM)
                        except (ProcessLookupError, OSError):
                            pass
                        try:
                            popen.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            try:
                                os.killpg(os.getpgid(popen.pid), signal.SIGKILL)
                            except (ProcessLookupError, OSError):
                                pass
                    else:
                        popen.wait()
                except Exception as ex:
                    logger.error(f"Error reaping process in run_command: {ex}")
            if conf_path and os.path.exists(conf_path):
                os.remove(conf_path)

    if command_obj:
        logger.warning(f"Command {command_obj.id} finished with return code {return_code}")
        command_obj.output = output.replace('\x00', '')
        command_obj.return_code = return_code
        command_obj.save()
    else:
        logger.warning(f"Command finished with return code {return_code} (no database record saved)")

    if history_file:
        mode = 'a'
        if not os.path.exists(history_file):
            mode = 'w'
        with open(history_file, mode) as f:
            f.write(f'\n{cmd}\n{return_code}\n{output}\n------------------\n')
            
    if remove_ansi_sequence:
        output = remove_ansi_escape_sequences(output)
        
    return return_code, output

def run_command_with_retry(cmd, results_file, max_retries=3, **kwargs):
    """Run a command and retry up to max_retries times if results_file is empty.

    Args:
        cmd (str): Command to run.
        results_file (str): Path to the output file to check for emptiness.
        max_retries (int): Maximum number of attempts (default 3).
        **kwargs: Passed through to run_command.
    Returns:
        tuple: (return_code, output) from the last attempt.
    """
    tool_name = os.path.basename(cmd.split()[0]) if cmd else 'unknown'
    return_code, output = run_command(cmd, **kwargs)

    for attempt in range(2, max_retries + 1):
        if results_file and os.path.exists(results_file) and os.path.getsize(results_file) > 0:
            break
        logger.warning(
            f'{tool_name}: results file "{results_file}" is empty after attempt {attempt - 1}/{max_retries}. Retrying...'
        )
        return_code, output = run_command(cmd, **kwargs)

    if not results_file or not os.path.exists(results_file) or os.path.getsize(results_file) == 0:
        logger.warning(f'{tool_name}: results file "{results_file}" still empty after {max_retries} attempts. Moving on.')

    return return_code, output


def save_email(email_address: str, scan_history=None, source: str = 'hunter'):
    if not validators.email(email_address):
        logger.info('Email %s is invalid. Skipping.', email_address)
        return None, False
    email, created = Email.objects.get_or_create(
        address=email_address,
        defaults={'source': source},
    )

    # Add email to ScanHistory
    if scan_history:
        scan_history.emails.add(email)
        scan_history.save()
        from reNgine.tasks.osint import enrich_identities_task
        threading.Thread(
            target=enrich_identities_task,
            kwargs={'identity': email_address, 'identity_type': 'email', 'scan_history_id': scan_history.id},
            daemon=True
        ).start()

    return email, created

def save_employee(name, designation='', scan_history=None):
    employee, created = Employee.objects.get_or_create(
        name=name,
        designation=designation)

    # Add employee to ScanHistory
    if scan_history:
        scan_history.employees.add(employee)
        scan_history.save()
        from reNgine.tasks.osint import enrich_identities_task
        threading.Thread(
            target=enrich_identities_task,
            kwargs={'identity': name, 'identity_type': 'employee', 'scan_history_id': scan_history.id},
            daemon=True
        ).start()

    return employee, created

def save_subdomain(subdomain_name, ctx={}):
    """Get or create Subdomain; rediscovery updates the existing row instead of duplicating.

    Idempotent across Temporal activity retries and discovery-phase restarts.
    """
    scan_id = ctx.get('scan_history_id')
    subscan_id = ctx.get('subscan_id')
    out_of_scope_subdomains = ctx.get('out_of_scope_subdomains', [])
    subdomain_checker = SubdomainScopeChecker(out_of_scope_subdomains)

    subdomain_name = (subdomain_name or '').strip().lower()
    if not subdomain_name:
        return None, False

    valid_domain = (
        validators.domain(subdomain_name) or
        validators.ipv4(subdomain_name) or
        validators.ipv6(subdomain_name)
    )
    if not valid_domain:
        logger.error(f'{subdomain_name} is not a valid domain. Skipping.')
        return None, False

    if subdomain_checker.is_out_of_scope(subdomain_name):
        logger.error(f'{subdomain_name} is out-of-scope. Skipping.')
        return None, False

    if ctx.get('domain_id'):
        domain = Domain.objects.filter(id=ctx.get('domain_id')).first()
        if domain and domain.name not in subdomain_name:
            logger.error(f"{subdomain_name} is not a subdomain of domain {domain.name}. Skipping.")
            return None, False

    scan = ScanHistory.objects.filter(pk=scan_id).first()
    domain = scan.domain if scan else Domain.objects.filter(id=ctx.get('domain_id')).first()

    subdomain = None
    created = False
    if scan:
        subdomain = Subdomain.objects.filter(
            scan_history=scan,
            name__iexact=subdomain_name,
        ).first()

    if subdomain:
        update_fields = []
        if subdomain.name != subdomain_name:
            subdomain.name = subdomain_name
            update_fields.append('name')
        if domain and subdomain.target_domain_id != domain.id:
            subdomain.target_domain = domain
            update_fields.append('target_domain')
        if not subdomain.discovered_date:
            subdomain.discovered_date = timezone.now()
            update_fields.append('discovered_date')
        if update_fields:
            subdomain.save(update_fields=update_fields)
    else:
        try:
            subdomain, created = Subdomain.objects.get_or_create(
                scan_history=scan,
                target_domain=domain,
                name=subdomain_name,
                defaults={'discovered_date': timezone.now()},
            )
        except IntegrityError:
            subdomain = Subdomain.objects.filter(
                scan_history=scan,
                name__iexact=subdomain_name,
            ).first()
            created = False

    if not subdomain:
        return None, False

    if subscan_id:
        from startScan.models import SubScan
        if SubScan.objects.filter(pk=subscan_id).exists():
            subdomain.subdomain_subscan_ids.add(subscan_id)

    return subdomain, created

def save_endpoint(
        http_url,
        ctx={},
        crawl=False,
        is_default=False,
        **endpoint_data):
    """Get or create EndPoint object."""
    endpoint_data = replace_nulls(endpoint_data)
    scheme = urlparse(http_url).scheme
    endpoint = None
    created = False
    
    if ctx.get('domain_id'):
        # Cache resolved Domain in ctx to avoid repeated SELECT per save_endpoint() call.
        domain = ctx.get('_domain_obj')
        if domain is None or isinstance(domain, int):
            domain = Domain.objects.filter(id=ctx.get('domain_id')).first()
            ctx['_domain_obj'] = domain
        if domain and domain.name not in http_url:
            logger.error(f"{http_url} is not a URL of domain {domain.name}. Skipping.")
            return None, False

    if crawl:
        # Avoid circular import by importing here
        from reNgine.tasks import http_crawl
        from reNgine.temporal_activities import TemporalTaskProxy
        ctx['track'] = False
        proxy = TemporalTaskProxy(ctx, 'http_crawl', 'HTTP Crawl')
        results = http_crawl(
            proxy,
            urls=[http_url],
            method='HEAD',
            ctx=ctx)
        if results and isinstance(results, list) and isinstance(results[0], dict):
            endpoint_data = results[0]
            if 'endpoint_id' in endpoint_data:
                endpoint_id = endpoint_data['endpoint_id']
                created = endpoint_data.get('endpoint_created', False)
                endpoint = EndPoint.objects.get(pk=endpoint_id)
    elif not scheme:
        return None, False
    else:
        # Cache resolved ORM objects in ctx to avoid repeated queries within
        # the same scan context (e.g., once per port in port_scan's hot loop).
        scan = ctx.get('_scan_obj')
        if scan is None or isinstance(scan, int):
            scan = ScanHistory.objects.filter(pk=ctx.get('scan_history_id')).first()
            ctx['_scan_obj'] = scan

        domain = ctx.get('_domain_obj')
        if domain is None or isinstance(domain, int):
            domain = Domain.objects.filter(pk=ctx.get('domain_id')).first()
            ctx['_domain_obj'] = domain

        if not validators.url(http_url):
            return None, False
        http_url = sanitize_url(http_url)

        endpoints = EndPoint.objects.filter(
            scan_history=scan,
            target_domain=domain,
            http_url=http_url,
            **endpoint_data
        )

        if endpoints.exists():
            endpoint = endpoints.first()
            created = False
        else:
            endpoint = EndPoint.objects.create(
                scan_history=scan,
                target_domain=domain,
                http_url=http_url,
                **endpoint_data
            )
            created = True

    if created:
        endpoint.is_default = is_default
        endpoint.discovered_date = timezone.now()
        endpoint.save()

        # Centralized Brute-Force Candidate Registration
        auth_keywords = ['login', 'admin', 'auth', 'portal', 'controlpanel', 'signin', 'manage']
        if any(k in http_url.lower() for k in auth_keywords):
            from reNgine.utilities import save_auth_candidate
            try:
                parsed = urlparse(http_url)
                port = parsed.port or (443 if parsed.scheme == 'https' else 80)
                save_auth_candidate(
                    scan_history=endpoint.scan_history,
                    subdomain=endpoint.subdomain,
                    endpoint=endpoint,
                    target=parsed.hostname,
                    protocol='http',
                    port=port,
                    source_tool=endpoint_data.get('source_tool', 'discovery_engine'),
                    tech_hint=f"Discovered URL: {http_url}"
                )
            except Exception as e:
                logger.error(f"Error registering AuthCandidate from endpoint {http_url}: {e}")

        subscan_id = ctx.get('subscan_id')
        if subscan_id:
            from startScan.models import SubScan
            if SubScan.objects.filter(pk=subscan_id).exists():
                endpoint.endpoint_subscan_ids.add(subscan_id)
            # No second save() — M2M add() writes directly to the join table

    return endpoint, created

def save_parameter(
	endpoint,
	name,
	param_type='unknown',
	impact='none',
	value=None,
	# CPDE intelligence fields — all optional; backward-compatible
	confidence=0,
	sources=None,
	param_location=None,
	data_type=None,
	is_auth_related=False,
	observed_in_js=False,
	observed_in_openapi=False,
	observed_in_graphql=False,
	scan_history_id=None,
):
	"""Save a discovered parameter to the database.

	Creates the parameter if it does not exist (keyed on endpoint + name +
	param_location). When the record already exists, CPDE intelligence fields
	are merged rather than overwritten: sources lists are unioned, confidence
	takes the maximum, and boolean flags are ORed — so multiple tools each
	calling save_parameter() for the same parameter accumulate evidence rather
	than replacing each other's data.

	Args:
		endpoint: EndPoint instance the parameter belongs to.
		name (str): Parameter name.
		param_type (str): Tool source label (e.g. 'Arjun', 'js_ast'). Defaults to 'unknown'.
		impact (str): Impact category. Defaults to 'none'.
		value (str): Observed parameter value, if any.
		confidence (int): 0-100 confidence score from CPDE. Defaults to 0.
		sources (list): Evidence source labels (e.g. ['arjun', 'js_ast']). Defaults to [].
		param_location (str): json_body|query_string|header|graphql_var|form_data|path.
		data_type (str): Inferred JS type (string, number, boolean, object, array).
		is_auth_related (bool): True when name matches auth patterns.
		observed_in_js (bool): True when observed via JS/AST analysis.
		observed_in_openapi (bool): True when observed in an OpenAPI schema.
		observed_in_graphql (bool): True when observed as a GraphQL variable.
		scan_history_id (int): ScanHistory PK for the direct denormalized FK.

	Returns:
		tuple: (Parameter instance, created: bool)
	"""
	if sources is None:
		sources = []

	# Resolve the scan_history FK if not provided (derive from endpoint)
	if not scan_history_id and endpoint and hasattr(endpoint, 'scan_history_id'):
		scan_history_id = endpoint.scan_history_id

	# Key on endpoint + name + param_location so the same parameter name
	# can exist in multiple locations (e.g. both query_string and json_body).
	lookup = {'endpoint': endpoint, 'name': name}
	if param_location:
		lookup['param_location'] = param_location

	param, created = Parameter.objects.get_or_create(
		**lookup,
		defaults={
			'type': param_type,
			'impact': impact,
			'value': value,
			'confidence': confidence,
			'sources': sources,
			'param_location': param_location,
			'data_type': data_type,
			'is_auth_related': is_auth_related,
			'observed_in_js': observed_in_js,
			'observed_in_openapi': observed_in_openapi,
			'observed_in_graphql': observed_in_graphql,
			'scan_history_id': scan_history_id,
		}
	)

	if not created:
		# Merge CPDE intelligence fields — never overwrite with lower-quality data
		update_fields = []

		if param_type and param_type != 'unknown' and param.type != param_type:
			param.type = param_type
			update_fields.append('type')
		if value and not param.value:
			param.value = value
			update_fields.append('value')

		# Merge sources: union existing + new labels
		if sources:
			merged = list(set((param.sources or []) + sources))
			if merged != param.sources:
				param.sources = merged
				update_fields.append('sources')

		# Confidence: keep the maximum observed across all tools
		if confidence > param.confidence:
			param.confidence = confidence
			update_fields.append('confidence')

		# Boolean flags: once True, stay True regardless of caller order
		if observed_in_js and not param.observed_in_js:
			param.observed_in_js = True
			update_fields.append('observed_in_js')
		if observed_in_openapi and not param.observed_in_openapi:
			param.observed_in_openapi = True
			update_fields.append('observed_in_openapi')
		if observed_in_graphql and not param.observed_in_graphql:
			param.observed_in_graphql = True
			update_fields.append('observed_in_graphql')
		if is_auth_related and not param.is_auth_related:
			param.is_auth_related = True
			update_fields.append('is_auth_related')

		if not param.param_location and param_location:
			param.param_location = param_location
			update_fields.append('param_location')
		if not param.data_type and data_type:
			param.data_type = data_type
			update_fields.append('data_type')
		if not param.scan_history_id and scan_history_id:
			param.scan_history_id = scan_history_id
			update_fields.append('scan_history_id')

		if update_fields:
			param.save(update_fields=update_fields)

	return param, created

def stream_command(
		cmd, 
		cwd=None, 
		shell=False, 
		history_file=None, 
		encoding='utf-8', 
		scan_id=None, 
		activity_id=None, 
		trunc_char=None,
		proxy=None,
		timeout=3600,
		route_to_executor=True,
		max_output_chars=_COMMAND_OUTPUT_MAX_CHARS,
	):
	"""Run a command and yield output line by line.

	Args:
		cmd (str): Command to run.
		cwd (str): Current working directory.
		shell (bool): Run within separate shell if True.
		history_file (str): Write command + output to history file.
		encoding (str): Output encoding.
		scan_id (int): Scan ID.
		activity_id (int): Activity ID.
		trunc_char (str): Character used to truncate the output line.
		proxy (str): If provided, may be used for proxychains wrapping.
		timeout (int): Overall execution timeout in seconds.
	Yields:
		str/dict: Output line.
	"""
	color = get_tool_color(cmd)
	logger.debug(f"{color}{cmd}{COLOR_RESET}")

	conf_path = None
	if proxy:
		proxy_manager = ProxychainsWrapper()
		if proxy_manager.should_wrap():
			cmd, conf_path = proxy_manager.wrap_command(cmd, proxy=proxy)

	# Create a command record in the database
	command_obj = Command.objects.create(
		command=sanitize_command_for_db(cmd),
		time=timezone.now(),
		scan_history_id=scan_id,
		activity_id=activity_id)

	redis_client, soc_config = _init_redis_logging(scan_id)
	command_obj_id = command_obj.id if command_obj else 0

	# Check if the command is a routed tool
	should_route = False
	tool = ""
	clean_cmd = sanitize_command_for_db(cmd)
	if clean_cmd:
		binary = clean_cmd.split()[0]
		tool = os.path.basename(binary).lower()
		if tool.endswith(('.py', '.sh', '.nse')):
			tool = tool.rsplit('.', 1)[0]
		if tool in ROUTED_TOOLS:
			should_route = True

	if route_to_executor and should_route:
		logger.info(f"Routing {tool} command execution to Go executor: {cmd}")
		import asyncio
		import time
		from temporalio.client import Client

		async def _execute_remote_command(command_str, scan_history_id, command_rec_id):
			"""Start GoExecutorTaskWorkflow and wait for result, cancelling it if the scan is aborted.

			Uses start_workflow + a polling loop (10 s timeout slices) so that an
			ABORTED_TASK status in DB or a cancel_event from the Temporal heartbeat
			thread causes the GoExecutorTaskWorkflow to be cancelled promptly rather
			than waiting for the full tool run to complete.
			"""
			from reNgine.temporal_client import TemporalClientProvider
			from reNgine.definitions import ABORTED_TASK
			client = await TemporalClientProvider.get_client()
			workflow_id = f"go-exec-{tool}-{command_rec_id or int(time.time())}"

			handle = await client.start_workflow(
				"GoExecutorTaskWorkflow",
				{
					"command": [command_str],
					"scan_id": scan_history_id or 0,
					"command_id": command_rec_id or 0,
					"working_dir": cwd or "",
				},
				id=workflow_id,
				task_queue="python-orchestrator-queue"
			)
			# Create a single task to await the workflow result.
			# This avoids creating multiple handle.result() coroutines on every iteration,
			# preventing gRPC connection leaks and RPC cancellation errors.
			result_task = asyncio.create_task(handle.result())

			try:
				# Poll until result_task is complete.
				while not result_task.done():
					# 1) Check the cancel_event set by _run_task's heartbeat thread.
					try:
						from reNgine.temporal_activities import _task_cancel_local
						ce = getattr(_task_cancel_local, 'cancel_event', None)
						if ce and ce.is_set():
							logger.warning(
								f"[stream_command] cancel_event set — cancelling GoExecutorTaskWorkflow {workflow_id}"
							)
							try:
								await handle.cancel()
							except Exception as cancel_err:
								logger.error(f"[stream_command] Failed to cancel workflow {workflow_id}: {cancel_err}")
							result_task.cancel()
							return {"exit_code": -1, "stdout": "", "stderr": "Scan aborted"}
					except Exception as e:
						logger.debug(f"[stream_command] Local cancel_event check failed: {e}")

					# 2) Fallback: direct DB check.
					if scan_history_id:
						try:
							loop = asyncio.get_event_loop()
							status = await loop.run_in_executor(
								None,
								lambda: __import__(
									'startScan.models', fromlist=['ScanHistory']
								).ScanHistory.objects.filter(pk=scan_history_id)
								.values_list('scan_status', flat=True)
								.first()
							)
							if status == ABORTED_TASK:
								logger.warning(
									f"[stream_command] DB ABORTED_TASK — cancelling GoExecutorTaskWorkflow {workflow_id}"
								)
								try:
									await handle.cancel()
								except Exception as cancel_err:
									logger.error(f"[stream_command] Failed to cancel workflow {workflow_id}: {cancel_err}")
								result_task.cancel()
								return {"exit_code": -1, "stdout": "", "stderr": "Scan aborted"}
						except Exception as e:
							logger.debug(f"[stream_command] DB abort status check failed: {e}")

					# Wait for up to 10 seconds or until the workflow finishes.
					# This yields control to the event loop, letting result_task run,
					# without creating redundant coroutines or raising TimeoutError.
					await asyncio.wait([result_task], timeout=10.0)

				# Once result_task is done, return its result.
				return await result_task
			except Exception as e:
				logger.error(f"[stream_command] Error waiting for GoExecutorTaskWorkflow: {e}")
				raise
			finally:
				# Ensure result_task is cancelled if we exit early (e.g. on abort or error).
				if not result_task.done():
					result_task.cancel()

		try:
			try:
				loop = asyncio.get_event_loop()
			except RuntimeError:
				loop = asyncio.new_event_loop()
				asyncio.set_event_loop(loop)

			# Route sync-to-async boundary safely depending on event loop state
			if loop.is_running():
				import concurrent.futures
				with concurrent.futures.ThreadPoolExecutor() as pool:
					future = pool.submit(asyncio.run, _execute_remote_command(cmd, scan_id, command_obj_id))
					exec_res = future.result()
			else:
				exec_res = loop.run_until_complete(_execute_remote_command(cmd, scan_id, command_obj_id))

			return_code = exec_res.get("exit_code", 0)
			stdout = exec_res.get("stdout", "")
			stderr = exec_res.get("stderr", "")
			output = stdout + "\n" + stderr
			if redis_client and soc_config:
				for line in stdout.splitlines():
					_publish_to_redis_log(redis_client, soc_config, scan_id, command_obj_id, line)
				for line in stderr.splitlines():
					_publish_to_redis_log(redis_client, soc_config, scan_id, command_obj_id, line)
		except Exception as e:
			logger.error(f"Error executing remote command: {e}")
			output = f"Error executing remote command: {e}"
			return_code = 127
			stdout = ""
			stderr = output

		if command_obj:
			command_obj.output = output.replace('\x00', '')
			command_obj.return_code = return_code
			command_obj.save()

		if history_file:
			mode = 'a'
			if not os.path.exists(history_file):
				mode = 'w'
			with open(history_file, mode) as f:
				f.write(f'\n{cmd}\n{return_code}\n{output}\n------------------\n')

		# Yield stdout line by line
		for line in stdout.splitlines():
			line = line.replace('\x00', '').strip()
			if not line:
				continue
			item = line
			try:
				item = json.loads(line)
			except json.JSONDecodeError:
				pass
			yield item

		if conf_path and os.path.exists(conf_path):
			os.remove(conf_path)
		return

	# Sanitize the cmd
	command = cmd if (shell or isinstance(cmd, list)) else cmd.split()

	# Run the command using subprocess
	process = subprocess.Popen(
		command,
		stdout=subprocess.PIPE,
		stderr=subprocess.STDOUT,
		universal_newlines=True,
		errors='replace',
		shell=shell,
		cwd=cwd,
		preexec_fn=os.setsid)

	# Start a watchdog thread to terminate the command if it runs too long
	import threading
	import time

	def watchdog(proc, limit_sec):
		deadline = time.monotonic() + limit_sec
		while time.monotonic() < deadline:
			if proc.poll() is not None:
				return  # Process finished normally before timeout
			time.sleep(2)
			
		# If we reach here, it timed out
		if proc.poll() is None:
			logger.error(f"Watchdog: Command timed out after {limit_sec} seconds. Killing process: {cmd}")
			try:
				os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
			except (ProcessLookupError, OSError):
				pass
			except Exception as ex:
				logger.error(f"Watchdog: Failed to kill process: {ex}")
			
			# Force close stdout to break the blocked readline() in the main thread
			if proc.stdout:
				try:
					proc.stdout.close()
				except Exception:
					pass

	watchdog_thread = threading.Thread(
		target=watchdog,
		args=(process, timeout),
		daemon=True
	)
	watchdog_thread.start()

	# Log the output in real-time to the database
	output = ""

	# Process the output
	line_count = 0
	try:
		for line in iter(lambda: process.stdout.readline(), ''):
			if not line:
				break
			line = line.replace('\x00', '')
			line = line.strip()
			ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
			line = ansi_escape.sub('', line)
			line = line.replace('\\x0d\\x0a', '\n')
			if trunc_char and line.endswith(trunc_char):
				line = line[:-1]
			item = line

			# Try to parse the line as JSON
			try:
				item = json.loads(line)
			except json.JSONDecodeError:
				pass

			# Log to console for visibility
			if isinstance(item, str):
				logger.debug(f"{COLOR_WHITE}{item}{COLOR_RESET}")
			else:
				logger.debug(f"{COLOR_WHITE}{json.dumps(item)}{COLOR_RESET}")

			# Yield the line
			yield item
			
			# Real-time log streaming to Redis if enabled
			if redis_client and soc_config:
				_publish_to_redis_log(redis_client, soc_config, scan_id, command_obj_id, line)

			# Update output
			output += '\n' + line
			line_count += 1
			if line_count % 10 == 0:
				stored_output = output.replace('\x00', '')
				if max_output_chars and len(stored_output) > max_output_chars:
					stored_output = stored_output[-max_output_chars:]
				command_obj.output = stored_output
				command_obj.save()

				# Kill switch: abort the subprocess if the scan was stopped
				if scan_id:
					try:
						from startScan.models import ScanHistory
						from reNgine.definitions import ABORTED_TASK
						_scan = ScanHistory.objects.filter(pk=scan_id).only('scan_status').first()
						if _scan and _scan.scan_status == ABORTED_TASK:
							logger.warning(
								f"[stream_command] Scan {scan_id} aborted — killing subprocess."
							)
							try:
								os.killpg(os.getpgid(process.pid), signal.SIGKILL)
							except (ProcessLookupError, OSError):
								pass
							break
					except Exception:
						pass

		process.wait()
		command_obj.output = output.replace('\x00', '')
		command_obj.return_code = process.returncode
		command_obj.save()

	except BaseException as e:
		if not isinstance(e, GeneratorExit):
			logger.error(f"Error in stream_command: {str(e)}")
		if process:
			try:
				os.killpg(os.getpgid(process.pid), signal.SIGKILL)
			except (ProcessLookupError, OSError):
				pass
		raise
	finally:
		if process:
			if process.stdout:
				try:
					process.stdout.close()
				except Exception:
					pass
			try:
				if process.poll() is None:
					try:
						os.killpg(os.getpgid(process.pid), signal.SIGTERM)
					except (ProcessLookupError, OSError):
						pass
					try:
						process.wait(timeout=5)
					except subprocess.TimeoutExpired:
						try:
							os.killpg(os.getpgid(process.pid), signal.SIGKILL)
						except (ProcessLookupError, OSError):
							pass
				else:
					process.wait()
			except Exception as ex:
				logger.error(f"Error reaping process in stream_command: {ex}")
		if conf_path and os.path.exists(conf_path):
			os.remove(conf_path)


def activity_heartbeat_safe(message: str) -> None:
	"""Send a Temporal activity heartbeat when running inside an activity context."""
	try:
		from temporalio import activity
		activity.heartbeat(message)
	except Exception:
		pass


def _link_endpoints_subscan(http_urls, scan, subscan_id):
	"""Attach endpoints to a subscan via the M2M through table (idempotent)."""
	from startScan.models import SubScan
	if not subscan_id or not http_urls:
		return
	if not SubScan.objects.filter(pk=subscan_id).exists():
		return
	ep_ids = list(
		EndPoint.objects.filter(scan_history=scan, http_url__in=http_urls)
		.values_list('pk', flat=True)
	)
	if not ep_ids:
		return
	through = EndPoint.endpoint_subscan_ids.through
	through.objects.bulk_create(
		[through(endpoint_id=ep_id, subscan_id=subscan_id) for ep_id in ep_ids],
		ignore_conflicts=True,
	)


def bulk_persist_fetch_urls(urls, ctx, batch_size=FETCH_URL_PERSIST_BATCH_SIZE, heartbeat_interval=5000):
	"""Persist discovered URLs as skeleton EndPoint rows using batched bulk_create.

	Returns the number of new endpoints queued for insert (not counting conflicts).
	"""
	scan_id = ctx.get('scan_history_id')
	domain_id = ctx.get('domain_id')
	subscan_id = ctx.get('subscan_id')

	scan = ScanHistory.objects.filter(pk=scan_id).first()
	domain = Domain.objects.filter(pk=domain_id).first()
	if not scan or not domain:
		return 0

	existing_urls = set(
		EndPoint.objects.filter(scan_history=scan, target_domain=domain)
		.values_list('http_url', flat=True)
	)

	subdomain_cache = {}
	now = timezone.now()
	pending = []
	created_count = 0
	batch_urls = []
	total = len(urls)

	for idx, url in enumerate(urls):
		http_url = sanitize_url(url)
		if not http_url or not validators.url(http_url):
			continue
		if http_url in existing_urls:
			continue

		subdomain_name = get_subdomain_from_url(http_url)
		if subdomain_name not in subdomain_cache:
			sub, _ = save_subdomain(subdomain_name, ctx=ctx)
			if not sub:
				continue
			subdomain_cache[subdomain_name] = sub

		pending.append(EndPoint(
			scan_history=scan,
			target_domain=domain,
			subdomain=subdomain_cache[subdomain_name],
			http_url=http_url,
			discovered_date=now,
			is_default=False,
		))
		batch_urls.append(http_url)
		existing_urls.add(http_url)

		if len(pending) >= batch_size:
			EndPoint.objects.bulk_create(pending, ignore_conflicts=True)
			if subscan_id:
				_link_endpoints_subscan(batch_urls, scan, subscan_id)
			created_count += len(pending)
			pending = []
			batch_urls = []

		if heartbeat_interval and total and (idx + 1) % heartbeat_interval == 0:
			activity_heartbeat_safe(f'fetch_url persist {idx + 1}/{total}')

	if pending:
		EndPoint.objects.bulk_create(pending, ignore_conflicts=True)
		if subscan_id:
			_link_endpoints_subscan(batch_urls, scan, subscan_id)
		created_count += len(pending)

	return created_count


def bulk_get_or_create_directory_files(candidates):
	"""Return DirectoryFile instances for fuzzing hits, creating missing rows in bulk."""
	from startScan.models import DirectoryFile
	if not candidates:
		return []

	urls = [c['url'] for c in candidates if c.get('url')]
	existing = {
		(d.name, d.url, d.http_status): d
		for d in DirectoryFile.objects.filter(url__in=urls)
	}
	result = []
	new_objs = []
	for candidate in candidates:
		key = (candidate['name'], candidate['url'], candidate['http_status'])
		if key in existing:
			result.append(existing[key])
			continue
		obj = DirectoryFile(
			name=candidate['name'],
			url=candidate['url'],
			http_status=candidate['http_status'],
			length=candidate.get('length', 0),
			words=candidate.get('words', 0),
			lines=candidate.get('lines', 0),
			content_type=candidate.get('content_type') or '',
		)
		new_objs.append(obj)

	if new_objs:
		DirectoryFile.objects.bulk_create(new_objs)
		for obj in new_objs:
			fetched = DirectoryFile.objects.filter(
				name=obj.name,
				url=obj.url,
				http_status=obj.http_status,
			).first()
			if fetched:
				key = (fetched.name, fetched.url, fetched.http_status)
				existing[key] = fetched
				result.append(fetched)

	# Preserve order and uniqueness for callers linking M2M
	seen = set()
	ordered = []
	for candidate in candidates:
		key = (candidate['name'], candidate['url'], candidate['http_status'])
		dfile = existing.get(key)
		if dfile and key not in seen:
			seen.add(key)
			ordered.append(dfile)
	return ordered


def bulk_apply_gf_pattern_from_file(gf_output_file, gf_pattern, ctx, batch_size=500):
	"""Apply a GF pattern match file to endpoints with batched bulk_update."""
	scan_id = ctx.get('scan_history_id')
	domain_id = ctx.get('domain_id')
	scan = ScanHistory.objects.filter(pk=scan_id).first()
	domain = Domain.objects.filter(pk=domain_id).first()
	if not scan or not domain or not os.path.exists(gf_output_file):
		return 0

	updated = 0
	url_batch = []
	line_idx = 0

	def _flush_url_batch(urls):
		nonlocal updated
		if not urls:
			return
		sanitized = [sanitize_url(u) for u in urls if u and validators.url(sanitize_url(u))]
		if not sanitized:
			return
		bulk_persist_fetch_urls(sanitized, ctx, batch_size=len(sanitized))
		endpoints = EndPoint.objects.filter(
			scan_history=scan,
			target_domain=domain,
			http_url__in=sanitized,
		)
		to_update = []
		for ep in endpoints:
			earlier = ep.matched_gf_patterns or ''
			if earlier:
				if gf_pattern in {p.strip() for p in earlier.split(',') if p.strip()}:
					continue
				pattern = f'{earlier},{gf_pattern}'
			else:
				pattern = gf_pattern
			ep.matched_gf_patterns = pattern
			to_update.append(ep)
		if to_update:
			EndPoint.objects.bulk_update(to_update, ['matched_gf_patterns'], batch_size=batch_size)
			updated += len(to_update)

	with open(gf_output_file, 'r', encoding='utf-8', errors='replace') as gf_file:
		for raw_line in gf_file:
			line_idx += 1
			url = raw_line.strip()
			if not url:
				continue
			url_batch.append(url)
			if len(url_batch) >= batch_size:
				_flush_url_batch(url_batch)
				url_batch = []
			if line_idx % 5000 == 0:
				activity_heartbeat_safe(f'gf pattern {gf_pattern} line {line_idx}')

	if url_batch:
		_flush_url_batch(url_batch)

	return updated


def bulk_apply_gf_pattern_from_urls(urls, gf_pattern, ctx, batch_size=500):
	"""Apply a GF pattern match to endpoints given a list of matched URL strings.

	Mirrors bulk_apply_gf_pattern_from_file but accepts an in-memory list instead of a file,
	so callers that already hold matched URLs (e.g. RunGFOnAllEndpointsActivity) avoid a
	round-trip through disk.
	"""
	scan_id = ctx.get('scan_history_id')
	domain_id = ctx.get('domain_id')
	scan = ScanHistory.objects.filter(pk=scan_id).first()
	domain = Domain.objects.filter(pk=domain_id).first()
	if not scan or not domain or not urls:
		return 0

	updated = 0

	def _flush(batch):
		nonlocal updated
		if not batch:
			return
		sanitized = [sanitize_url(u) for u in batch if u and validators.url(sanitize_url(u))]
		if not sanitized:
			return
		bulk_persist_fetch_urls(sanitized, ctx, batch_size=len(sanitized))
		endpoints = EndPoint.objects.filter(
			scan_history=scan,
			target_domain=domain,
			http_url__in=sanitized,
		)
		to_update = []
		for ep in endpoints:
			earlier = ep.matched_gf_patterns or ''
			if earlier:
				if gf_pattern in {p.strip() for p in earlier.split(',') if p.strip()}:
					continue
				ep.matched_gf_patterns = f'{earlier},{gf_pattern}'
			else:
				ep.matched_gf_patterns = gf_pattern
			to_update.append(ep)
		if to_update:
			EndPoint.objects.bulk_update(to_update, ['matched_gf_patterns'], batch_size=batch_size)
			updated += len(to_update)

	url_batch = []
	for i, url in enumerate(urls):
		url = url.strip() if url else ''
		if not url:
			continue
		url_batch.append(url)
		if len(url_batch) >= batch_size:
			_flush(url_batch)
			url_batch = []
		if i % 5000 == 0 and i > 0:
			activity_heartbeat_safe(f'gf pattern {gf_pattern} url {i}')

	_flush(url_batch)
	return updated


def ensure_endpoints_crawled_and_execute(task_proxy, task_function, ctx, description=None, max_wait_time=300):
	"""
	Ensure endpoints are crawled before executing a task that needs alive endpoints.
	
	Args:
		task_function: The task function to execute
		ctx: Task context
		description: Task description
		max_wait_time: Maximum time to wait for endpoints (seconds)
		
	Returns:
		Task result or None if no alive endpoints available
	"""
	from copy import deepcopy
	from reNgine.common_func import get_http_urls

	logger.info(f'Ensuring endpoints are crawled for {task_function.__name__}')

	if alive_endpoints := get_http_urls(is_alive=True, ctx=ctx):
		logger.info(f'Found {len(alive_endpoints)} alive endpoints, executing {task_function.__name__}')
		return task_function(ctx=ctx, description=description)

	# No alive endpoints found, check if we have uncrawled endpoints
	uncrawled_endpoints = get_http_urls(is_uncrawled=True, ctx=ctx)

	if not uncrawled_endpoints:
		logger.warning(f'No endpoints found for {task_function.__name__}, skipping task')
		return None

	logger.info(f'Found {len(uncrawled_endpoints)} uncrawled endpoints, launching HTTP crawl first')

	from reNgine.tasks import http_crawl
	custom_ctx = deepcopy(ctx)
	custom_ctx['track'] = False  # Don't track this internal crawl

	# Run synchronously — safe here because this function is called from Temporal activities
	precrawl_limit = min(len(uncrawled_endpoints), PRECRAWL_MAX_URLS)
	http_crawl(task_proxy, urls=uncrawled_endpoints[:precrawl_limit], ctx=custom_ctx)

	if alive_endpoints := get_http_urls(is_alive=True, ctx=ctx):
		logger.info(f'Found {len(alive_endpoints)} alive endpoints after crawl, executing {task_function.__name__}')
		return task_function(ctx=ctx, description=description)
	else:
		logger.warning(f'No alive endpoints found after crawl, skipping {task_function.__name__}')
		return None


def save_fuzzing_file(name, url, http_status, length=0, words=0, lines=0, content_type=None):
	"""
	Save or retrieve DirectoryFile safely handling database concurrency/race conditions.
	"""
	from startScan.models import DirectoryFile
	from django.db import IntegrityError
	import time

	# Try/except block with retries to handle database concurrency/race conditions
	for attempt in range(3):
		try:
			dfile, created = DirectoryFile.objects.get_or_create(
				name=name,
				url=url,
				http_status=http_status,
				defaults={
					'length': length,
					'words': words,
					'lines': lines,
					'content_type': content_type or ''
				}
			)
			return dfile, created
		except IntegrityError:
			if attempt < 2:
				time.sleep(0.1 * (attempt + 1))
			continue

	# Final attempt
	return DirectoryFile.objects.get_or_create(
		name=name,
		url=url,
		http_status=http_status,
		defaults={
			'length': length,
			'words': words,
			'lines': lines,
			'content_type': content_type or ''
		}
	)


def parse_custom_header_to_list(custom_header):
	"""
	Convert dictionary, comma-separated string, or list of headers to flat list of header strings.
	"""
	if not custom_header:
		return []
	if isinstance(custom_header, list):
		return custom_header
	if isinstance(custom_header, dict):
		return [f"{k}: {v}" for k, v in custom_header.items()]
	if isinstance(custom_header, str):
		res = []
		for h in custom_header.split(','):
			h = h.strip()
			if h:
				res.append(h)
		return res
	return []


def is_iterable(variable):
	try:
		iter(variable)
		return not isinstance(variable, (str, bytes))
	except TypeError:
		return False


def save_subdomain_metadata(subdomain, endpoint, extra_datas=None):
	"""Save metadata from endpoint to subdomain.

	Args:
		subdomain: Subdomain object
		endpoint: EndPoint object
		extra_datas: Additional metadata to save
	"""
	if extra_datas is None:
		extra_datas = {}
	if endpoint and endpoint.is_alive:
		logger.info(f'Saving HTTP metadatas from {endpoint.http_url}')
		subdomain.http_url = endpoint.http_url
		subdomain.http_status = endpoint.http_status
		subdomain.response_time = endpoint.response_time
		subdomain.page_title = endpoint.page_title
		subdomain.content_type = endpoint.content_type
		subdomain.content_length = endpoint.content_length
		subdomain.webserver = endpoint.webserver

		cname = extra_datas.get('cname')
		if cname and is_iterable(cname):
			subdomain.cname = ','.join(cname)
		elif isinstance(cname, str):
			subdomain.cname = cname

		is_cdn = extra_datas.get('is_cdn', False)
		if isinstance(is_cdn, bool):
			subdomain.is_cdn = is_cdn
		else:
			cdn = extra_datas.get('cdn')
			if cdn:
				subdomain.is_cdn = True

		cdn_name = extra_datas.get('cdn_name')
		if cdn_name:
			subdomain.cdn_name = cdn_name

		for tech in endpoint.techs.all():
			subdomain.technologies.add(tech)
		subdomain.save()
	elif http_url := extra_datas.get('http_url'):
		subdomain.http_url = http_url
		subdomain.save()
	else:
		logger.debug(f'No HTTP URL found for {subdomain.name} yet. Skipping metadata extraction.')


