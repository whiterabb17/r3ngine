"""
Stress test command builder for r3ngine.

Provides pure command-construction functions for each supported stress tool
(k6, wrk, hping3, locust, stressor).  No subprocess execution, no Redis, no
Django ORM — just cmd list construction plus any temp-file setup that the tool
requires before launch.

Called by:
  - reNgine/stress_testing_tasks.py  (legacy Celery path)
  - reNgine/temporal_activities.py   (Temporal RunStressToolActivity)
"""

import json
import logging
import os
import re
import shlex
import tempfile
import time

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Shared sanitisation helper
# ---------------------------------------------------------------------------

def sanitize(val, allowed_chars=None, default=""):
    """Reject shell-unsafe characters from tool arguments.

    Args:
        val: Raw value (any type; will be str-cast).
        allowed_chars: Regex pattern for the full string. Defaults to
            alphanumeric + common URL/path characters.
        default: Return value when val is None or fails validation.

    Returns:
        str: Sanitised value, or *default* if val is unsafe/empty.
    """
    if val is None:
        return default
    val_str = str(val).strip()
    if not allowed_chars:
        allowed_chars = r"^[a-zA-Z0-9.\-_/:=%]+$"
    if not re.match(allowed_chars, val_str):
        logger.warning("[stress_cmd_builder] Sanitization blocked input: %r", val_str)
        return default
    return val_str


# ---------------------------------------------------------------------------
# Per-tool command builders
# ---------------------------------------------------------------------------

def _build_k6_cmd(tool_config, endpoint_url, scan_id, concurrency, duration,
                   single_proxy=None, k6_user_agent=None):
    """Build a k6 run command.

    Writes a temporary JS scenario script to /tmp and returns the file path
    as a cleanup target alongside the cmd list.

    Returns:
        (cmd: list[str], temp_files: list[str])
    """
    k6_vus = sanitize(tool_config.get("vus"), default=str(concurrency))
    k6_duration = sanitize(tool_config.get("duration"), default=str(duration))
    if k6_duration and not any(k6_duration.endswith(u) for u in ("s", "m", "h")):
        k6_duration = f"{k6_duration}s"

    k6_attack_type = sanitize(tool_config.get("attack_type", "http_get"), default="http_get")
    k6_rps = sanitize(tool_config.get("rps"), default="")
    k6_insecure = tool_config.get("insecure_skip_tls", False)
    k6_no_reuse = tool_config.get("no_connection_reuse", False)
    k6_http_debug = sanitize(tool_config.get("http_debug"), default="")

    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPad; CPU OS 17_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    ]
    user_agents_json = json.dumps(user_agents)

    k6_proxy_block = ""
    if single_proxy:
        _p = single_proxy if "://" in single_proxy else f"http://{single_proxy}"
        k6_proxy_block = (
            f"\n    scenarios: {{\n"
            f"        default: {{\n"
            f"            executor: 'constant-vus',\n"
            f"            vus: {k6_vus},\n"
            f"            duration: {json.dumps(k6_duration)},\n"
            f"            env: {{ HTTP_PROXY: {json.dumps(_p)}, HTTPS_PROXY: {json.dumps(_p)} }},\n"
            f"        }},\n"
            f"    }},"
        )
    else:
        k6_proxy_block = f"\n    vus: {k6_vus},\n    duration: {json.dumps(k6_duration)},"

    script_path = f"/tmp/k6_script_{scan_id}_{int(time.time())}.js"

    if k6_attack_type == "slowloris":
        script_content = f"""import http from 'k6/http';
import {{ sleep, check }} from 'k6';
const userAgents = {user_agents_json};
export const options = {{{k6_proxy_block}
}};
export default function () {{
    const randomUA = userAgents[Math.floor(Math.random() * userAgents.length)];
    const params = {{
        headers: {{
            'User-Agent': randomUA,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'X-Keep-Alive': 'true',
        }},
        timeout: '30s',
    }};
    try {{
        const res = http.get({json.dumps(endpoint_url)}, params);
        check(res, {{'status is 200-399': (r) => r.status >= 200 && r.status < 400}});
        sleep(10);
    }} catch (e) {{
        sleep(1);
    }}
}}
"""
    else:
        script_content = f"""import http from 'k6/http';
import {{ sleep, check }} from 'k6';
const userAgents = {user_agents_json};
export const options = {{{k6_proxy_block}
}};
export default function () {{
    const randomUA = userAgents[Math.floor(Math.random() * userAgents.length)];
    const params = {{
        headers: {{
            'User-Agent': randomUA,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        }},
    }};
    const res = http.get({json.dumps(endpoint_url)}, params);
    check(res, {{'status is 200-399': (r) => r.status >= 200 && r.status < 400}});
    sleep(0.5);
}}
"""

    with open(script_path, "w") as f:
        f.write(script_content)

    summary_path = f"/tmp/k6_summary_{scan_id}_{int(time.time())}.json"
    cmd = ["k6", "run", "--vus", k6_vus, "--duration", k6_duration]
    if k6_rps:
        cmd += ["--rps", k6_rps]
    if k6_insecure:
        cmd += ["--insecure-skip-tls-verify"]
    if k6_no_reuse:
        cmd += ["--no-connection-reuse"]
    if k6_http_debug:
        cmd += [f"--http-debug={k6_http_debug}"]
    cmd += [f"--summary-export={summary_path}", script_path]

    return cmd, [script_path, summary_path]


def _build_wrk_cmd(tool_config, endpoint_url, concurrency, duration, k6_user_agent=None):
    """Build a wrk benchmark command.

    Returns:
        (cmd: list[str], temp_files: list[str])
    """
    wrk_threads = sanitize(tool_config.get("threads"), default="2")
    wrk_connections = sanitize(tool_config.get("connections"), default=str(concurrency))
    wrk_duration = sanitize(tool_config.get("duration"), default=str(duration))
    if wrk_duration and not any(wrk_duration.endswith(u) for u in ("s", "m", "h")):
        wrk_duration = f"{wrk_duration}s"

    wrk_latency = tool_config.get("latency", True)
    wrk_timeout = sanitize(tool_config.get("timeout"), default="")
    wrk_headers = tool_config.get("headers", [])
    ua = k6_user_agent or "Mozilla/5.0 (compatible; r3ngine/3.1)"

    cmd = ["wrk", "-t", wrk_threads, "-c", wrk_connections, "-d", wrk_duration]
    if wrk_latency:
        cmd += ["--latency"]
    if wrk_timeout:
        cmd += ["--timeout", wrk_timeout]
    cmd += ["-H", f"User-Agent: {ua}"]
    for header in wrk_headers:
        san_hdr = sanitize(header, allowed_chars=r"^[a-zA-Z0-9.\-_/:=%\s]+$")
        if san_hdr:
            cmd += ["-H", san_hdr]
    cmd += [endpoint_url]

    return cmd, []


def _build_hping3_cmd(tool_config, target_domain, duration):
    """Build an hping3 packet flood command.

    hping3 operates at L3/L4 and takes a hostname/IP, not a URL.

    Returns:
        (cmd: list[str], temp_files: list[str])
    """
    hping_mode = sanitize(tool_config.get("attack_mode"), default="syn")
    hping_port = sanitize(tool_config.get("port"), default="80")
    hping_rate = sanitize(tool_config.get("rate"), default="fast")
    hping_data = sanitize(tool_config.get("data_size"), default="")

    cmd = ["hping3"]
    if hping_mode == "udp":
        cmd += ["--udp"]
    elif hping_mode == "icmp":
        cmd += ["--icmp"]
    else:
        cmd += ["--syn"]

    cmd += ["-p", hping_port]

    if hping_rate == "flood":
        cmd += ["--flood"]
    elif hping_rate == "faster":
        cmd += ["--faster"]
    else:
        cmd += ["--fast"]

    if hping_data:
        cmd += ["-d", hping_data]

    cmd += ["-c", "100", target_domain]

    return cmd, []


def _build_locust_cmd(tool_config, endpoint_url, scan_id, concurrency, duration,
                       single_proxy=None, k6_user_agent=None):
    """Build a Locust headless load test command.

    Writes a temporary locustfile.py to /tmp, splitting the target endpoint
    URL into a base host and relative path to avoid double slashes or target
    mismatches at runtime.

    Args:
        tool_config (dict): Configuration dictionary containing tool parameters.
        endpoint_url (str): The target URL endpoint.
        scan_id (str/int): The scan ID.
        concurrency (int): Concurrency level.
        duration (str/int): Duration of stress scan.
        single_proxy (str, optional): Target proxy IP/host.
        k6_user_agent (str, optional): User agent string for client requests.

    Returns:
        tuple: (cmd: list[str], temp_files: list[str])
    """
    from urllib.parse import urlparse

    # Extract target host and relative path to prevent endpoint errors
    parsed_url = urlparse(endpoint_url)
    scheme = parsed_url.scheme or "http"
    netloc = parsed_url.netloc

    # Fallback in case endpoint was passed without a protocol scheme
    if not netloc and '/' in endpoint_url:
        parsed_url = urlparse(f"http://{endpoint_url}")
        scheme = parsed_url.scheme or "http"
        netloc = parsed_url.netloc
    elif not netloc:
        netloc = endpoint_url

    base_host = f"{scheme}://{netloc}"
    
    # Construct relative path containing parameters, query and fragments
    request_path = parsed_url.path
    if not request_path:
        request_path = "/"
    if parsed_url.params:
        request_path += f";{parsed_url.params}"
    if parsed_url.query:
        request_path += f"?{parsed_url.query}"
    if parsed_url.fragment:
        request_path += f"#{parsed_url.fragment}"

    locust_users = sanitize(tool_config.get("users"), default=str(concurrency))
    locust_spawn = sanitize(
        tool_config.get("spawn_rate"),
        default=str(max(1, int(concurrency) // 5))
    )
    locust_runtime = sanitize(tool_config.get("run_time"), default=str(duration))
    if locust_runtime and not any(locust_runtime.endswith(u) for u in ("s", "m", "h")):
        locust_runtime = f"{locust_runtime}s"
    locust_loglevel = sanitize(tool_config.get("loglevel"), default="ERROR")
    ua = k6_user_agent or "Mozilla/5.0 (compatible; r3ngine/3.1)"

    proxy_lines = []
    if single_proxy:
        _lp = single_proxy if "://" in single_proxy else f"http://{single_proxy}"
        proxy_lines = [
            "    def on_start(self):",
            f"        self.client.headers.update({{'User-Agent': '{ua}', 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 'Accept-Language': 'en-US,en;q=0.5'}})",
            f"        self.client.proxies = {{'http': '{_lp}', 'https': '{_lp}'}}",
            "        self.client.verify = False",
        ]
    else:
        proxy_lines = [
            "    def on_start(self):",
            f"        self.client.headers.update({{'User-Agent': '{ua}', 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 'Accept-Language': 'en-US,en;q=0.5'}})",
            "        self.client.verify = False",
        ]

    locust_on_start = "\n".join(proxy_lines)

    # Use json.dumps to safely convert path into a valid Python string literal
    escaped_path = json.dumps(request_path)

    script_path = f"/tmp/locustfile_{scan_id}_{int(time.time())}.py"
    with open(script_path, "w") as f:
        f.write(f"""from locust import HttpUser, task, between
import logging
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.getLogger('locust').setLevel(logging.{locust_loglevel})

class StressUser(HttpUser):
    wait_time = between(0.1, 0.5)

{locust_on_start}

    @task
    def test_target(self):
        with self.client.get({escaped_path}, verify=False, catch_response=True) as response:
            if response.status_code > 0:
                response.success()
""")

    cmd = [
        "locust",
        "--headless",
        "-u", locust_users,
        "-r", locust_spawn,
        "--run-time", locust_runtime,
        "--host", base_host,
        "--locustfile", script_path,
        "--print-stats",
    ]

    return cmd, [script_path]


def _build_stressor_cmd(tool_config, endpoint_url, target_domain, scan_id,
                         concurrency, duration, base_dir):
    """Build a TA_Stresser command.

    May create a temporary proxy file.

    Returns:
        (cmd: list[str], temp_files: list[str])
    """
    stresser_method = sanitize(tool_config.get("method"), default="GET")
    stresser_threads = sanitize(tool_config.get("threads"), default=str(concurrency))
    stresser_duration = sanitize(tool_config.get("duration"), default=str(duration))

    # Convert duration to integer seconds (stressor expects bare integer)
    dur_match = re.match(r"^(\d+)([smh]?)$", stresser_duration.strip())
    if dur_match:
        val = int(dur_match.group(1))
        unit = dur_match.group(2) or "s"
        if unit == "m":
            stresser_duration = str(val * 60)
        elif unit == "h":
            stresser_duration = str(val * 3600)
        else:
            stresser_duration = str(val)

    stresser_rpc = sanitize(tool_config.get("rpc"), default="1")
    stresser_proxy_type = sanitize(tool_config.get("proxy_type"), default="0")

    # Write proxy list to temp file if proxies are configured
    temp_proxy_path = None
    try:
        from scanEngine.models import Proxy
        proxy_lines = []
        if Proxy.objects.all().exists():
            proxy_config = Proxy.objects.first()
            if proxy_config.use_proxy and proxy_config.proxies:
                for line in proxy_config.proxies.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    for scheme in ("http://", "https://", "socks4://", "socks5://",
                                   "socks5h://", "socks4a://"):
                        if line.lower().startswith(scheme):
                            line = line[len(scheme):]
                            break
                    if line:
                        proxy_lines.append(line)
        if proxy_lines:
            tf = tempfile.NamedTemporaryFile(
                mode="w", delete=False, suffix=".txt", prefix="proxies_stressor_"
            )
            tf.write("\n".join(proxy_lines) + "\n")
            tf.close()
            temp_proxy_path = tf.name
    except Exception as e:
        logger.error("[stress_cmd_builder] Failed to create stressor proxy file: %s", e)

    script_path = os.path.join(base_dir, "reNgine", "stressor", "stressor.py")
    stresser_proxy_file = temp_proxy_path or ""

    is_l7 = stresser_method in ("CFB", "BYPASS", "GET", "POST", "OVH", "STRESS",
                                  "SLOW", "HEAD", "COOKIE", "TOR")
    if is_l7:
        cmd = [
            "python3", script_path,
            stresser_method,
            endpoint_url,
            stresser_proxy_type,
            stresser_threads,
            stresser_proxy_file if stresser_proxy_file else "none",
            stresser_rpc,
            stresser_duration,
            "debug",
        ]
    else:
        target_host_port = f"{target_domain}:{tool_config.get('port', '80')}"
        if stresser_proxy_file:
            cmd = [
                "python3", script_path,
                stresser_method,
                target_host_port,
                stresser_threads,
                stresser_duration,
                stresser_proxy_type,
                stresser_proxy_file,
            ]
        else:
            cmd = [
                "python3", script_path,
                stresser_method,
                target_host_port,
                stresser_threads,
                stresser_duration,
            ]

    temp_files = [temp_proxy_path] if temp_proxy_path else []
    return cmd, temp_files


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_stress_command(tool, tool_config, endpoint_url, target_domain, scan_id,
                          concurrency, duration, single_proxy=None,
                          k6_user_agent=None, base_dir=None):
    """Build the shell command for a stress tool.

    Dispatches to the per-tool builder and returns a shell command string
    ready for ``subprocess.Popen(..., shell=True)`` plus a list of temp files
    that must be removed after the subprocess exits.

    Args:
        tool (str): One of "k6", "wrk", "hping3", "locust", "stressor".
        tool_config (dict): Tool-specific configuration dict from the API payload.
        endpoint_url (str): Full HTTP URL of the target endpoint.
        target_domain (str): Bare hostname/domain (used by hping3 and L4 stressor).
        scan_id (int): ScanHistory PK — used for unique temp-file naming.
        concurrency (int): Default VU/connection count (overridden by tool_config if set).
        duration (str): Default duration string e.g. "30s" (overridden by tool_config).
        single_proxy (str, optional): Single proxy URL for tools that support it.
        k6_user_agent (str, optional): User-Agent string from OpSec settings.
        base_dir (str, optional): Django BASE_DIR; required for stressor script path.

    Returns:
        tuple[str, list[str]]: (cmd_str, temp_files)
            cmd_str   — space-joined command suitable for shell=True Popen.
            temp_files — list of absolute paths to remove after process exits.

    Raises:
        ValueError: If *tool* is not one of the supported tool names.
    """
    if tool == "k6":
        cmd, temps = _build_k6_cmd(
            tool_config, endpoint_url, scan_id, concurrency, duration,
            single_proxy=single_proxy, k6_user_agent=k6_user_agent,
        )
    elif tool == "wrk":
        cmd, temps = _build_wrk_cmd(
            tool_config, endpoint_url, concurrency, duration,
            k6_user_agent=k6_user_agent,
        )
    elif tool == "hping3":
        cmd, temps = _build_hping3_cmd(tool_config, target_domain, duration)
    elif tool == "locust":
        cmd, temps = _build_locust_cmd(
            tool_config, endpoint_url, scan_id, concurrency, duration,
            single_proxy=single_proxy, k6_user_agent=k6_user_agent,
        )
    elif tool == "stressor":
        cmd, temps = _build_stressor_cmd(
            tool_config, endpoint_url, target_domain, scan_id,
            concurrency, duration, base_dir=base_dir or "",
        )
    else:
        raise ValueError(f"Unsupported stress tool: {tool!r}")

    cmd_str = " ".join(shlex.quote(str(c)) for c in cmd)
    return cmd_str, temps
