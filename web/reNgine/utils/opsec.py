import os
import random
import logging
import re
import tempfile
import subprocess
import json
from urllib.parse import urlparse
from django.conf import settings
from scanEngine.models import OpSec, Proxy
from reNgine.definitions import BRUTUS_EXEC_PATH, PROXYCHAINS_EXEC_PATH

class OpSecManager:
    """
    Manages Operational Security (OpSec) settings and provides utility functions
    to inject stealth flags into tool commands.
    """

    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.2; rv:122.0) Gecko/20100101 Firefox/122.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPad; CPU OS 17_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
    ]

    WAF_BYPASS_HEADERS = [
        "X-Forwarded-For: 127.0.0.1",
        "X-Originating-IP: 127.0.0.1",
        "X-Remote-IP: 127.0.0.1",
        "X-Remote-Addr: 127.0.0.1",
        "X-Client-IP: 127.0.0.1",
        "X-Host: 127.0.0.1",
        "Forwarded: for=127.0.0.1;proto=http;by=127.0.0.1",
    ]

    def __init__(self):
        self.settings = OpSec.objects.first()
        self.proxy_settings = Proxy.objects.first()

    def is_enabled(self):
        return self.settings and self.settings.enable_opsec

    def get_random_ua(self, proxy_ip=None):
        ua = random.choice(self.USER_AGENTS)
        if proxy_ip:
            ua = ua.replace("127.0.0.1", proxy_ip)
        return ua

    def get_waf_headers(self, proxy_ip=None):
        headers = self.WAF_BYPASS_HEADERS
        if proxy_ip:
            headers = [h.replace("127.0.0.1", proxy_ip) for h in headers]
        return headers

    def _extract_proxy_ip(self, proxy_str):
        """
        Extracts the IP or Hostname from a proxy string.
        Expected format: http://{ip}:{port} or socks5://{ip}:{port}
        """
        if not proxy_str:
            return None
        
        # Add scheme if missing for urlparse
        if "://" not in proxy_str:
            proxy_str = f"http://{proxy_str}"
            
        try:
            parsed = urlparse(proxy_str)
            return parsed.hostname
        except Exception:
            return None

    def apply_stealth(self, tool_name, command, proxy=None):
        """
        Applies stealth flags to a given command string for a specific tool.
        """
        if not self.is_enabled():
            return command

        proxy_ip = self._extract_proxy_ip(proxy)

        if tool_name == "nuclei":
            return self._apply_nuclei(command, proxy_ip)
        elif tool_name == "nmap":
            return self._apply_nmap(command, proxy_ip)
        elif tool_name == "subfinder":
            return self._apply_subfinder(command)
        elif tool_name == "amass":
            return self._apply_amass(command)
        elif tool_name == "ffuf":
            return self._apply_ffuf(command, proxy_ip)
        elif tool_name == "httpx":
            return self._apply_httpx(command, proxy_ip)

        elif tool_name == "dalfox":
            return self._apply_dalfox(command, proxy_ip)
        elif tool_name == "dirsearch":
            return self._apply_dirsearch(command, proxy_ip)
        
        return command

    def _apply_nuclei(self, cmd, proxy_ip=None):
        flags = []
        if self.settings.enable_random_ua:
            flags.append(f"-H 'User-Agent: {self.get_random_ua(proxy_ip)}'")
        
        if self.settings.enable_waf_bypass:
            for header in self.get_waf_headers(proxy_ip):
                flags.append(f"-H '{header}'")
        
        if self.settings.enable_rate_limit and not re.search(r'\s-rl\s', cmd):
            flags.append(f"-rl {self.settings.max_rps}")

        if self.settings.http_protocol == "http2":
            flags.append("-fh2")
        
        if self.settings.custom_dns_servers:
            dns = ",".join(self.settings.custom_dns_servers.splitlines())
            flags.append(f"-resolvers {dns}")

        return f"{cmd} {' '.join(flags)}"

    def _apply_nmap(self, cmd, proxy_ip=None):
        flags = []
        if self.settings.enable_delay:
            flags.append(f"--scan-delay {self.settings.delay_ms}ms")
        
        if self.settings.enable_random_ua:
            flags.append(f"--script-args http.useragent='{self.get_random_ua(proxy_ip)}'")
        
        if self.settings.custom_dns_servers:
            dns = ",".join(self.settings.custom_dns_servers.splitlines())
            flags.append(f"--dns-servers {dns}")

        return f"{cmd} {' '.join(flags)}"

    def _apply_subfinder(self, cmd):
        flags = []
        if self.settings.enable_rate_limit:
            # subfinder -rl (requests per minute)
            flags.append(f"-rl {self.settings.max_rps * 60}")
        return f"{cmd} {' '.join(flags)}"

    def _apply_amass(self, cmd):
        return cmd

    def _apply_ffuf(self, cmd, proxy_ip=None):
        flags = []
        if self.settings.enable_random_ua:
            flags.append(f"-H 'User-Agent: {self.get_random_ua(proxy_ip)}'")
        if self.settings.enable_rate_limit and '-rate' not in cmd:
            flags.append(f"-rate {self.settings.max_rps}")
        return f"{cmd} {' '.join(flags)}"

    def _apply_httpx(self, cmd, proxy_ip=None):
        flags = []
        if self.settings.enable_random_ua:
            flags.append(f"-H 'User-Agent: {self.get_random_ua(proxy_ip)}'")
        if self.settings.http_protocol == "http2":
            flags.append("-http2")
        return f"{cmd} {' '.join(flags)}"

    def _apply_dalfox(self, cmd, proxy_ip=None):
        flags = []
        if self.settings.enable_random_ua:
            flags.append(f"--user-agent '{self.get_random_ua(proxy_ip)}'")
        
        if self.settings.enable_waf_bypass:
            for header in self.get_waf_headers(proxy_ip):
                flags.append(f"-H '{header}'")
        
        if self.settings.enable_delay:
            flags.append(f"--delay {self.settings.delay_ms}")
            
        return f"{cmd} {' '.join(flags)}"

    def _apply_dirsearch(self, cmd, proxy_ip=None):
        flags = []
        if self.settings.enable_random_ua:
            flags.append(f"-H 'User-Agent: {self.get_random_ua(proxy_ip)}'")
        
        if self.settings.enable_waf_bypass:
            for header in self.get_waf_headers(proxy_ip):
                flags.append(f"-H '{header}'")
        
        return f"{cmd} {' '.join(flags)}"

    def strip_metadata(self, file_path):
        """
        Strips metadata from a given file. Supported formats: PDF, JPG, PNG.
        """
        if not self.is_enabled() or not self.settings.enable_metadata_stripping:
            return

        if not os.path.exists(file_path):
            return

        ext = os.path.splitext(file_path)[1].lower()
        try:
            if ext == ".pdf":
                import pikepdf
                with pikepdf.open(file_path, allow_overwriting_input=True) as pdf:
                    del pdf.Root.Metadata
                    pdf.save(file_path)
            elif ext in [".jpg", ".jpeg", ".png"]:
                from PIL import Image
                img = Image.open(file_path)
                data = list(img.getdata())
                img_without_exif = Image.new(img.mode, img.size)
                img_without_exif.putdata(data)
                img_without_exif.save(file_path)
        except Exception:
            pass

    def strip_directory(self, directory):
        """
        Recursively strips metadata from all files in a directory.
        """
        if not self.is_enabled() or not self.settings.enable_metadata_stripping:
            return
        

class ProxychainsWrapper:
    """
    Handles dynamic generation of proxychains configurations for stealthy rotation.
    """
    def __init__(self):
        self.proxies = self._fetch_proxies()

    def _fetch_proxies(self):
        proxy_obj = Proxy.objects.first()
        if proxy_obj and proxy_obj.use_tor:
            return ["socks5 tor 9050"]
        if not proxy_obj or not proxy_obj.use_proxy or not proxy_obj.proxies:
            return []
        
        # Clean and validate proxy list
        proxies = []
        for line in proxy_obj.proxies.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Format expected by proxychains: type host port [user pass]
            # reNgine might store as protocol://host:port or host:port
            
            p_type = "socks5" # default
            p_host = ""
            p_port = ""
            
            if "://" in line:
                p_type = line.split("://")[0].lower()
                if p_type == "http" or p_type == "https":
                    p_type = "http" # proxychains uses 'http' for both
                line = line.split("://")[1]
            
            if ":" in line:
                parts = line.split(":")
                p_host = parts[0]
                p_port = parts[1]
                # If there are more parts, could be user:pass@host:port or host:port:user:pass
                # But simple host:port is most common in reNgine
                proxies.append(f"{p_type} {p_host} {p_port}")
            elif " " in line:
                # Already in type host port format
                proxies.append(line)
                
        return proxies

    def get_random_proxy(self):
        """
        Retrieves a random, verified alive, and unauthenticated proxy from the fetched proxy list.
        Converts the proxychains line format to standard requests proxy dictionary for testing.

        Enhancement: all candidates are checked in *parallel* (up to 10 workers) and the first
        live one wins, instead of the old sequential loop capped at 5.  This removes the hard
        upper-bound on tries while cutting worst-case wait time dramatically.

        Returns:
            str: Validated proxy line in 'type host port [user pass]' format, or None if no valid proxy is found.
        """
        if not self.proxies:
            return None

        from concurrent.futures import ThreadPoolExecutor, as_completed
        from reNgine.common_func import check_proxy_robust

        # Shuffle for random distribution across the available pool
        test_list = list(self.proxies)
        random.shuffle(test_list)

        _log = logging.getLogger(__name__)

        def _check_line(proxy_str):
            """Parse a proxychains line, validate via HTTP, and return the line or None."""
            parts = proxy_str.split()
            if len(parts) < 3:
                return None
            p_type, p_host, p_port = parts[0], parts[1], parts[2]
            scheme = 'http' if p_type in ['http', 'https'] else p_type
            proxy_url = f'{scheme}://{p_host}:{p_port}'
            if check_proxy_robust(proxy_url, timeout=10):
                return proxy_str
            _log.error('Proxychains proxy %s validation failed.', proxy_url)
            return None

        max_workers = min(10, len(test_list))
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            future_map = {pool.submit(_check_line, line): line for line in test_list}
            for fut in as_completed(future_map):
                try:
                    result = fut.result()
                except Exception:
                    result = None
                if result:
                    # Cancel remaining futures – we have a winner
                    for other in future_map:
                        if other is not fut:
                            other.cancel()
                    return result

        return None


    def should_wrap(self):
        proxy_obj = Proxy.objects.first()
        if proxy_obj and proxy_obj.use_tor:
            return True
        return proxy_obj and proxy_obj.use_proxy and proxy_obj.use_proxychains

    def write_temp_config(self, proxy_str):
        fd, path = tempfile.mkstemp(suffix=".conf", prefix="proxychains_")
        os.close(fd)
        with open(path, 'w') as f:
            f.write("strict_chain\n")
            f.write("proxy_dns\n")
            f.write("tcp_read_time_out 15000\ntcp_connect_time_out 8000\n")
            f.write("[ProxyList]\n")
            f.write(f"{proxy_str}\n")
        return path

    def wrap_command(self, cmd, proxy=None):
        """
        Conditionally wraps a command with proxychains if enabled in settings.
        Returns (wrapped_command, temp_config_path)
        """
        if not proxy:
            proxy = self.get_random_proxy()
        
        if proxy and self.should_wrap():
            conf_path = self.write_temp_config(proxy)
            return f"{PROXYCHAINS_EXEC_PATH} -f {conf_path} {cmd}", conf_path
        return cmd, None


