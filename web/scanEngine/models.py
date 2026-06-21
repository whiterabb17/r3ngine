import yaml
import logging
from typing import Any
from django.db import models

logger = logging.getLogger('django')


class hybrid_property:
    def __init__(self, func):
        self.func = func
        self.name = func.__name__
        self.exp = None

    def __get__(self, instance, owner):
        if instance is None:
            return self
        return self.func(instance)

    def __set__(self, instance, value):
        pass

    def expression(self, exp):
        self.exp = exp
        return self

class EngineType(models.Model):
    id = models.AutoField(primary_key=True)
    engine_name = models.CharField(max_length=200)
    yaml_configuration = models.TextField()
    default_engine = models.BooleanField(null=True, default=False)

    def __str__(self):
        return self.engine_name

    def get_number_of_steps(self):
        return len(self.tasks) if self.tasks else 0

    @hybrid_property
    def tasks(self):
        if not self.yaml_configuration:
            return []
        try:
            config = yaml.safe_load(self.yaml_configuration)
            if isinstance(config, dict):
                return list(config.keys())
        except Exception:
            pass
        return []

    def has_task(self, task_name):
        return task_name in self.tasks

class Wordlist(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=200)
    short_name = models.CharField(max_length=50, unique=True)
    count = models.IntegerField(default=0)

    def __str__(self):
        return self.name


class Configuration(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=200)
    short_name = models.CharField(max_length=50, unique=True)
    content = models.TextField()

    def __str__(self):
        return self.name


class InterestingLookupModel(models.Model):
    id = models.AutoField(primary_key=True)
    keywords = models.TextField(null=True, blank=True)
    custom_type = models.BooleanField(default=False)
    title_lookup = models.BooleanField(default=True)
    url_lookup = models.BooleanField(default=True)
    condition_200_http_lookup = models.BooleanField(default=False)


class Notification(models.Model):
    id = models.AutoField(primary_key=True)
    send_to_slack = models.BooleanField(default=False)
    send_to_lark = models.BooleanField(default=False)
    send_to_discord = models.BooleanField(default=False)
    send_to_telegram = models.BooleanField(default=False)

    slack_hook_url = models.CharField(max_length=200, null=True, blank=True)
    lark_hook_url = models.CharField(max_length=200, null=True, blank=True)
    discord_hook_url = models.CharField(max_length=200, null=True, blank=True)
    telegram_bot_token = models.CharField(max_length=100, null=True, blank=True)
    telegram_bot_chat_id = models.CharField(max_length=100, null=True, blank=True)

    send_scan_status_notif = models.BooleanField(default=True)
    send_interesting_notif = models.BooleanField(default=True)
    send_vuln_notif = models.BooleanField(default=True)
    send_subdomain_changes_notif = models.BooleanField(default=True)

    send_scan_output_file = models.BooleanField(default=True)
    send_scan_tracebacks = models.BooleanField(default=True)


class Proxy(models.Model):
    id = models.AutoField(primary_key=True)
    use_proxy = models.BooleanField(default=False)
    proxies = models.TextField(blank=True, null=True)
    use_proxychains = models.BooleanField(default=False)
    use_tor = models.BooleanField(default=False)
    # Timestamp of the last batch-verification run (set by fetch_proxies_task).
    # Used by get_random_proxy() to skip redundant re-validation while the list
    # is still fresh.
    proxies_verified_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text='When the stored proxy list was last batch-verified as live.',
    )
    # How many minutes the batch-verified list is considered trustworthy before
    # get_random_proxy() falls back to individual re-validation.
    proxy_ttl_minutes = models.IntegerField(
        default=120,
        help_text='Minutes before the verified proxy list is considered stale (default 120).',
    )


class OpSec(models.Model):
    id = models.AutoField(primary_key=True)
    enable_opsec = models.BooleanField(default=False)
    enable_random_ua = models.BooleanField(default=True)
    enable_rate_limit = models.BooleanField(default=False)
    max_rps = models.IntegerField(default=10)
    enable_delay = models.BooleanField(default=False)
    delay_ms = models.IntegerField(default=100)
    enable_jitter = models.BooleanField(default=False)
    jitter_percent = models.IntegerField(default=10)
    enable_waf_bypass = models.BooleanField(default=False)
    enable_ja3_randomization = models.BooleanField(default=False)
    http_protocol = models.CharField(max_length=10, default='http2') # http1.1, http2
    custom_dns_servers = models.TextField(blank=True, null=True)
    enable_metadata_stripping = models.BooleanField(default=False)
    # When True, check_proxy_robust() will compare the proxy's reported outbound
    # IP against the server's real IP and reject transparent proxies that expose
    # it.  Opt-in because it requires an extra HTTP call to detect the server IP.
    enable_transparent_proxy_detection = models.BooleanField(
        default=False,
        help_text='Reject proxies that do not change the outbound IP (transparent proxies). Opt-in.',
    )


class Hackerone(models.Model):
    id = models.AutoField(primary_key=True)
    # TODO: username and api_key fields will be deprecated in another major release, Instead HackerOneAPIKey model from dasbhboard/models.py will be used
    username = models.CharField(max_length=100, null=True, blank=True) # unused
    api_key = models.CharField(max_length=200, null=True, blank=True) # unused
    send_report = models.BooleanField(default=False, null=True, blank=True)
    send_critical = models.BooleanField(default=True)
    send_high = models.BooleanField(default=True)
    send_medium = models.BooleanField(default=False)
    report_template = models.TextField(blank=True, null=True)


class VulnerabilityReportSetting(models.Model):
    id = models.AutoField(primary_key=True)
    primary_color = models.CharField(max_length=10, null=True, blank=True, default='#FFB74D')
    secondary_color = models.CharField(max_length=10, null=True, blank=True, default='#212121')
    company_name = models.CharField(max_length=100, null=True, blank=True)
    company_address = models.CharField(max_length=200, null=True, blank=True)
    company_email = models.CharField(max_length=100, null=True, blank=True)
    company_website = models.CharField(max_length=100, null=True, blank=True)
    show_rengine_banner = models.BooleanField(default=True)
    show_executive_summary = models.BooleanField(default=True)
    executive_summary_description = models.TextField(blank=True, null=True, default='''On **{scan_date}**, **{target_name}** engaged **{company_name}** to perform a security audit on their Web application.

**{company_name}** performed both Security Audit and Reconnaissance using automated tool reNgine. https://github.com/whiterabb17/r3ngine.

## Observations

During the course of this engagement **{company_name}** was able to discover **{subdomain_count}** Subdomains and  **{vulnerability_count}** Vulnerabilities, including informational vulnerabilities and these could pose a significant risk to the security of the application.

The breakdown of the Vulnerabilities Identified in **{target_name}** by severity are as follows:

* Critical : {critical_count}
* High : {high_count}
* Medium : {medium_count}
* Low : {low_count}
* Info : {info_count}
* Unknown : {unknown_count}

**{company_name}** recommends that these issues be addressed in timely manner.

''')
    enable_llm_report_generation = models.BooleanField(default=False)
    show_footer = models.BooleanField(default=False)
    footer_text = models.CharField(max_length=200, null=True, blank=True)
    include_attack_surface_map = models.BooleanField(default=False)


class InstalledExternalTool(models.Model):
    id = models.AutoField(primary_key=True)
    logo_url = models.CharField(max_length=200, null=True, blank=True)
    name = models.CharField(max_length=100)
    description = models.CharField(max_length=2000)
    github_url = models.CharField(max_length=500)
    license_url = models.CharField(max_length=500, null=True, blank=True)
    version_lookup_command = models.CharField(max_length=500, null=True, blank=True)
    update_command = models.CharField(max_length=500, null=True, blank=True)
    install_command = models.CharField(max_length=500)
    version_match_regex = models.CharField(max_length=100, default=r'[vV]*(\d+\.)?(\d+\.)?(\*|\d+)', null=True, blank=True)
    is_default = models.BooleanField(default=False)
    is_subdomain_gathering = models.BooleanField(default=False)
    is_github_cloned = models.BooleanField(default=False)
    github_clone_path = models.CharField(max_length=1500, null=True, blank=True)
    subdomain_gathering_command = models.CharField(max_length=300, null=True, blank=True)

    def __str__(self):
        return self.name


class HardwareProfile(models.Model):
    PROFILE_TYPE_CHOICES = [
        ('builtin', 'Built-in'),
        ('custom', 'Custom'),
    ]

    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(help_text="Description of the profile", blank=True, null=True)
    threads = models.IntegerField(default=10)
    rate_limit = models.IntegerField(default=150)
    timeout = models.IntegerField(default=10, help_text="Timeout in minutes")
    delay = models.FloatField(default=0.0, help_text="Delay between requests in seconds")
    retries = models.IntegerField(default=2)
    profile_type = models.CharField(
        max_length=20,
        choices=PROFILE_TYPE_CHOICES,
        default='custom',
    )
    is_active = models.BooleanField(default=True)
    is_default = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.name} ({self.profile_type})"


class ScanProfile(models.Model):
    """Comprehensive scan profile combining throttle settings and scanning mode flags.

    Distinct from HardwareProfile (hardware capability limits). ScanProfile controls
    WHAT scanning behavior is active (passive-only, stealth, headless, etc.) alongside
    optional rate throttling. Ported from rengine-ng's Secator profile system.

    Applied to every tool activity via ctx['profile'] in the workflow context.
    """

    CATEGORY_CHOICES = [
        ('speed', 'Speed / Throttle'),
        ('evasion', 'Evasion'),
        ('content', 'Content'),
        ('network', 'Network'),
        ('general', 'General'),
        ('hardware', 'Hardware'),
    ]

    name = models.CharField(max_length=64, unique=True)
    description = models.TextField(blank=True, default='')
    category = models.CharField(max_length=32, choices=CATEGORY_CHOICES, default='general')
    is_builtin = models.BooleanField(default=False)

    # Throttle settings (null = use tool default)
    rate_limit = models.PositiveIntegerField(null=True, blank=True)
    delay = models.FloatField(null=True, blank=True)
    threads = models.PositiveIntegerField(null=True, blank=True)
    timeout = models.PositiveIntegerField(null=True, blank=True)
    retries = models.PositiveIntegerField(null=True, blank=True)

    # Mode flags
    passive = models.BooleanField(default=False)
    active = models.BooleanField(default=False)
    stealth = models.BooleanField(default=False)
    headless = models.BooleanField(default=False)
    screenshot = models.BooleanField(default=False)
    hunt_secrets = models.BooleanField(default=False)
    nuclei_full = models.BooleanField(default=False)
    brute_dns = models.BooleanField(default=False)
    brute_http = models.BooleanField(default=False)
    test_ssl = models.BooleanField(default=False)
    all_ports = models.BooleanField(default=False)
    tor = models.BooleanField(default=False)
    fragment = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['category', 'name']

    def __str__(self):
        return self.name

    def to_ctx_dict(self) -> dict[str, Any]:
        """Return throttle + flag settings as a dict for merging into a workflow ctx.

        Only non-None throttle values are included. Mode flags are only included when
        True — absent keys mean False. Consumers must use ctx.get('flag', False).
        """
        d = {}
        if self.rate_limit is not None:
            d['rate_limit'] = self.rate_limit
        if self.delay is not None:
            d['delay'] = self.delay
        if self.threads is not None:
            d['threads'] = self.threads
        if self.timeout is not None:
            d['timeout'] = self.timeout
        if self.retries is not None:
            d['retries'] = self.retries
        for flag in ('passive', 'active', 'stealth', 'headless', 'screenshot',
                     'hunt_secrets', 'nuclei_full', 'brute_dns', 'brute_http',
                     'test_ssl', 'all_ports', 'tor', 'fragment'):
            if getattr(self, flag):
                d[flag] = True
        return d
