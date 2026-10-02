// ─── Section envelope ────────────────────────────────────────────────────────

export interface SectionState<T> {
  enabled: boolean;
  config: T;
}

// ─── Global ──────────────────────────────────────────────────────────────────

export interface GlobalConfig {
  threads: number;
  timeout: number;
  rate_limit: number;
  retries: number;
  intensity: 'normal' | 'aggressive' | 'light';
  custom_headers: string[];
  enable_http_crawl: boolean;
}

// ─── Tier 1: Discovery ───────────────────────────────────────────────────────

export interface SubdomainDiscoveryConfig {
  uses_tools: string[];
  threads: number;
  timeout: number;
  enable_http_crawl: boolean;
  use_subfinder_config: boolean;
  use_amass_config: boolean;
  amass_wordlist: string;
}

export interface DnsSecurityConfig {
  enable_axfr: boolean;
  enable_dnssec_check: boolean;
  enable_dns_brute: boolean;
  /** Response/query size ratio from which a resolver counts as an amplifier. */
  amplification_threshold: number;
}

export interface OsintConfig {
  discover: string[];
  dorks: string[];
  /** Plain-text dorks (`_target_` is replaced by the host). */
  custom_dorks: string[];
  /**
   * Structured custom dorks (`lookup_site` with `lookup_extensions` or `lookup_keywords`)
   * from the YAML. The form has no editor for them and writes them back unchanged.
   */
  custom_dork_rules: Record<string, unknown>[];
  /** Extra dork runners on top of GoFuzz: dorks_hunter, xnldorker. */
  dork_engines: string[];
  /** Maximum documents the metainfo lookup inspects. */
  documents_limit: number;
  /** EmailFinder, part of the `emails` lookup. */
  emailfinder: boolean;
  whatbreach: boolean;
  whatbreach_download_databases: boolean;
  credspy: boolean;
  /** Breach lookups, written to osint.leaks_and_secrets. */
  leaklookup: boolean;
  leaksearch: boolean;
  microsoft_recon: boolean;
  /** misconfig-mapper against third-party services. */
  misconfig: boolean;
  /** osint.domain_security.spoofcheck */
  spoofcheck: boolean;
  /** osint.api_leaks.* */
  porch_pirate: boolean;
  postleaks: boolean;
  /** SwaggerSpy internet search (the post-crawl path probe is post_crawl_osint.swaggerspy). */
  swaggerspy: boolean;
  /** osint.github_analysis: written only when on, as the backend runs it for any non-empty mapping. */
  github_analysis: boolean;
  /** osint.github_analysis.uses_tools */
  github_tools: string[];
  /** osint.github_analysis.gato */
  github_gato: boolean;
  /** osint.github_analysis.github_orgs; empty derives the organisation from the domain. */
  github_orgs: string[];
}

/** `amass_intel_discovery` in engine YAML: its presence schedules Amass Intel in Tier 1. */
export interface AmassIntelConfig {
  /** Falls back to subdomain_discovery.use_amass_config when the section does not set it. */
  use_amass_config: boolean;
}

/** `baddns` in engine YAML: its presence schedules the standalone BadDNS step; it has no settings. */
export type BaddnsConfig = Record<string, never>;

export interface SpiderfootConfig {
  modules: string;
  intensity: 'normal' | 'fast' | 'deep';
  threads: number;
}

export interface VigoliumHarvestConfig {
  strategy: 'fast' | 'balanced' | 'thorough';
  concurrency: number;
  rate_limit: number;
  timeout: string;
}

export interface VigoliumDiscoveryConfig {
  strategy: 'fast' | 'balanced' | 'thorough';
  concurrency: number;
  rate_limit: number;
  timeout: string;
}

export interface FirewallVpnConfig {
  run_ike_scan: boolean;
  run_sslscan: boolean;
  enable_testssl: boolean;
  enable_crt_sh: boolean;
  ports: number[];
}

// ─── Tier 2: Surface ─────────────────────────────────────────────────────────

export interface HttpCrawlConfig {
  threads: number;
  follow_redirect: boolean;
}

export interface PortScanConfig {
  ports: string[];
  rate_limit: number;
  threads: number;
  timeout: number;
  passive: boolean;
  enable_http_crawl: boolean;
  enable_nmap: boolean;
  nmap_cmd: string;
  nmap_script: string;
  nmap_script_args: string;
  exclude_ports: string[];
  exclude_subdomains: boolean;
  /** enum4linux-ng, SNMP, LDAP and rdp-sec-check against matching open ports. */
  enable_network_enum: boolean;
}

/**
 * `email_security` in engine YAML. The backend treats a missing section as enabled,
 * so the section toggle maps to `email_security.enabled`, not to key presence.
 */
export interface EmailSecurityConfig {
  /** Reacher mailbox probing against the target MX (`mailbox_verification.enabled`). */
  mailbox_verification: boolean;
  /** Per-address check timeout in seconds (backend clamps to 1–120). */
  timeout: number;
  /** Maximum addresses probed per scan (backend clamps to 1–1000). */
  max_candidates: number;
  /** Pause between checks in milliseconds (backend clamps to 0–10000). */
  delay_ms: number;
  /** Optional self-hosted Reacher origin; empty uses the bundled CLI. */
  http_url: string;
}

// Screenshot has no settings the task reads; presence in YAML = enabled.
export type ScreenshotConfig = Record<string, never>;

// ─── Tier 3+4: Recon & Fuzzing ───────────────────────────────────────────────

export interface FetchUrlConfig {
  uses_tools: string[];
  remove_duplicate_endpoints: boolean;
  duplicate_fields: string[];
  enable_http_crawl: boolean;
  gf_patterns: string[];
  ignore_file_extensions: string[];
  threads: number;
}

export interface WebApiDiscoveryConfig {
  uses_tools: string[];
  scan_only_active: boolean;
  threads: number;
  timeout: number;
  kr_wordlist: string;
  run_favirecon: boolean;
  run_sourcemapper: boolean;
  run_grpcurl: boolean;
  run_julius: boolean;
  run_gqlspection: boolean;
}

export interface ParamDiscoveryConfig {
  min_confidence: number;
}

export interface DirFileFuzzConfig {
  run_ffuf: boolean;
  run_dirsearch: boolean;
  run_feroxbuster: boolean;
  auto_calibration: boolean;
  enable_http_crawl: boolean;
  extensions: string[];
  wordlist_name: string;
  rate_limit: number;
  threads: number;
  timeout: number;
  max_time: number;
  recursive_level: number;
  match_http_status: number[];
  follow_redirect: boolean;
  stop_on_error: boolean;
  max_repeat_by_signature: number;
}

/** `post_crawl_osint` in engine YAML, run after directory fuzzing (Tier 4a). */
export interface PostCrawlOsintConfig {
  /** exifray document-metadata search; the YAML key keeps its old metagoofil name. */
  metagoofil: boolean;
  /** SwaggerSpy path probe against live subdomains. */
  swaggerspy: boolean;
}

// ─── Tier 5: Analysis ────────────────────────────────────────────────────────

export interface WafDetectionConfig {
  enable_http_crawl: boolean;
  use_shodan: boolean;
  use_censys: boolean;
}

export interface WafBypassConfig {
  use_benchmarking: boolean;
  use_nuclei: boolean;
}

export interface LeaksSecretsConfig {
  gitleaks: boolean;
  trufflehog: boolean;
  betterleaks: boolean;
}

export interface VigoliumAnalysisConfig {
  strategy: 'fast' | 'balanced' | 'thorough';
  concurrency: number;
  rate_limit: number;
  timeout: string;
}

// ─── Tier 6: Vulnerability ───────────────────────────────────────────────────

export interface NucleiConfig {
  use_nuclei_config: boolean;
  /** `nuclei -update-templates` before a scan that has no pre-batched tags. */
  auto_update_templates: boolean;
  severities: string[];
  tags: string[];
  templates: string[];
  custom_templates: string[];
  /** Template budget per tag batch in the Temporal nuclei planner (backend default 100). */
  max_templates_per_batch: number;
}

/** `vulnerability_scan.dalfox`. A 0 or empty value leaves the flag out, as the task does. */
export interface DalfoxConfig {
  waf_evasion: boolean;
  deep_scan: boolean;
  remote_payloads: boolean;
  remote_wordlists: boolean;
  /** Whole-run limit in seconds (`--scan-timeout`); 0 means no limit. */
  scan_timeout: number;
  /** Blind XSS callback (`-b`). */
  blind_xss_server: string;
  /** Empty: the engine-wide `user_agent`. */
  user_agent: string;
  /** Per-request timeout in seconds; 0: dalfox's own default. */
  timeout: number;
  /** Pause between requests in milliseconds; 0: none. */
  delay: number;
  /** `--workers`; 0: the engine-wide threads. */
  threads: number;
}

/** `vulnerability_scan.s3scanner`. */
export interface S3ScannerConfig {
  /** 0: the engine-wide threads. */
  threads: number;
  /** One s3scanner run per provider. */
  providers: string[];
}

export interface CpanelScannerConfig {
  run_cpanel2shell: boolean;
  cpanel_user_wordlist: string;
  /** `single` keeps one proxy for every target; `rotating` picks one per target. */
  proxy_type: 'rotating' | 'single';
}

export interface VigoliumVulnConfig {
  strategy: 'fast' | 'balanced' | 'thorough';
  concurrency: number;
  rate_limit: number;
  timeout: string;
  run_phase_a: boolean;  // Phase A: spidering (Tier 6 vuln scan)
  run_phase_b: boolean;  // Phase B: known-issue-scan + dynamic-assessment
  scope_origin: 'all' | 'relaxed' | 'balanced' | 'strict';
  skip_spidering: boolean;
}

export interface AcunetixConfig {
  /** Register every live, externally reachable subdomain as an Acunetix target. */
  submit_live_subdomains: boolean;
  /** A host already submitted within this many days is skipped. */
  resubmit_after_days: number;
  /** Also start an Acunetix scan for each freshly submitted target. */
  start_scan_on_submit: boolean;
  /** Hosts sent to Acunetix per batch. */
  submission_batch_size: number;
  /** Seconds to wait between batches. */
  submission_batch_pause: number;
  /** Scans started per run; the remaining hosts are added as targets and scanned on a later run. */
  max_scans_per_run: number;
}

export const DEFAULT_ACUNETIX_CONFIG: AcunetixConfig = {
  submit_live_subdomains: false,
  resubmit_after_days: 3,
  start_scan_on_submit: false,
  submission_batch_size: 20,
  submission_batch_pause: 5,
  max_scans_per_run: 20,
};

export interface VulnerabilityScanConfig {
  run_nuclei: boolean;
  run_dalfox: boolean;
  run_crlfuzz: boolean;
  run_s3scanner: boolean;
  run_acunetix: boolean;
  run_wpscan: boolean;
  run_wptaint_scan: boolean;
  run_smugglex: boolean;
  run_second_order: boolean;
  run_nuclei_dast: boolean;
  run_vigolium: boolean;
  run_semgrep: boolean;
  /** vulnerability_scan.react_scanner.run_react2shell */
  run_react2shell: boolean;
  /** Dedup, OpenAPI extraction and GraphQL dispatch after the Tier 6 tools. */
  run_post_scan_processing: boolean;
  /** Nuclei `-c`; a missing key falls back to the engine-wide threads. */
  concurrency: number;
  /** Nuclei and Nuclei DAST `-rl`; falls back to the engine-wide rate_limit. */
  rate_limit: number;
  /** Nuclei and Nuclei DAST `-retries`; falls back to the engine-wide retries. */
  retries: number;
  intensity: 'normal' | 'aggressive' | 'light';
  fetch_gpt_report: boolean;
  enable_http_crawl: boolean;
  wpscan_enumeration: string;
  wpscan_detection_mode: 'mixed' | 'passive' | 'aggressive';
  acunetix?: AcunetixConfig;
  nuclei: NucleiConfig;
  dalfox: DalfoxConfig;
  s3scanner: S3ScannerConfig;
  cpanel_scanner: CpanelScannerConfig;
  vigolium: VigoliumVulnConfig;
}

// ─── Tier 7: Intelligence ────────────────────────────────────────────────────

export interface AttackPathConfig {
  top_n: number;
}

export interface VigoliumAuditConfig {
  intensity: 'quick' | 'balanced' | 'deep';
  use_ai: boolean;
  timeout: number;
}

export interface Tier7Config {
  high_noise_modules: string[];
}

// ─── Root EngineConfig ───────────────────────────────────────────────────────

export interface EngineConfig {
  global: GlobalConfig;
  // Tier 1
  subdomain_discovery: SectionState<SubdomainDiscoveryConfig>;
  dns_security: SectionState<DnsSecurityConfig>;
  osint: SectionState<OsintConfig>;
  spiderfoot_scan: SectionState<SpiderfootConfig>;
  vigolium_harvest: SectionState<VigoliumHarvestConfig>;
  vigolium_discovery: SectionState<VigoliumDiscoveryConfig>;
  firewall_vpn_scan: SectionState<FirewallVpnConfig>;
  amass_intel_discovery: SectionState<AmassIntelConfig>;
  baddns: SectionState<BaddnsConfig>;
  // Tier 2
  http_crawl: SectionState<HttpCrawlConfig>;
  port_scan: SectionState<PortScanConfig>;
  email_security: SectionState<EmailSecurityConfig>;
  screenshot: SectionState<ScreenshotConfig>;
  // Tier 3+4
  fetch_url: SectionState<FetchUrlConfig>;
  web_api_discovery: SectionState<WebApiDiscoveryConfig>;
  param_discovery: SectionState<ParamDiscoveryConfig>;
  dir_file_fuzz: SectionState<DirFileFuzzConfig>;
  post_crawl_osint: SectionState<PostCrawlOsintConfig>;
  // Tier 5
  waf_detection: SectionState<WafDetectionConfig>;
  waf_bypass: SectionState<WafBypassConfig>;
  leaks_and_secrets: SectionState<LeaksSecretsConfig>;
  vigolium_analysis: SectionState<VigoliumAnalysisConfig>;
  // Tier 6
  vulnerability_scan: SectionState<VulnerabilityScanConfig>;
  // Tier 7
  attack_path_modeling: SectionState<AttackPathConfig>;
  vigolium_audit: SectionState<VigoliumAuditConfig>;
  tier_7: SectionState<Tier7Config>;
}

export type SectionKey = keyof Omit<EngineConfig, 'global'>;

// ─── Defaults ────────────────────────────────────────────────────────────────

export const DEFAULT_GLOBAL: GlobalConfig = {
  threads: 30,
  timeout: 5,
  rate_limit: 150,
  retries: 1,
  intensity: 'normal',
  custom_headers: [],
  enable_http_crawl: true,
};

/** reNgine.definitions.S3SCANNER_DEFAULT_PROVIDERS */
export const S3SCANNER_DEFAULT_PROVIDERS = ['gcp', 'aws', 'digitalocean', 'dreamhost', 'linode'];

/** reNgine.definitions.CPANEL_SCANNER_DEFAULT_WORDLIST */
export const CPANEL_DEFAULT_USER_WORDLIST = '/usr/src/wordlist/cpanel_users.txt';

/** What dalfox_xss_scan uses for a missing key. */
export const DEFAULT_DALFOX_CONFIG: DalfoxConfig = {
  waf_evasion: false, deep_scan: false, remote_payloads: false, remote_wordlists: false,
  scan_timeout: 300, blind_xss_server: '', user_agent: '', timeout: 0, delay: 0, threads: 0,
};

export const DEFAULT_ENGINE_CONFIG: EngineConfig = {
  global: DEFAULT_GLOBAL,
  subdomain_discovery: {
    enabled: true,
    config: {
      uses_tools: ['subfinder', 'ctfr', 'sublist3r', 'tlsx', 'oneforall', 'netlas', 'baddns'],
      threads: 30, timeout: 5, enable_http_crawl: true,
      use_subfinder_config: false, use_amass_config: false, amass_wordlist: '',
    },
  },
  dns_security: {
    enabled: false,
    config: { enable_axfr: true, enable_dnssec_check: true, enable_dns_brute: false, amplification_threshold: 10 },
  },
  osint: {
    enabled: false,
    config: {
      discover: ['emails', 'metainfo', 'employees'],
      dorks: ['login_pages', 'admin_panels', 'dashboard_pages', 'stackoverflow',
              'social_media', 'project_management', 'code_sharing', 'config_files',
              'jenkins', 'wordpress_files', 'php_error', 'exposed_documents', 'db_files', 'git_exposed'],
      custom_dorks: [],
      custom_dork_rules: [],
      dork_engines: [],
      documents_limit: 50,
      emailfinder: true,
      whatbreach: true,
      whatbreach_download_databases: false,
      credspy: false,
      leaklookup: false,
      leaksearch: false,
      microsoft_recon: false,
      misconfig: false,
      spoofcheck: false,
      porch_pirate: false,
      postleaks: false,
      swaggerspy: false,
      github_analysis: false,
      github_tools: ['enumerepo', 'trufflehog', 'gitleaks'],
      github_gato: false,
      github_orgs: [],
    },
  },
  spiderfoot_scan: { enabled: false, config: { modules: 'all', intensity: 'normal', threads: 10 } },
  vigolium_harvest: { enabled: true, config: { strategy: 'balanced', concurrency: 30, rate_limit: 100, timeout: '60s' } },
  vigolium_discovery: { enabled: true, config: { strategy: 'balanced', concurrency: 40, rate_limit: 100, timeout: '30s' } },
  firewall_vpn_scan: { enabled: false, config: { run_ike_scan: true, run_sslscan: true, enable_testssl: false, enable_crt_sh: false, ports: [443, 4444, 8443, 10443, 5443] } },
  amass_intel_discovery: { enabled: false, config: { use_amass_config: false } },
  baddns: { enabled: false, config: {} },
  http_crawl: { enabled: true, config: { threads: 30, follow_redirect: true } },
  port_scan: {
    enabled: true,
    config: {
      ports: ['top-100'], rate_limit: 150, threads: 30, timeout: 5,
      passive: false, enable_http_crawl: true, enable_nmap: false,
      nmap_cmd: '', nmap_script: '', nmap_script_args: '',
      exclude_ports: [], exclude_subdomains: false, enable_network_enum: false,
    },
  },
  email_security: {
    enabled: true,
    config: { mailbox_verification: true, timeout: 15, max_candidates: 200, delay_ms: 250, http_url: '' },
  },
  screenshot: { enabled: false, config: {} },
  fetch_url: {
    enabled: true,
    config: {
      uses_tools: ['gospider', 'hakrawler', 'waybackurls', 'katana', 'gau'],
      remove_duplicate_endpoints: true,
      duplicate_fields: ['content_length', 'page_title'],
      enable_http_crawl: true,
      gf_patterns: [
        'api-keys', 'command-injection', 'cors', 'crlf', 'debug_logic',
        'email-injection', 'graphql', 'http-smuggling', 'idor', 'img-traversal',
        'interestingEXT', 'interestingparams', 'interestingsubs', 'jsvar', 'jwt',
        'lfi', 'mass-assignment', 'nosqli', 'oauth', 'open-redirect',
        'path-traversal', 'prototype-pollution', 'rce', 'redirect', 'sqli',
        'ssrf', 's3-bucket', 'ssti', 'upload', 'websocket', 'xss', 'xxe'
      ],
      ignore_file_extensions: ['png', 'jpg', 'jpeg', 'gif', 'mp4', 'mpeg', 'mp3'],
      threads: 30,
    },
  },
  web_api_discovery: {
    enabled: false,
    config: {
      uses_tools: ['kiterunner', 'arjun', 'linkfinder', 'paramspider', 'aquatone',
                   'semgrep', 'retire', 'jwt_tool', 'graphql-cop', 'favirecon',
                   'sourcemapper', 'grpcurl', 'julius', 'gqlspection'],
      scan_only_active: true, threads: 30, timeout: 5, kr_wordlist: 'routes-small.kite',
      run_favirecon: true, run_sourcemapper: true, run_grpcurl: true, run_julius: true, run_gqlspection: true,
    },
  },
  param_discovery: { enabled: true, config: { min_confidence: 50 } },
  dir_file_fuzz: {
    enabled: false,
    config: {
      run_ffuf: true, run_dirsearch: false, run_feroxbuster: false,
      auto_calibration: true, enable_http_crawl: true,
      extensions: ['html', 'php', 'git', 'yaml', 'conf', 'cnf', 'config', 'gz', 'env', 'log',
                   'db', 'mysql', 'bak', 'asp', 'aspx', 'txt', 'sql', 'json', 'yml', 'pdf'],
      wordlist_name: 'dicc', rate_limit: 150, threads: 30, timeout: 5,
      max_time: 300, recursive_level: 2, match_http_status: [200, 204],
      follow_redirect: false, stop_on_error: false, max_repeat_by_signature: 10,
    },
  },
  post_crawl_osint: { enabled: false, config: { metagoofil: true, swaggerspy: true } },
  waf_detection: { enabled: false, config: { enable_http_crawl: true, use_shodan: true, use_censys: true } },
  waf_bypass: { enabled: false, config: { use_benchmarking: true, use_nuclei: true } },
  leaks_and_secrets: { enabled: false, config: { gitleaks: true, trufflehog: true, betterleaks: false } },
  vigolium_analysis: { enabled: true, config: { strategy: 'balanced', concurrency: 20, rate_limit: 50, timeout: '10s' } },
  vulnerability_scan: {
    enabled: true,
    config: {
      run_nuclei: true, run_dalfox: false, run_crlfuzz: false, run_s3scanner: true,
      run_acunetix: true, run_wpscan: true, run_wptaint_scan: true, run_smugglex: true,
      run_second_order: true, run_nuclei_dast: true, run_vigolium: true,
      run_semgrep: true, run_react2shell: true, run_post_scan_processing: true,
      concurrency: 50, rate_limit: 150, retries: 1,
      intensity: 'normal', fetch_gpt_report: true, enable_http_crawl: true,
      wpscan_enumeration: 'vp,vt,u', wpscan_detection_mode: 'mixed',
      acunetix: { ...DEFAULT_ACUNETIX_CONFIG },
      nuclei: {
        use_nuclei_config: false, auto_update_templates: true,
        severities: ['unknown', 'info', 'low', 'medium', 'high', 'critical'], tags: [], templates: [], custom_templates: [],
        max_templates_per_batch: 100,
      },
      dalfox: DEFAULT_DALFOX_CONFIG,
      s3scanner: { threads: 0, providers: [...S3SCANNER_DEFAULT_PROVIDERS] },
      cpanel_scanner: { run_cpanel2shell: true, cpanel_user_wordlist: CPANEL_DEFAULT_USER_WORDLIST, proxy_type: 'rotating' },
      vigolium: { strategy: 'balanced', concurrency: 50, rate_limit: 100, timeout: '300s', run_phase_a: true, run_phase_b: true, scope_origin: 'balanced', skip_spidering: false },
    },
  },
  // On by default like the backend: a missing section runs APME.
  attack_path_modeling: { enabled: true, config: { top_n: 5 } },
  tier_7: { enabled: true, config: { high_noise_modules: ['sourcemap-detect', 'cookie-security-detect'] } },
  // Code Scan runs the audit unless run_vigolium_audit is false.
  vigolium_audit: { enabled: true, config: { intensity: 'balanced', use_ai: false, timeout: 3600 } },
};
