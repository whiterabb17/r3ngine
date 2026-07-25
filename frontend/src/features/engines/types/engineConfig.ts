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
  bbot: boolean;
  use_subfinder_config: boolean;
  use_amass_config: boolean;
  amass_wordlist: string;
}

// DnsSecurity has no user-facing config fields; presence in YAML = enabled
export type DnsSecurityConfig = Record<string, never>;

export interface OsintConfig {
  discover: string[];
  dorks: string[];
  custom_dorks: string[];
  intensity: 'normal' | 'aggressive' | 'light';
  documents_limit: number;
  whatbreach: boolean;
  whatbreach_download_databases: boolean;
  credspy: boolean;
}

export interface SpiderfootConfig {
  modules: string;
  intensity: 'normal' | 'aggressive' | 'light';
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
}

export interface ScreenshotConfig {
  intensity: 'normal' | 'aggressive' | 'light';
  timeout: number;
  threads: number;
  enable_http_crawl: boolean;
}

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

// ─── Tier 5: Analysis ────────────────────────────────────────────────────────

export interface WafDetectionConfig {
  enable_http_crawl: boolean;
  use_shodan: boolean;
  use_censys: boolean;
}

export interface WafBypassConfig {
  use_benchmarking: boolean;
  use_nuclei: boolean;
  timeout: number;
  threads: number;
}

export interface LeaksSecretsConfig {
  gitleaks: boolean;
  trufflehog: boolean;
  leaklookup: boolean;
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
  severities: string[];
  tags: string[];
  templates: string[];
  custom_templates: string[];
}

export interface CpanelScannerConfig {
  run_cpanel2shell: boolean;
  cpanel_user_wordlist: string;
  proxy_type: 'rotating' | 'static';
}

export interface VigoliumVulnConfig {
  strategy: 'fast' | 'balanced' | 'thorough';
  concurrency: number;
  rate_limit: number;
  timeout: string;
  run_phase_a: boolean;  // Phase A: spidering + discovery
  run_phase_b: boolean;  // Phase B: known-issue-scan + dynamic-assessment
  scope_origin: 'all' | 'relaxed' | 'balanced' | 'strict';
  skip_spidering: boolean;
}

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
  concurrency: number;
  rate_limit: number;
  retries: number;
  timeout: number;
  intensity: 'normal' | 'aggressive' | 'light';
  fetch_gpt_report: boolean;
  enable_http_crawl: boolean;
  wpscan_enumeration: string;
  wpscan_detection_mode: 'mixed' | 'passive' | 'aggressive';
  nuclei: NucleiConfig;
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
  // Tier 2
  http_crawl: SectionState<HttpCrawlConfig>;
  port_scan: SectionState<PortScanConfig>;
  screenshot: SectionState<ScreenshotConfig>;
  // Tier 3+4
  fetch_url: SectionState<FetchUrlConfig>;
  web_api_discovery: SectionState<WebApiDiscoveryConfig>;
  param_discovery: SectionState<ParamDiscoveryConfig>;
  dir_file_fuzz: SectionState<DirFileFuzzConfig>;
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

export const DEFAULT_ENGINE_CONFIG: EngineConfig = {
  global: DEFAULT_GLOBAL,
  subdomain_discovery: {
    enabled: true,
    config: {
      uses_tools: ['subfinder', 'ctfr', 'sublist3r', 'tlsx', 'oneforall', 'netlas', 'baddns'],
      threads: 30, timeout: 5, enable_http_crawl: true,
      bbot: false, use_subfinder_config: false, use_amass_config: false, amass_wordlist: '',
    },
  },
  dns_security: { enabled: false, config: {} },
  osint: {
    enabled: false,
    config: {
      discover: ['emails', 'metainfo', 'employees'],
      dorks: ['login_pages', 'admin_panels', 'dashboard_pages', 'stackoverflow',
              'social_media', 'project_management', 'code_sharing', 'config_files',
              'jenkins', 'wordpress_files', 'php_error', 'exposed_documents', 'db_files', 'git_exposed'],
      custom_dorks: [],
      intensity: 'normal',
      documents_limit: 50,
      whatbreach: true,
      whatbreach_download_databases: false,
      credspy: false,
    },
  },
  spiderfoot_scan: { enabled: false, config: { modules: 'all', intensity: 'normal', threads: 10 } },
  vigolium_harvest: { enabled: true, config: { strategy: 'balanced', concurrency: 20, rate_limit: 50, timeout: '10s' } },
  vigolium_discovery: { enabled: true, config: { strategy: 'balanced', concurrency: 20, rate_limit: 50, timeout: '10s' } },
  firewall_vpn_scan: { enabled: false, config: { run_ike_scan: true, run_sslscan: true, ports: [443, 4444, 8443, 10443, 5443] } },
  http_crawl: { enabled: true, config: { threads: 30, follow_redirect: true } },
  port_scan: {
    enabled: true,
    config: {
      ports: ['top-100'], rate_limit: 150, threads: 30, timeout: 5,
      passive: false, enable_http_crawl: true, enable_nmap: false,
      nmap_cmd: '', nmap_script: '', nmap_script_args: '',
      exclude_ports: [], exclude_subdomains: false,
    },
  },
  screenshot: { enabled: false, config: { intensity: 'normal', timeout: 10, threads: 40, enable_http_crawl: true } },
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
      run_dirsearch: true, run_feroxbuster: false, auto_calibration: true, enable_http_crawl: true,
      extensions: ['html', 'php', 'git', 'yaml', 'conf', 'cnf', 'config', 'gz', 'env', 'log',
                   'db', 'mysql', 'bak', 'asp', 'aspx', 'txt', 'sql', 'json', 'yml', 'pdf'],
      wordlist_name: 'dicc', rate_limit: 150, threads: 30, timeout: 5,
      max_time: 300, recursive_level: 2, match_http_status: [200, 204],
      follow_redirect: false, stop_on_error: false, max_repeat_by_signature: 10,
    },
  },
  waf_detection: { enabled: false, config: { enable_http_crawl: true, use_shodan: true, use_censys: true } },
  waf_bypass: { enabled: false, config: { use_benchmarking: true, use_nuclei: true, timeout: 10, threads: 10 } },
  leaks_and_secrets: { enabled: false, config: { gitleaks: true, trufflehog: true, leaklookup: true } },
  vigolium_analysis: { enabled: true, config: { strategy: 'balanced', concurrency: 20, rate_limit: 50, timeout: '10s' } },
  vulnerability_scan: {
    enabled: true,
    config: {
      run_nuclei: true, run_dalfox: false, run_crlfuzz: false, run_s3scanner: true,
      run_acunetix: true, run_wpscan: true, run_wptaint_scan: true, run_smugglex: true,
      run_second_order: true, run_nuclei_dast: true, run_vigolium: true,
      concurrency: 50, rate_limit: 150, retries: 1, timeout: 5,
      intensity: 'normal', fetch_gpt_report: true, enable_http_crawl: true,
      wpscan_enumeration: 'vp,vt,u', wpscan_detection_mode: 'mixed',
      nuclei: { use_nuclei_config: false, severities: ['unknown', 'info', 'low', 'medium', 'high', 'critical'], tags: [], templates: [], custom_templates: [] },
      cpanel_scanner: { run_cpanel2shell: true, cpanel_user_wordlist: '/usr/src/app/wordlist/cpanel_users.txt', proxy_type: 'rotating' },
      vigolium: { strategy: 'balanced', concurrency: 50, rate_limit: 100, timeout: '15s', run_phase_a: true, run_phase_b: true, scope_origin: 'balanced', skip_spidering: false },
    },
  },
  attack_path_modeling: { enabled: false, config: { top_n: 5 } },
  tier_7: { enabled: true, config: { high_noise_modules: ['sourcemap-detect', 'cookie-security-detect'] } },
  vigolium_audit: { enabled: false, config: { intensity: 'balanced', use_ai: false, timeout: 3600 } },
};
