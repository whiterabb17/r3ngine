import { useState, useCallback, useEffect } from 'react';
import { dump as yamlDump, load as yamlLoad } from 'js-yaml';
import type { DumpOptions } from 'js-yaml';
import type {
  EngineConfig, SectionKey, GlobalConfig,
} from '../types/engineConfig';
import { DEFAULT_ENGINE_CONFIG } from '../types/engineConfig';

// ─── Serialiser ──────────────────────────────────────────────────────────────

function serialiseConfigToYaml(config: EngineConfig): string {
  const out: Record<string, unknown> = {};

  // Global fields — top level, no wrapper key
  const g = config.global;
  if (g.custom_headers.length > 0) out.custom_headers = g.custom_headers;
  if (!g.enable_http_crawl) out.enable_http_crawl = false; // only write when non-default
  out.threads = g.threads;
  out.timeout = g.timeout;
  out.rate_limit = g.rate_limit;
  out.retries = g.retries;
  if (g.intensity !== 'normal') out.intensity = g.intensity;

  // Helper: write a section if enabled
  function writeSection(key: string, data: Record<string, unknown>) {
    out[key] = data;
  }

  // ── Tier 1 ──────────────────────────────────────────────────────────────
  if (config.subdomain_discovery.enabled) {
    const c = config.subdomain_discovery.config;
    const s: Record<string, unknown> = { uses_tools: c.uses_tools, threads: c.threads, timeout: c.timeout, enable_http_crawl: c.enable_http_crawl, bbot: c.bbot };
    if (c.use_subfinder_config) s.use_subfinder_config = true;
    if (c.use_amass_config) s.use_amass_config = true;
    if (c.amass_wordlist) s.amass_wordlist = c.amass_wordlist;
    writeSection('subdomain_discovery', s);
  }

  if (config.dns_security.enabled) writeSection('dns_security', {});

  if (config.osint.enabled) {
    const c = config.osint.config;
    writeSection('osint', {
      discover: c.discover,
      dorks: c.dorks,
      ...(c.custom_dorks.length > 0 ? { custom_dorks: c.custom_dorks } : {}),
      intensity: c.intensity,
      documents_limit: c.documents_limit,
    });
  }

  if (config.spiderfoot_scan.enabled) {
    const c = config.spiderfoot_scan.config;
    writeSection('spiderfoot_scan', { modules: c.modules, intensity: c.intensity, threads: c.threads });
  }

  if (config.vigolium_harvest.enabled) {
    const c = config.vigolium_harvest.config;
    writeSection('vigolium_harvest', { run_vigolium_harvest: true, strategy: c.strategy, concurrency: c.concurrency, rate_limit: c.rate_limit, timeout: c.timeout });
  }

  if (config.vigolium_discovery.enabled) {
    const c = config.vigolium_discovery.config;
    writeSection('vigolium_discovery', { run_vigolium_discovery: true, strategy: c.strategy, concurrency: c.concurrency, rate_limit: c.rate_limit, timeout: c.timeout });
  }

  if (config.firewall_vpn_scan.enabled) {
    const c = config.firewall_vpn_scan.config;
    writeSection('firewall_vpn_scan', { run_ike_scan: c.run_ike_scan, run_sslscan: c.run_sslscan, ports: c.ports });
  }

  // ── Tier 2 ──────────────────────────────────────────────────────────────
  if (config.http_crawl.enabled) {
    const c = config.http_crawl.config;
    writeSection('http_crawl', { threads: c.threads, follow_redirect: c.follow_redirect });
  }

  if (config.port_scan.enabled) {
    const c = config.port_scan.config;
    const s: Record<string, unknown> = {
      ports: c.ports, rate_limit: c.rate_limit, threads: c.threads, timeout: c.timeout,
      passive: c.passive, enable_http_crawl: c.enable_http_crawl,
    };
    if (c.enable_nmap) {
      s.enable_nmap = true;
      if (c.nmap_cmd) s.nmap_cmd = c.nmap_cmd;
      if (c.nmap_script) s.nmap_script = c.nmap_script;
      if (c.nmap_script_args) s.nmap_script_args = c.nmap_script_args;
    }
    if (c.exclude_ports.length > 0) s.exclude_ports = c.exclude_ports;
    if (c.exclude_subdomains) s.exclude_subdomains = true;
    writeSection('port_scan', s);
  }

  if (config.screenshot.enabled) {
    const c = config.screenshot.config;
    writeSection('screenshot', { intensity: c.intensity, timeout: c.timeout, threads: c.threads, enable_http_crawl: c.enable_http_crawl });
  }

  // ── Tier 3+4 ────────────────────────────────────────────────────────────
  if (config.fetch_url.enabled) {
    const c = config.fetch_url.config;
    writeSection('fetch_url', {
      uses_tools: c.uses_tools, remove_duplicate_endpoints: c.remove_duplicate_endpoints,
      duplicate_fields: c.duplicate_fields, enable_http_crawl: c.enable_http_crawl,
      gf_patterns: c.gf_patterns, ignore_file_extensions: c.ignore_file_extensions, threads: c.threads,
    });
  }

  if (config.web_api_discovery.enabled) {
    const c = config.web_api_discovery.config;
    writeSection('web_api_discovery', {
      uses_tools: c.uses_tools, scan_only_active: c.scan_only_active,
      threads: c.threads, timeout: c.timeout, kr_wordlist: c.kr_wordlist,
      run_favirecon: c.run_favirecon, run_sourcemapper: c.run_sourcemapper,
      run_grpcurl: c.run_grpcurl, run_julius: c.run_julius, run_gqlspection: c.run_gqlspection,
    });
  }

  if (config.param_discovery.enabled) {
    writeSection('param_discovery', { enabled: true, min_confidence: config.param_discovery.config.min_confidence });
  }

  if (config.dir_file_fuzz.enabled) {
    const c = config.dir_file_fuzz.config;
    writeSection('dir_file_fuzz', {
      run_dirsearch: c.run_dirsearch, run_feroxbuster: c.run_feroxbuster,
      auto_calibration: c.auto_calibration, enable_http_crawl: c.enable_http_crawl,
      extensions: c.extensions, wordlist_name: c.wordlist_name,
      rate_limit: c.rate_limit, threads: c.threads, timeout: c.timeout,
      max_time: c.max_time, recursive_level: c.recursive_level,
      match_http_status: c.match_http_status, follow_redirect: c.follow_redirect,
      stop_on_error: c.stop_on_error, max_repeat_by_signature: c.max_repeat_by_signature,
    });
  }

  // ── Tier 5 ──────────────────────────────────────────────────────────────
  if (config.waf_detection.enabled) {
    const c = config.waf_detection.config;
    writeSection('waf_detection', { enable_http_crawl: c.enable_http_crawl, use_shodan: c.use_shodan, use_censys: c.use_censys });
  }

  if (config.waf_bypass.enabled) {
    const c = config.waf_bypass.config;
    writeSection('waf_bypass', { enabled: true, use_benchmarking: c.use_benchmarking, use_nuclei: c.use_nuclei, timeout: c.timeout, threads: c.threads });
  }

  if (config.leaks_and_secrets.enabled) {
    const c = config.leaks_and_secrets.config;
    writeSection('leaks_and_secrets', { gitleaks: c.gitleaks, trufflehog: c.trufflehog, leaklookup: c.leaklookup });
  }

  if (config.vigolium_analysis.enabled) {
    const c = config.vigolium_analysis.config;
    writeSection('vigolium_analysis', { run_vigolium_analysis: true, strategy: c.strategy, concurrency: c.concurrency, rate_limit: c.rate_limit, timeout: c.timeout });
  }

  // ── Tier 6 ──────────────────────────────────────────────────────────────
  if (config.vulnerability_scan.enabled) {
    const c = config.vulnerability_scan.config;
    const s: Record<string, unknown> = {
      run_nuclei: c.run_nuclei, run_dalfox: c.run_dalfox, run_crlfuzz: c.run_crlfuzz,
      run_s3scanner: c.run_s3scanner, run_acunetix: c.run_acunetix, run_wpscan: c.run_wpscan,
      run_wptaint_scan: c.run_wptaint_scan, run_smugglex: c.run_smugglex,
      run_second_order: c.run_second_order, run_nuclei_dast: c.run_nuclei_dast,
      run_vigolium: c.run_vigolium,
      concurrency: c.concurrency, rate_limit: c.rate_limit, retries: c.retries,
      timeout: c.timeout, intensity: c.intensity, fetch_gpt_report: c.fetch_gpt_report,
      enable_http_crawl: c.enable_http_crawl,
    };
    if (c.run_wpscan) {
      s.wpscan_enumeration = c.wpscan_enumeration;
      s.wpscan_detection_mode = c.wpscan_detection_mode;
    }
    if (c.run_nuclei) s.nuclei = { use_nuclei_config: c.nuclei.use_nuclei_config, severities: c.nuclei.severities, ...(c.nuclei.tags.length ? { tags: c.nuclei.tags } : {}), ...(c.nuclei.templates.length ? { templates: c.nuclei.templates } : {}), ...(c.nuclei.custom_templates.length ? { custom_templates: c.nuclei.custom_templates } : {}) };
    s.cpanel_scanner = { run_cpanel2shell: c.cpanel_scanner.run_cpanel2shell, cpanel_user_wordlist: c.cpanel_scanner.cpanel_user_wordlist, proxy_type: c.cpanel_scanner.proxy_type };
    if (c.run_vigolium) s.vigolium = { strategy: c.vigolium.strategy, concurrency: c.vigolium.concurrency, rate_limit: c.vigolium.rate_limit, timeout: c.vigolium.timeout };
    writeSection('vulnerability_scan', s);
  }

  // ── Tier 7 ──────────────────────────────────────────────────────────────
  if (config.attack_path_modeling.enabled) {
    writeSection('attack_path_modeling', { enabled: true, top_n: config.attack_path_modeling.config.top_n });
  }

  if (config.vigolium_audit.enabled) {
    const c = config.vigolium_audit.config;
    writeSection('vigolium_audit', { run_vigolium_audit: true, intensity: c.intensity, use_ai: c.use_ai, timeout: c.timeout });
  }

  return yamlDump(out, { lineWidth: 120, quotingType: "'", forceQuotes: false } as DumpOptions);
}

// ─── Parser ──────────────────────────────────────────────────────────────────

function parseYamlToConfig(yamlStr: string): EngineConfig {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const raw: any = yamlLoad(yamlStr) ?? {};
  const def = DEFAULT_ENGINE_CONFIG;

  // Merge osint.leaks_and_secrets into top-level leaks_and_secrets
  const osintLeaks = raw.osint?.leaks_and_secrets ?? {};
  const topLeaks = raw.leaks_and_secrets ?? {};
  const mergedLeaks = { ...osintLeaks, ...topLeaks };

  const g = def.global;
  const global: EngineConfig['global'] = {
    threads: raw.threads ?? g.threads,
    timeout: raw.timeout ?? g.timeout,
    rate_limit: raw.rate_limit ?? g.rate_limit,
    retries: raw.retries ?? g.retries,
    intensity: raw.intensity ?? g.intensity,
    custom_headers: raw.custom_headers ?? [],
    enable_http_crawl: raw.enable_http_crawl ?? g.enable_http_crawl,
  };

  function section<T>(key: string, map: (r: Record<string, unknown>) => T, defConfig: T): { enabled: boolean; config: T } {
    const present = key in raw && raw[key] !== null;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const r: Record<string, unknown> = present ? (raw[key] as any) : {};
    return { enabled: present, config: present ? map(r) : defConfig };
  }

  return {
    global,

    subdomain_discovery: section('subdomain_discovery', (r) => ({
      uses_tools: (r.uses_tools as string[]) ?? def.subdomain_discovery.config.uses_tools,
      threads: (r.threads as number) ?? def.subdomain_discovery.config.threads,
      timeout: (r.timeout as number) ?? def.subdomain_discovery.config.timeout,
      enable_http_crawl: (r.enable_http_crawl as boolean) ?? true,
      bbot: (r.bbot as boolean) ?? false,
      use_subfinder_config: (r.use_subfinder_config as boolean) ?? false,
      use_amass_config: (r.use_amass_config as boolean) ?? false,
      amass_wordlist: (r.amass_wordlist as string) ?? '',
    }), def.subdomain_discovery.config) as EngineConfig['subdomain_discovery'],

    dns_security: { enabled: 'dns_security' in raw, config: {} },

    osint: section('osint', (r) => ({
      discover: (r.discover as string[]) ?? def.osint.config.discover,
      dorks: (r.dorks as string[]) ?? def.osint.config.dorks,
      custom_dorks: (r.custom_dorks as string[]) ?? [],
      intensity: (r.intensity as 'normal' | 'aggressive' | 'light') ?? 'normal',
      documents_limit: (r.documents_limit as number) ?? 50,
    }), def.osint.config) as EngineConfig['osint'],

    spiderfoot_scan: section('spiderfoot_scan', (r) => ({
      modules: (r.modules as string) ?? 'all',
      intensity: (r.intensity as 'normal' | 'aggressive' | 'light') ?? 'normal',
      threads: (r.threads as number) ?? 10,
    }), def.spiderfoot_scan.config) as EngineConfig['spiderfoot_scan'],

    vigolium_harvest: section('vigolium_harvest', (r) => ({
      strategy: (r.strategy as 'fast' | 'balanced' | 'thorough') ?? 'balanced',
      concurrency: (r.concurrency as number) ?? 20,
      rate_limit: (r.rate_limit as number) ?? 50,
      timeout: (r.timeout as string) ?? '10s',
    }), def.vigolium_harvest.config) as EngineConfig['vigolium_harvest'],

    vigolium_discovery: section('vigolium_discovery', (r) => ({
      strategy: (r.strategy as 'fast' | 'balanced' | 'thorough') ?? 'balanced',
      concurrency: (r.concurrency as number) ?? 20,
      rate_limit: (r.rate_limit as number) ?? 50,
      timeout: (r.timeout as string) ?? '10s',
    }), def.vigolium_discovery.config) as EngineConfig['vigolium_discovery'],

    firewall_vpn_scan: section('firewall_vpn_scan', (r) => ({
      run_ike_scan: (r.run_ike_scan as boolean) ?? true,
      run_sslscan: (r.run_sslscan as boolean) ?? true,
      ports: (r.ports as number[]) ?? [443, 4444, 8443, 10443, 5443],
    }), def.firewall_vpn_scan.config) as EngineConfig['firewall_vpn_scan'],

    http_crawl: section('http_crawl', (r) => ({
      threads: (r.threads as number) ?? 30,
      follow_redirect: (r.follow_redirect as boolean) ?? true,
    }), def.http_crawl.config) as EngineConfig['http_crawl'],

    port_scan: section('port_scan', (r) => ({
      ports: (r.ports as string[]) ?? ['top-100'],
      rate_limit: (r.rate_limit as number) ?? 150,
      threads: (r.threads as number) ?? 30,
      timeout: (r.timeout as number) ?? 5,
      passive: (r.passive as boolean) ?? false,
      enable_http_crawl: (r.enable_http_crawl as boolean) ?? true,
      enable_nmap: (r.enable_nmap as boolean) ?? false,
      nmap_cmd: (r.nmap_cmd as string) ?? '',
      nmap_script: (r.nmap_script as string) ?? '',
      nmap_script_args: (r.nmap_script_args as string) ?? '',
      exclude_ports: (r.exclude_ports as string[]) ?? [],
      exclude_subdomains: (r.exclude_subdomains as boolean) ?? false,
    }), def.port_scan.config) as EngineConfig['port_scan'],

    screenshot: section('screenshot', (r) => ({
      intensity: (r.intensity as 'normal' | 'aggressive' | 'light') ?? 'normal',
      timeout: (r.timeout as number) ?? 10,
      threads: (r.threads as number) ?? 40,
      enable_http_crawl: (r.enable_http_crawl as boolean) ?? true,
    }), def.screenshot.config) as EngineConfig['screenshot'],

    fetch_url: section('fetch_url', (r) => ({
      uses_tools: (r.uses_tools as string[]) ?? def.fetch_url.config.uses_tools,
      remove_duplicate_endpoints: (r.remove_duplicate_endpoints as boolean) ?? true,
      duplicate_fields: (r.duplicate_fields as string[]) ?? ['content_length', 'page_title'],
      enable_http_crawl: (r.enable_http_crawl as boolean) ?? true,
      gf_patterns: (r.gf_patterns as string[]) ?? def.fetch_url.config.gf_patterns,
      ignore_file_extensions: (r.ignore_file_extensions as string[]) ?? def.fetch_url.config.ignore_file_extensions,
      threads: (r.threads as number) ?? 30,
    }), def.fetch_url.config) as EngineConfig['fetch_url'],

    web_api_discovery: section('web_api_discovery', (r) => ({
      uses_tools: (r.uses_tools as string[]) ?? def.web_api_discovery.config.uses_tools,
      scan_only_active: (r.scan_only_active as boolean) ?? true,
      threads: (r.threads as number) ?? 30,
      timeout: (r.timeout as number) ?? 5,
      kr_wordlist: (r.kr_wordlist as string) ?? 'routes-small.kite',
      run_favirecon: (r.run_favirecon as boolean) ?? true,
      run_sourcemapper: (r.run_sourcemapper as boolean) ?? true,
      run_grpcurl: (r.run_grpcurl as boolean) ?? true,
      run_julius: (r.run_julius as boolean) ?? true,
      run_gqlspection: (r.run_gqlspection as boolean) ?? true,
    }), def.web_api_discovery.config) as EngineConfig['web_api_discovery'],

    param_discovery: section('param_discovery', (r) => ({
      min_confidence: (r.min_confidence as number) ?? 50,
    }), def.param_discovery.config) as EngineConfig['param_discovery'],

    dir_file_fuzz: section('dir_file_fuzz', (r) => ({
      run_dirsearch: (r.run_dirsearch as boolean) ?? true,
      run_feroxbuster: (r.run_feroxbuster as boolean) ?? false,
      auto_calibration: (r.auto_calibration as boolean) ?? true,
      enable_http_crawl: (r.enable_http_crawl as boolean) ?? true,
      extensions: (r.extensions as string[]) ?? def.dir_file_fuzz.config.extensions,
      wordlist_name: (r.wordlist_name as string) ?? 'dicc',
      rate_limit: (r.rate_limit as number) ?? 150,
      threads: (r.threads as number) ?? 30,
      timeout: (r.timeout as number) ?? 5,
      max_time: (r.max_time as number) ?? 300,
      recursive_level: (r.recursive_level as number) ?? 2,
      match_http_status: (r.match_http_status as number[]) ?? [200, 204],
      follow_redirect: (r.follow_redirect as boolean) ?? false,
      stop_on_error: (r.stop_on_error as boolean) ?? false,
      max_repeat_by_signature: (r.max_repeat_by_signature as number) ?? 10,
    }), def.dir_file_fuzz.config) as EngineConfig['dir_file_fuzz'],

    waf_detection: section('waf_detection', (r) => ({
      enable_http_crawl: (r.enable_http_crawl as boolean) ?? true,
      use_shodan: (r.use_shodan as boolean) ?? true,
      use_censys: (r.use_censys as boolean) ?? true,
    }), def.waf_detection.config) as EngineConfig['waf_detection'],

    waf_bypass: section('waf_bypass', (r) => ({
      use_benchmarking: (r.use_benchmarking as boolean) ?? true,
      use_nuclei: (r.use_nuclei as boolean) ?? true,
      timeout: (r.timeout as number) ?? 10,
      threads: (r.threads as number) ?? 10,
    }), def.waf_bypass.config) as EngineConfig['waf_bypass'],

    leaks_and_secrets: {
      enabled: Object.keys(mergedLeaks).length > 0 || 'leaks_and_secrets' in raw,
      config: {
        gitleaks: (mergedLeaks.gitleaks as boolean) ?? true,
        trufflehog: (mergedLeaks.trufflehog as boolean) ?? true,
        leaklookup: (mergedLeaks.leaklookup as boolean) ?? true,
      },
    },

    vigolium_analysis: section('vigolium_analysis', (r) => ({
      strategy: (r.strategy as 'fast' | 'balanced' | 'thorough') ?? 'balanced',
      concurrency: (r.concurrency as number) ?? 20,
      rate_limit: (r.rate_limit as number) ?? 50,
      timeout: (r.timeout as string) ?? '10s',
    }), def.vigolium_analysis.config) as EngineConfig['vigolium_analysis'],

    vulnerability_scan: section('vulnerability_scan', (r) => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const n: any = r.nuclei ?? {};
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const cp: any = r.cpanel_scanner ?? {};
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const vig: any = r.vigolium ?? {};
      return {
        run_nuclei: (r.run_nuclei as boolean) ?? true,
        run_dalfox: (r.run_dalfox as boolean) ?? false,
        run_crlfuzz: (r.run_crlfuzz as boolean) ?? false,
        run_s3scanner: (r.run_s3scanner as boolean) ?? true,
        run_acunetix: (r.run_acunetix as boolean) ?? true,
        run_wpscan: (r.run_wpscan as boolean) ?? true,
        run_wptaint_scan: (r.run_wptaint_scan as boolean) ?? true,
        run_smugglex: (r.run_smugglex as boolean) ?? true,
        run_second_order: (r.run_second_order as boolean) ?? true,
        run_nuclei_dast: (r.run_nuclei_dast as boolean) ?? true,
        run_vigolium: (r.run_vigolium as boolean) ?? true,
        concurrency: (r.concurrency as number) ?? 50,
        rate_limit: (r.rate_limit as number) ?? 150,
        retries: (r.retries as number) ?? 1,
        timeout: (r.timeout as number) ?? 5,
        intensity: (r.intensity as 'normal' | 'aggressive' | 'light') ?? 'normal',
        fetch_gpt_report: (r.fetch_gpt_report as boolean) ?? true,
        enable_http_crawl: (r.enable_http_crawl as boolean) ?? true,
        wpscan_enumeration: (r.wpscan_enumeration as string) ?? 'vp,vt,u',
        wpscan_detection_mode: (r.wpscan_detection_mode as 'mixed' | 'passive' | 'aggressive') ?? 'mixed',
        nuclei: {
          use_nuclei_config: n.use_nuclei_config ?? false,
          severities: n.severities ?? ['unknown', 'info', 'low', 'medium', 'high', 'critical'],
          tags: n.tags ?? [],
          templates: n.templates ?? [],
          custom_templates: n.custom_templates ?? [],
        },
        cpanel_scanner: {
          run_cpanel2shell: cp.run_cpanel2shell ?? true,
          cpanel_user_wordlist: cp.cpanel_user_wordlist ?? '/usr/src/app/wordlist/cpanel_users.txt',
          proxy_type: cp.proxy_type ?? 'rotating',
        },
        vigolium: {
          strategy: vig.strategy ?? 'balanced',
          concurrency: vig.concurrency ?? 50,
          rate_limit: vig.rate_limit ?? 100,
          timeout: vig.timeout ?? '15s',
        },
      };
    }, def.vulnerability_scan.config) as EngineConfig['vulnerability_scan'],

    attack_path_modeling: section('attack_path_modeling', (r) => ({
      top_n: (r.top_n as number) ?? 5,
    }), def.attack_path_modeling.config) as EngineConfig['attack_path_modeling'],

    vigolium_audit: section('vigolium_audit', (r) => ({
      intensity: (r.intensity as 'quick' | 'balanced' | 'deep') ?? 'balanced',
      use_ai: (r.use_ai as boolean) ?? false,
      timeout: (r.timeout as number) ?? 3600,
    }), def.vigolium_audit.config) as EngineConfig['vigolium_audit'],
  };
}

// ─── Hook ────────────────────────────────────────────────────────────────────

export interface UseEngineConfigReturn {
  config: EngineConfig;
  yaml: string;
  yamlError: string | null;
  updateSection: <K extends SectionKey>(
    section: K,
    patch: Partial<EngineConfig[K]['config']>
  ) => void;
  toggleSection: (section: SectionKey, enabled: boolean) => void;
  updateGlobal: (patch: Partial<GlobalConfig>) => void;
  setYaml: (raw: string) => void;
  loadTemplate: (yamlStr: string) => void;
}

export function useEngineConfig(initialYaml?: string): UseEngineConfigReturn {
  const [config, setConfig] = useState<EngineConfig>(() => {
    if (initialYaml) {
      try { return parseYamlToConfig(initialYaml); } catch { /* fall through */ }
    }
    return DEFAULT_ENGINE_CONFIG;
  });
  const [yaml, setYamlStr] = useState<string>(() => initialYaml ?? serialiseConfigToYaml(DEFAULT_ENGINE_CONFIG));
  const [yamlError, setYamlError] = useState<string | null>(null);

  // Re-parse when initialYaml changes (edit mode load)
  useEffect(() => {
    if (!initialYaml) return;
    try {
      const parsed = parseYamlToConfig(initialYaml);
      setConfig(parsed);
      setYamlStr(serialiseConfigToYaml(parsed));
      setYamlError(null);
    } catch (e) {
      setYamlError(e instanceof Error ? e.message : String(e));
    }
  }, [initialYaml]);

  // Keep yaml in sync when config changes
  const updateConfigAndYaml = useCallback((next: EngineConfig) => {
    setConfig(next);
    setYamlStr(serialiseConfigToYaml(next));
    setYamlError(null);
  }, []);

  const updateSection = useCallback(<K extends SectionKey>(
    section: K,
    patch: Partial<EngineConfig[K]['config']>
  ) => {
    setConfig((prev) => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const prevSection = prev[section] as any;
      const next: EngineConfig = {
        ...prev,
        [section]: {
          ...prevSection,
          config: { ...prevSection.config, ...patch },
        },
      };
      setYamlStr(serialiseConfigToYaml(next));
      setYamlError(null);
      return next;
    });
  }, []);

  const toggleSection = useCallback((section: SectionKey, enabled: boolean) => {
    setConfig((prev) => {
      const next: EngineConfig = { ...prev, [section]: { ...prev[section], enabled } };
      setYamlStr(serialiseConfigToYaml(next));
      setYamlError(null);
      return next;
    });
  }, []);

  const updateGlobal = useCallback((patch: Partial<GlobalConfig>) => {
    setConfig((prev) => {
      const next: EngineConfig = { ...prev, global: { ...prev.global, ...patch } };
      setYamlStr(serialiseConfigToYaml(next));
      setYamlError(null);
      return next;
    });
  }, []);

  const setYaml = useCallback((raw: string) => {
    setYamlStr(raw);
    try {
      const parsed = parseYamlToConfig(raw);
      setConfig(parsed);
      setYamlError(null);
    } catch (e) {
      setYamlError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  const loadTemplate = useCallback((yamlStr: string) => {
    try {
      const parsed = parseYamlToConfig(yamlStr);
      updateConfigAndYaml(parsed);
    } catch (e) {
      setYamlError(e instanceof Error ? e.message : String(e));
    }
  }, [updateConfigAndYaml]);

  return { config, yaml, yamlError, updateSection, toggleSection, updateGlobal, setYaml, loadTemplate };
}
