import { describe, expect, it } from 'vitest';
import { act, renderHook } from '@testing-library/react';
import { load as yamlLoad } from 'js-yaml';
import { FORM_OWNED_KEYS, serialiseConfigToYaml, useEngineConfig } from '../useEngineConfig';
import type { OwnedKeys } from '../useEngineConfig';
import { DEFAULT_ENGINE_CONFIG } from '../../types/engineConfig';
import type { EngineConfig } from '../../types/engineConfig';

type Mapping = Record<string, unknown>;

function isMapping(node: unknown): node is Mapping {
  return typeof node === 'object' && node !== null && !Array.isArray(node);
}

function loadMapping(yaml: string): Mapping {
  const doc: unknown = yamlLoad(yaml);
  if (!isMapping(doc)) throw new Error('expected a YAML mapping');
  return doc;
}

function mappingAt(root: Mapping, ...path: string[]): Mapping {
  return path.reduce<Mapping>((node, key) => {
    const next = node[key];
    if (!isMapping(next)) throw new Error(`expected a mapping at ${path.join('.')}`);
    return next;
  }, root);
}

const ENGINE_YAML = `
threads: 12
osint:
  leaks_and_secrets:
    gitleaks: false
leaks_and_secrets:
  trufflehog: false
port_scan: true
vulnerability_scan:
  run_nuclei: false
  nuclei:
    tags: [cve]
  acunetix:
    resubmit_after_days: 7
    max_scans_per_run: 10
`;

describe('useEngineConfig YAML parsing', () => {
  it('reads nested mappings and falls back to defaults for missing keys', () => {
    const { result } = renderHook(() => useEngineConfig(ENGINE_YAML));
    const { config } = result.current;

    expect(config.global.threads).toBe(12);
    expect(config.leaks_and_secrets).toEqual({
      enabled: true,
      config: { gitleaks: false, trufflehog: false, betterleaks: false },
    });
    expect(config.vulnerability_scan.config.run_nuclei).toBe(false);
    expect(config.vulnerability_scan.config.nuclei.tags).toEqual(['cve']);
    expect(config.vulnerability_scan.config.nuclei.templates).toEqual([]);
    expect(config.vulnerability_scan.config.acunetix?.resubmit_after_days).toBe(7);
    expect(config.vulnerability_scan.config.acunetix?.submit_live_subdomains).toBe(false);
    expect(config.vulnerability_scan.config.acunetix?.max_scans_per_run).toBe(10);
    expect(config.vulnerability_scan.config.acunetix?.submission_batch_size).toBe(20);
    expect(config.vulnerability_scan.config.acunetix?.submission_batch_pause).toBe(5);
  });

  it('treats a section given as a scalar as enabled with default settings', () => {
    const { result } = renderHook(() => useEngineConfig(ENGINE_YAML));
    expect(result.current.config.port_scan.enabled).toBe(true);
    expect(result.current.config.port_scan.config.ports).toEqual(['top-100']);
  });

  it('reports a YAML document that is not a mapping and keeps the last config', () => {
    const { result } = renderHook(() => useEngineConfig(ENGINE_YAML));
    act(() => result.current.setYaml('just a string'));

    expect(result.current.yamlError).toBe('Engine configuration must be a YAML mapping');
    expect(result.current.config.global.threads).toBe(12);
  });

  it('merges a section patch into that section only', () => {
    const { result } = renderHook(() => useEngineConfig(ENGINE_YAML));
    act(() => result.current.updateSection('port_scan', { rate_limit: 10 }));

    expect(result.current.config.port_scan.config.rate_limit).toBe(10);
    expect(result.current.config.port_scan.config.ports).toEqual(['top-100']);
    expect(result.current.yaml).toContain('rate_limit: 10');
  });
});

describe('useEngineConfig web_api_discovery checkboxes', () => {
  it('mirrors uses_tools when a run_<tool> flag is absent', () => {
    const yaml = `
web_api_discovery:
  uses_tools: [linkfinder, favirecon]
  run_julius: true
`;
    const { result } = renderHook(() => useEngineConfig(yaml));
    const { config } = result.current.config.web_api_discovery;

    expect(config.run_favirecon).toBe(true);
    expect(config.run_sourcemapper).toBe(false);
    expect(config.run_julius).toBe(true);
  });
});

describe('useEngineConfig dir_file_fuzz tool switches', () => {
  it('turns ffuf on when run_ffuf is absent, like the backend', () => {
    const { result } = renderHook(() => useEngineConfig('dir_file_fuzz:\n  threads: 10\n'));
    expect(result.current.config.dir_file_fuzz.config.run_ffuf).toBe(true);
  });

  it('round-trips run_ffuf: false through the YAML', () => {
    const { result } = renderHook(() => useEngineConfig('dir_file_fuzz:\n  run_ffuf: false\n  run_dirsearch: true\n'));
    expect(result.current.config.dir_file_fuzz.config.run_ffuf).toBe(false);

    const section = mappingAt(loadMapping(serialiseConfigToYaml(result.current.config)), 'dir_file_fuzz');
    expect(section.run_ffuf).toBe(false);
    expect(section.run_dirsearch).toBe(true);

    const { result: reparsed } = renderHook(() => useEngineConfig(serialiseConfigToYaml(result.current.config)));
    expect(reparsed.current.config.dir_file_fuzz.config.run_ffuf).toBe(false);
  });

  it('always writes run_ffuf, even at its default', () => {
    const { result } = renderHook(() => useEngineConfig('dir_file_fuzz: {}\n'));
    const section = mappingAt(loadMapping(serialiseConfigToYaml(result.current.config)), 'dir_file_fuzz');
    expect(section.run_ffuf).toBe(true);
  });
});

describe('useEngineConfig secret scanning section', () => {
  it('reads secret_scanning so saving a built-in engine keeps it', () => {
    const yaml = `
secret_scanning:
  trufflehog: true
  gitleaks: false
  betterleaks: true
`;
    const { result } = renderHook(() => useEngineConfig(yaml));
    expect(result.current.config.leaks_and_secrets).toEqual({
      enabled: true,
      config: { gitleaks: false, trufflehog: true, betterleaks: true },
    });
  });

  it('writes the section as secret_scanning, including for older saves', () => {
    const { result } = renderHook(() => useEngineConfig('leaks_and_secrets:\n  gitleaks: false\n'));
    act(() => result.current.updateSection('leaks_and_secrets', { trufflehog: false }));
    const doc = loadMapping(result.current.yaml);

    expect(doc).not.toHaveProperty('leaks_and_secrets');
    expect(mappingAt(doc, 'secret_scanning')).toEqual({ gitleaks: false, trufflehog: false, betterleaks: false });
  });

  it('keeps breach lookups out of secret_scanning, where nothing reads them', () => {
    const { result } = renderHook(() => useEngineConfig('secret_scanning:\n  gitleaks: true\n  leaklookup: true\n'));
    act(() => result.current.updateSection('leaks_and_secrets', { trufflehog: false }));
    const doc = loadMapping(result.current.yaml);

    expect(mappingAt(doc, 'secret_scanning')).not.toHaveProperty('leaklookup');
    // The old spelling never ran a lookup, so it does not switch the OSINT one on.
    expect(result.current.config.osint.config.leaklookup).toBe(false);
  });
});

describe('useEngineConfig email security section', () => {
  it('treats a missing section as enabled, like the backend', () => {
    const { result } = renderHook(() => useEngineConfig('port_scan: {}\n'));
    expect(result.current.config.email_security).toEqual({
      enabled: true,
      config: { mailbox_verification: true, timeout: 15, max_candidates: 200, delay_ms: 250, http_url: '' },
    });
  });

  it('reads the section switch and the mailbox verification settings', () => {
    const yaml = `
email_security:
  enabled: true
  mailbox_verification:
    enabled: false
    max_candidates: 50
    http_url: https://reacher.example.test
`;
    const { result } = renderHook(() => useEngineConfig(yaml));
    const { enabled, config } = result.current.config.email_security;

    expect(enabled).toBe(true);
    expect(config.mailbox_verification).toBe(false);
    expect(config.max_candidates).toBe(50);
    expect(config.timeout).toBe(15);
    expect(config.http_url).toBe('https://reacher.example.test');
  });

  it('writes an explicit enabled: false when the section is switched off', () => {
    const { result } = renderHook(() => useEngineConfig('port_scan: {}\n'));
    act(() => result.current.toggleSection('email_security', false));

    expect(result.current.yaml).toMatch(/^email_security:\n {2}enabled: false$/m);
  });

  it('keeps mailbox verification off after an edit mode reload', () => {
    const { result } = renderHook(() => useEngineConfig('port_scan: {}\n'));
    act(() => result.current.updateSection('email_security', { mailbox_verification: false }));
    const saved = result.current.yaml;

    const { result: reopened } = renderHook(() => useEngineConfig(saved));
    expect(reopened.current.config.email_security.enabled).toBe(true);
    expect(reopened.current.config.email_security.config.mailbox_verification).toBe(false);
    expect(reopened.current.yaml).not.toContain('http_url');
  });
});

describe('useEngineConfig keys the form does not own', () => {
  const HAND_EDITED = `
threads: 12
delay: 2
custom_section:
  answer: 42
port_scan:
  ports: [top-100]
`;

  it('keeps an unknown top-level key through an edit', () => {
    const { result } = renderHook(() => useEngineConfig(HAND_EDITED));
    act(() => result.current.updateGlobal({ threads: 20 }));

    expect(result.current.yaml).toMatch(/^threads: 20$/m);
    expect(result.current.yaml).toMatch(/^delay: 2$/m);
    expect(result.current.yaml).toMatch(/^custom_section:\n {2}answer: 42$/m);
  });

  it('does not bring back a section the user switched off', () => {
    const { result } = renderHook(() => useEngineConfig(HAND_EDITED));
    act(() => result.current.toggleSection('port_scan', false));

    expect(result.current.yaml).not.toMatch(/^port_scan:/m);
    expect(result.current.yaml).toMatch(/^custom_section:/m);
  });

  it('does not bring back a global reset to its default', () => {
    const { result } = renderHook(() => useEngineConfig('intensity: aggressive\n'));
    act(() => result.current.updateGlobal({ intensity: 'normal' }));

    expect(result.current.yaml).not.toMatch(/^intensity:/m);
  });

  it('takes unknown keys from YAML typed into the YAML tab', () => {
    const { result } = renderHook(() => useEngineConfig(HAND_EDITED));
    act(() => result.current.setYaml('other_section:\n  x: 1\n'));
    act(() => result.current.updateGlobal({ threads: 5 }));

    expect(result.current.yaml).toMatch(/^other_section:/m);
    expect(result.current.yaml).not.toMatch(/^custom_section:/m);
  });

  it('writes the Tier 7 correlation settings', () => {
    const { result } = renderHook(() => useEngineConfig('tier_7:\n  high_noise_modules: [a]\n'));
    act(() => result.current.updateSection('tier_7', { high_noise_modules: ['b'] }));

    expect(result.current.yaml).toMatch(/^tier_7:\n {2}high_noise_modules:\n {4}- b$/m);
  });
});

describe('useEngineConfig keys the form does not own inside a section', () => {
  it('keeps an unknown section key through an edit of that section', () => {
    const { result } = renderHook(() => useEngineConfig('port_scan:\n  ports: [top-100]\n  some_backend_key: 1\n'));
    act(() => result.current.updateSection('port_scan', { rate_limit: 10 }));

    const portScan = mappingAt(loadMapping(result.current.yaml), 'port_scan');
    expect(portScan.rate_limit).toBe(10);
    expect(portScan.some_backend_key).toBe(1);
  });

  it('keeps unknown keys inside the nested mappings the form writes', () => {
    const yaml = `
vulnerability_scan:
  nuclei:
    tags: [cve]
    max_templates_per_batch: 200
  cpanel_scanner:
    proxy_type: static
    extra: 3
email_security:
  mailbox_verification:
    max_candidates: 50
    probe_from: probe@example.test
`;
    const { result } = renderHook(() => useEngineConfig(yaml));
    act(() => result.current.updateSection('vulnerability_scan', { rate_limit: 5 }));
    const doc = loadMapping(result.current.yaml);

    expect(mappingAt(doc, 'vulnerability_scan', 'nuclei')).toMatchObject({ tags: ['cve'], max_templates_per_batch: 200 });
    expect(mappingAt(doc, 'vulnerability_scan', 'cpanel_scanner')).toMatchObject({ proxy_type: 'single', extra: 3 });
    expect(mappingAt(doc, 'email_security', 'mailbox_verification')).toMatchObject({
      max_candidates: 50, probe_from: 'probe@example.test',
    });
  });

  it('does not bring back an owned key the form now leaves out', () => {
    const yaml = `
port_scan:
  enable_nmap: true
  nmap_cmd: nmap -sV
  exclude_subdomains: true
  some_backend_key: 1
osint:
  custom_dorks: [site-dork]
  whatbreach:
    download_found_databases: true
    extra: 1
`;
    const { result } = renderHook(() => useEngineConfig(yaml));
    act(() => result.current.updateSection('port_scan', { enable_nmap: false, exclude_subdomains: false }));
    act(() => result.current.updateSection('osint', { custom_dorks: [], whatbreach: false }));
    const doc = loadMapping(result.current.yaml);

    const portScan = mappingAt(doc, 'port_scan');
    expect(portScan).not.toHaveProperty('enable_nmap');
    expect(portScan).not.toHaveProperty('nmap_cmd');
    expect(portScan).not.toHaveProperty('exclude_subdomains');
    expect(portScan.some_backend_key).toBe(1);
    const osint = mappingAt(doc, 'osint');
    expect(osint).not.toHaveProperty('custom_dorks');
    expect(osint.whatbreach).toBe(false);
  });

  it('drops an owned nested mapping the form leaves out, with its unknown keys', () => {
    const yaml = `
vulnerability_scan:
  run_vigolium: true
  vigolium:
    strategy: fast
    extra: 1
  nuclei:
    tags: [cve]
    extra: 2
`;
    const { result } = renderHook(() => useEngineConfig(yaml));
    act(() => result.current.updateSection('vulnerability_scan', { run_vigolium: false, run_nuclei: false }));
    const vuln = mappingAt(loadMapping(result.current.yaml), 'vulnerability_scan');

    expect(vuln).not.toHaveProperty('vigolium');
    expect(vuln).not.toHaveProperty('nuclei');
  });

  it('still drops a disabled section with its unknown keys', () => {
    const { result } = renderHook(() => useEngineConfig('port_scan:\n  some_backend_key: 1\n'));
    act(() => result.current.toggleSection('port_scan', false));

    expect(result.current.yaml).not.toMatch(/^port_scan:/m);
    expect(result.current.yaml).not.toContain('some_backend_key');
  });

  it('keeps osint.leaks_and_secrets and carries its scanner keys into secret_scanning', () => {
    const yaml = `
osint:
  discover: [emails]
  leaks_and_secrets:
    gitleaks: false
    from_osint: 1
leaks_and_secrets:
  from_old_save: 2
`;
    const { result } = renderHook(() => useEngineConfig(yaml));
    act(() => result.current.updateSection('osint', { documents_limit: 10 }));
    const doc = loadMapping(result.current.yaml);

    // The OSINT pipeline reads this mapping, so a save must not drop it.
    expect(mappingAt(mappingAt(doc, 'osint'), 'leaks_and_secrets')).toEqual({
      leaklookup: false, leaksearch: false, gitleaks: false, from_osint: 1,
    });
    expect(doc).not.toHaveProperty('leaks_and_secrets');
    expect(mappingAt(doc, 'secret_scanning')).toMatchObject({ gitleaks: false, from_osint: 1, from_old_save: 2 });

    act(() => result.current.toggleSection('leaks_and_secrets', false));
    expect(loadMapping(result.current.yaml)).not.toHaveProperty('secret_scanning');
  });

  it('takes section keys from YAML typed into the YAML tab or loaded from a template', () => {
    const { result } = renderHook(() => useEngineConfig('port_scan:\n  first: 1\n'));
    act(() => result.current.setYaml('port_scan:\n  second: 2\n'));
    act(() => result.current.updateSection('port_scan', { threads: 5 }));

    expect(mappingAt(loadMapping(result.current.yaml), 'port_scan')).toMatchObject({ second: 2 });
    expect(result.current.yaml).not.toContain('first');

    act(() => result.current.loadTemplate('port_scan:\n  third: 3\n'));
    expect(mappingAt(loadMapping(result.current.yaml), 'port_scan')).toMatchObject({ third: 3 });
    expect(result.current.yaml).not.toContain('second');
  });
});

/** Every checkbox on, every text field and list filled: the config that writes the most keys. */
function everythingOn(node: unknown): unknown {
  if (typeof node === 'boolean') return true;
  if (typeof node === 'string') return node || 'set';
  if (Array.isArray(node)) return node.length > 0 ? node : ['set'];
  if (isMapping(node)) return Object.fromEntries(Object.entries(node).map(([key, value]) => [key, everythingOn(value)]));
  return node;
}

function unownedKeys(written: Mapping, ownedKeys: OwnedKeys, path = ''): string[] {
  return Object.entries(written).flatMap(([key, value]) => {
    if (!Object.hasOwn(ownedKeys, key)) return [`${path}${key}`];
    const inner = ownedKeys[key];
    return inner && isMapping(value) ? unownedKeys(value, inner, `${path}${key}.`) : [];
  });
}

function ownedMappingPaths(ownedKeys: OwnedKeys, path: string[] = []): string[][] {
  return Object.entries(ownedKeys).flatMap(([key, inner]) =>
    inner ? [[...path, key], ...ownedMappingPaths(inner, [...path, key])] : []);
}

describe('FORM_OWNED_KEYS', () => {
  const maximal = everythingOn(DEFAULT_ENGINE_CONFIG) as EngineConfig;
  const config: EngineConfig = {
    ...maximal,
    global: { ...maximal.global, intensity: 'aggressive', enable_http_crawl: false },
  };
  const written = loadMapping(serialiseConfigToYaml(config));

  it('lists every key the serialiser can write, at every level', () => {
    expect(unownedKeys(written, FORM_OWNED_KEYS)).toEqual([]);
  });

  it('is checked against every owned mapping, so the guard above is not vacuous', () => {
    for (const path of ownedMappingPaths(FORM_OWNED_KEYS)) {
      expect(() => mappingAt(written, ...path), path.join('.')).not.toThrow();
    }
    expect(mappingAt(written, 'port_scan')).toHaveProperty('nmap_script_args');
    expect(mappingAt(written, 'vulnerability_scan', 'nuclei')).toHaveProperty('custom_templates');
    expect(mappingAt(written, 'email_security', 'mailbox_verification')).toHaveProperty('http_url');
  });
});

describe('useEngineConfig steps the backend runs unless switched off', () => {
  it('shows Vigolium stages on when their section is missing and writes the flag when off', () => {
    const { result } = renderHook(() => useEngineConfig('threads: 5\n'));
    expect(result.current.config.vigolium_harvest.enabled).toBe(true);

    act(() => result.current.toggleSection('vigolium_harvest', false));
    expect(mappingAt(loadMapping(result.current.yaml), 'vigolium_harvest')).toEqual({ run_vigolium_harvest: false });
  });

  it('reads a stage switched off by its flag as off', () => {
    const { result } = renderHook(() => useEngineConfig('vigolium_analysis:\n  run_vigolium_analysis: false\n'));
    expect(result.current.config.vigolium_analysis.enabled).toBe(false);
  });

  it('writes attack_path_modeling.enabled: false when attack path modeling is off', () => {
    const { result } = renderHook(() => useEngineConfig('threads: 5\n'));
    expect(result.current.config.attack_path_modeling.enabled).toBe(true);

    act(() => result.current.toggleSection('attack_path_modeling', false));
    expect(mappingAt(loadMapping(result.current.yaml), 'attack_path_modeling')).toEqual({ enabled: false });
  });

  it('writes run_vigolium_audit: false when the Code Scan audit is off', () => {
    const { result } = renderHook(() => useEngineConfig('threads: 5\n'));
    act(() => result.current.toggleSection('vigolium_audit', false));
    expect(mappingAt(loadMapping(result.current.yaml), 'vigolium_audit')).toEqual({ run_vigolium_audit: false });
  });
});

describe('useEngineConfig settings moved to where the backend reads them', () => {
  it('moves the old leaks_and_secrets.run_semgrep into vulnerability_scan', () => {
    const yaml = 'leaks_and_secrets:\n  run_semgrep: false\nvulnerability_scan:\n  run_nuclei: true\n';
    const { result } = renderHook(() => useEngineConfig(yaml));
    expect(result.current.config.vulnerability_scan.config.run_semgrep).toBe(false);

    act(() => result.current.updateSection('vulnerability_scan', { run_dalfox: true }));
    expect(mappingAt(loadMapping(result.current.yaml), 'vulnerability_scan')).toMatchObject({ run_semgrep: false });
  });

  it('writes react2shell under react_scanner', () => {
    const { result } = renderHook(() => useEngineConfig('vulnerability_scan:\n  run_nuclei: true\n'));
    act(() => result.current.updateSection('vulnerability_scan', { run_react2shell: false }));
    const vuln = mappingAt(loadMapping(result.current.yaml), 'vulnerability_scan');
    expect(mappingAt(vuln, 'react_scanner')).toEqual({ run_react2shell: false });
  });

  it('writes the OSINT breach lookups under osint.leaks_and_secrets', () => {
    const { result } = renderHook(() => useEngineConfig('osint:\n  discover: [emails]\n'));
    act(() => result.current.updateSection('osint', { leaklookup: true }));
    const osint = mappingAt(loadMapping(result.current.yaml), 'osint');
    expect(mappingAt(osint, 'leaks_and_secrets')).toEqual({ leaklookup: true, leaksearch: false });
  });

  it('maps the old SpiderFoot intensities to the ones the backend knows', () => {
    const light = renderHook(() => useEngineConfig('spiderfoot_scan:\n  intensity: light\n'));
    const aggressive = renderHook(() => useEngineConfig('spiderfoot_scan:\n  intensity: aggressive\n'));
    expect(light.result.current.config.spiderfoot_scan.config.intensity).toBe('fast');
    expect(aggressive.result.current.config.spiderfoot_scan.config.intensity).toBe('deep');
  });

  it('keeps hand-set screenshot keys the form no longer shows', () => {
    const { result } = renderHook(() => useEngineConfig('screenshot:\n  threads: 40\n'));
    act(() => result.current.updateGlobal({ threads: 12 }));
    expect(mappingAt(loadMapping(result.current.yaml), 'screenshot')).toEqual({ threads: 40 });
  });

  it('round-trips the DNS security options', () => {
    const { result } = renderHook(() => useEngineConfig('dns_security:\n  enable_dns_brute: true\n'));
    act(() => result.current.updateSection('dns_security', { amplification_threshold: 20 }));
    expect(mappingAt(loadMapping(result.current.yaml), 'dns_security')).toEqual({
      enable_axfr: true, enable_dnssec_check: true, enable_dns_brute: true, amplification_threshold: 20,
    });
  });
});

describe('useEngineConfig OSINT tools', () => {
  const OSINT_ENGINE = `
osint:
  discover: [emails, metainfo]
  dorks: [login_pages]
  custom_dorks:
    - site:_target_ ext:php
    - lookup_site: _target_
      lookup_extensions: php
  intensity: light
  emailfinder: false
  microsoft_recon: true
  misconfig: true
  domain_security:
    spoofcheck: true
  api_leaks:
    porch_pirate: true
    swaggerspy: true
  dork_engines: [gofuzz, dorks_hunter]
  github_analysis:
    uses_tools: [enumerepo, titus]
    github_orgs: [acme-test]
`;

  it('reads every tool switch osint_discovery and dorking read', () => {
    const { result } = renderHook(() => useEngineConfig(OSINT_ENGINE));
    expect(result.current.config.osint.config).toMatchObject({
      custom_dorks: ['site:_target_ ext:php'],
      custom_dork_rules: [{ lookup_site: '_target_', lookup_extensions: 'php' }],
      emailfinder: false,
      microsoft_recon: true,
      misconfig: true,
      spoofcheck: true,
      porch_pirate: true,
      postleaks: false,
      swaggerspy: true,
      dork_engines: ['gofuzz', 'dorks_hunter'],
      github_analysis: true,
      github_tools: ['enumerepo', 'titus'],
      github_gato: false,
      github_orgs: ['acme-test'],
    });
  });

  it('writes them back where the backend reads them, keeping structured custom dorks', () => {
    const { result } = renderHook(() => useEngineConfig(OSINT_ENGINE));
    act(() => result.current.updateSection('osint', { postleaks: true, github_gato: true }));
    const osint = mappingAt(loadMapping(result.current.yaml), 'osint');

    expect(osint.custom_dorks).toEqual(['site:_target_ ext:php', { lookup_site: '_target_', lookup_extensions: 'php' }]);
    expect(osint).toMatchObject({ emailfinder: false, microsoft_recon: true, misconfig: true, dork_engines: ['gofuzz', 'dorks_hunter'] });
    expect(mappingAt(osint, 'domain_security')).toEqual({ spoofcheck: true });
    expect(mappingAt(osint, 'api_leaks')).toEqual({ porch_pirate: true, postleaks: true, swaggerspy: true });
    expect(mappingAt(osint, 'github_analysis')).toEqual({ uses_tools: ['enumerepo', 'titus'], gato: true, github_orgs: ['acme-test'] });
  });

  it('drops the intensity that silently skipped the metainfo lookup', () => {
    const { result } = renderHook(() => useEngineConfig(OSINT_ENGINE));
    act(() => result.current.updateSection('osint', { documents_limit: 10 }));
    expect(mappingAt(loadMapping(result.current.yaml), 'osint')).not.toHaveProperty('intensity');
  });

  it('leaves github_analysis out when it is off, as any mapping there runs it', () => {
    const { result } = renderHook(() => useEngineConfig(OSINT_ENGINE));
    act(() => result.current.updateSection('osint', { github_analysis: false }));
    expect(mappingAt(loadMapping(result.current.yaml), 'osint')).not.toHaveProperty('github_analysis');
  });

  it('defaults like the backend when the keys are missing', () => {
    const { result } = renderHook(() => useEngineConfig('osint:\n  discover: [emails]\n  github_analysis: {gato: true}\n'));
    expect(result.current.config.osint.config).toMatchObject({
      emailfinder: true, microsoft_recon: false, spoofcheck: false, dork_engines: [], custom_dork_rules: [],
      github_analysis: true, github_tools: ['enumerepo'], github_gato: true,
    });
    const empty = renderHook(() => useEngineConfig('osint:\n  github_analysis: {}\n'));
    expect(empty.result.current.config.osint.config.github_analysis).toBe(false);
  });
});

describe('useEngineConfig discovery steps scheduled by their top-level key', () => {
  it('reads amass_intel_discovery and baddns as on when the key is there, even without a value', () => {
    const { result } = renderHook(() => useEngineConfig('amass_intel_discovery:\nbaddns:\n'));
    expect(result.current.config.amass_intel_discovery.enabled).toBe(true);
    expect(result.current.config.baddns.enabled).toBe(true);

    const none = renderHook(() => useEngineConfig('threads: 5\n'));
    expect(none.result.current.config.amass_intel_discovery.enabled).toBe(false);
    expect(none.result.current.config.baddns.enabled).toBe(false);
  });

  it('takes the amass config switch from subdomain_discovery when the section does not set it', () => {
    const inherited = renderHook(() => useEngineConfig('amass_intel_discovery: {}\nsubdomain_discovery:\n  use_amass_config: true\n'));
    expect(inherited.result.current.config.amass_intel_discovery.config.use_amass_config).toBe(true);

    const own = renderHook(() => useEngineConfig(
      'amass_intel_discovery:\n  use_amass_config: false\nsubdomain_discovery:\n  use_amass_config: true\n',
    ));
    expect(own.result.current.config.amass_intel_discovery.config.use_amass_config).toBe(false);
  });

  it('writes the keys only while their cards are on', () => {
    const { result } = renderHook(() => useEngineConfig('threads: 5\n'));
    act(() => result.current.toggleSection('amass_intel_discovery', true));
    act(() => result.current.toggleSection('baddns', true));
    act(() => result.current.updateSection('amass_intel_discovery', { use_amass_config: true }));
    let doc = loadMapping(result.current.yaml);
    expect(mappingAt(doc, 'amass_intel_discovery')).toEqual({ use_amass_config: true });
    expect(mappingAt(doc, 'baddns')).toEqual({});

    act(() => result.current.toggleSection('baddns', false));
    doc = loadMapping(result.current.yaml);
    expect(doc).not.toHaveProperty('baddns');
  });
});

describe('useEngineConfig post-crawl OSINT section', () => {
  it('reads a tool whose key is missing as off, like the task', () => {
    const { result } = renderHook(() => useEngineConfig('post_crawl_osint:\n  swaggerspy: true\n'));
    expect(result.current.config.post_crawl_osint).toEqual({ enabled: true, config: { metagoofil: false, swaggerspy: true } });
  });

  it('round-trips both switches and drops the section when the card is off', () => {
    const { result } = renderHook(() => useEngineConfig('post_crawl_osint:\n  metagoofil: true\n  swaggerspy: true\n'));
    act(() => result.current.updateSection('post_crawl_osint', { swaggerspy: false }));
    expect(mappingAt(loadMapping(result.current.yaml), 'post_crawl_osint')).toEqual({ metagoofil: true, swaggerspy: false });

    act(() => result.current.toggleSection('post_crawl_osint', false));
    expect(loadMapping(result.current.yaml)).not.toHaveProperty('post_crawl_osint');
  });
});

describe('useEngineConfig Vigolium defaults', () => {
  it('loads missing Vigolium settings with the values the backend falls back to', () => {
    const { result } = renderHook(() => useEngineConfig('vulnerability_scan:\n  run_vigolium: true\n  vigolium: {}\n'));
    const c = result.current.config;
    expect(c.vigolium_harvest.config).toEqual({ strategy: 'balanced', concurrency: 30, rate_limit: 100, timeout: '60s' });
    expect(c.vigolium_discovery.config).toEqual({ strategy: 'balanced', concurrency: 40, rate_limit: 100, timeout: '30s' });
    expect(c.vigolium_analysis.config).toEqual({ strategy: 'balanced', concurrency: 20, rate_limit: 50, timeout: '10s' });
    expect(c.vulnerability_scan.config.vigolium.timeout).toBe('300s');
  });
});
