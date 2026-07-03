import React, { useState } from 'react';
import { Box, Tabs, Tab } from '@mui/material';
import type { UseEngineConfigReturn } from '../hooks/useEngineConfig';
import { GlobalSettingsSection } from './sections/GlobalSettingsSection';
import { SubdomainDiscoverySection } from './sections/SubdomainDiscoverySection';
import { DnsSecuritySection } from './sections/DnsSecuritySection';
import { OsintSection } from './sections/OsintSection';
import { SpiderfootSection } from './sections/SpiderfootSection';
import { VigoliumHarvestSection } from './sections/VigoliumHarvestSection';
import { VigoliumDiscoverySection } from './sections/VigoliumDiscoverySection';
import { FirewallVpnSection } from './sections/FirewallVpnSection';
import { HttpCrawlSection } from './sections/HttpCrawlSection';
import { PortScanSection } from './sections/PortScanSection';
import { ScreenshotSection } from './sections/ScreenshotSection';
import { FetchUrlSection } from './sections/FetchUrlSection';
import { WebApiDiscoverySection } from './sections/WebApiDiscoverySection';
import { ParamDiscoverySection } from './sections/ParamDiscoverySection';
import { DirFileFuzzSection } from './sections/DirFileFuzzSection';
import { WafDetectionSection } from './sections/WafDetectionSection';
import { WafBypassSection } from './sections/WafBypassSection';
import { LeaksSecretsSection } from './sections/LeaksSecretsSection';
import { VigoliumAnalysisSection } from './sections/VigoliumAnalysisSection';
import { VulnerabilitySection } from './sections/VulnerabilitySection';
import { AttackPathSection } from './sections/AttackPathSection';
import { VigoliumAuditSection } from './sections/VigoliumAuditSection';
import { YamlPreviewPanel } from './YamlPreviewPanel';
import { useThemeTokens } from '../../../theme/useThemeTokens';

interface EngineConfigTabsProps {
  state: UseEngineConfigReturn;
}

const TAB_LABELS = [
  'Global',
  'Tier 1 — Discovery',
  'Tier 2 — Surface',
  'Tier 3 — Recon',
  'Tier 4 — Fuzzing',
  'Tier 5 — Analysis',
  'Tier 6 — Vuln Scan',
  'Tier 7 — Intelligence',
  'YAML',
];

export const EngineConfigTabs: React.FC<EngineConfigTabsProps> = ({ state }) => {
  const [tab, setTab] = useState(0);
  const { tokens } = useThemeTokens();
  const { config, yaml, yamlError, updateSection, toggleSection, updateGlobal, setYaml } = state;

  const tabSx = {
    minWidth: 'auto',
    fontFamily: 'Orbitron',
    fontSize: '0.65rem',
    fontWeight: 700,
    letterSpacing: 0.5,
    '&.Mui-selected': { color: tokens.accent.primary },
  };

  const panelProps = (index: number) => ({
    role: 'tabpanel' as const,
    hidden: tab !== index,
    id: `engine-tab-panel-${index}`,
  });

  return (
    <Box>
      <Tabs
        value={tab}
        onChange={(_, v) => setTab(v)}
        variant="scrollable"
        scrollButtons="auto"
        sx={{
          borderBottom: '1px solid',
          borderColor: 'divider',
          mb: 2,
          '& .MuiTabs-indicator': { backgroundColor: tokens.accent.primary },
        }}
      >
        {TAB_LABELS.map((label) => (
          <Tab key={label} label={label} sx={tabSx} />
        ))}
      </Tabs>

      {/* Tab 0 — Global */}
      <Box {...panelProps(0)}>
        {tab === 0 && (
          <GlobalSettingsSection
            config={config.global}
            onChange={updateGlobal}
          />
        )}
      </Box>

      {/* Tab 1 — Tier 1: Discovery */}
      <Box {...panelProps(1)}>
        {tab === 1 && (
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            <SubdomainDiscoverySection
              config={config.subdomain_discovery.config}
              enabled={config.subdomain_discovery.enabled}
              onToggle={(v) => toggleSection('subdomain_discovery', v)}
              onChange={(p) => updateSection('subdomain_discovery', p)}
            />
            <DnsSecuritySection
              enabled={config.dns_security.enabled}
              onToggle={(v) => toggleSection('dns_security', v)}
            />
            <OsintSection
              config={config.osint.config}
              enabled={config.osint.enabled}
              onToggle={(v) => toggleSection('osint', v)}
              onChange={(p) => updateSection('osint', p)}
            />
            <SpiderfootSection
              config={config.spiderfoot_scan.config}
              enabled={config.spiderfoot_scan.enabled}
              onToggle={(v) => toggleSection('spiderfoot_scan', v)}
              onChange={(p) => updateSection('spiderfoot_scan', p)}
            />
            <VigoliumHarvestSection
              config={config.vigolium_harvest.config}
              enabled={config.vigolium_harvest.enabled}
              onToggle={(v) => toggleSection('vigolium_harvest', v)}
              onChange={(p) => updateSection('vigolium_harvest', p)}
            />
            <VigoliumDiscoverySection
              config={config.vigolium_discovery.config}
              enabled={config.vigolium_discovery.enabled}
              onToggle={(v) => toggleSection('vigolium_discovery', v)}
              onChange={(p) => updateSection('vigolium_discovery', p)}
            />
            <FirewallVpnSection
              config={config.firewall_vpn_scan.config}
              enabled={config.firewall_vpn_scan.enabled}
              onToggle={(v) => toggleSection('firewall_vpn_scan', v)}
              onChange={(p) => updateSection('firewall_vpn_scan', p)}
            />
          </Box>
        )}
      </Box>

      {/* Tab 2 — Tier 2: Surface */}
      <Box {...panelProps(2)}>
        {tab === 2 && (
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            <HttpCrawlSection
              config={config.http_crawl.config}
              enabled={config.http_crawl.enabled}
              onToggle={(v) => toggleSection('http_crawl', v)}
              onChange={(p) => updateSection('http_crawl', p)}
            />
            <PortScanSection
              config={config.port_scan.config}
              enabled={config.port_scan.enabled}
              onToggle={(v) => toggleSection('port_scan', v)}
              onChange={(p) => updateSection('port_scan', p)}
            />
            <ScreenshotSection
              config={config.screenshot.config}
              enabled={config.screenshot.enabled}
              onToggle={(v) => toggleSection('screenshot', v)}
              onChange={(p) => updateSection('screenshot', p)}
            />
          </Box>
        )}
      </Box>

      {/* Tab 3 — Tier 3: Recon */}
      <Box {...panelProps(3)}>
        {tab === 3 && (
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            <FetchUrlSection
              config={config.fetch_url.config}
              enabled={config.fetch_url.enabled}
              onToggle={(v) => toggleSection('fetch_url', v)}
              onChange={(p) => updateSection('fetch_url', p)}
            />
            <WebApiDiscoverySection
              config={config.web_api_discovery.config}
              enabled={config.web_api_discovery.enabled}
              onToggle={(v) => toggleSection('web_api_discovery', v)}
              onChange={(p) => updateSection('web_api_discovery', p)}
            />
            <ParamDiscoverySection
              config={config.param_discovery.config}
              enabled={config.param_discovery.enabled}
              onToggle={(v) => toggleSection('param_discovery', v)}
              onChange={(p) => updateSection('param_discovery', p)}
            />
          </Box>
        )}
      </Box>

      {/* Tab 4 — Tier 4: Fuzzing */}
      <Box {...panelProps(4)}>
        {tab === 4 && (
          <DirFileFuzzSection
            config={config.dir_file_fuzz.config}
            enabled={config.dir_file_fuzz.enabled}
            onToggle={(v) => toggleSection('dir_file_fuzz', v)}
            onChange={(p) => updateSection('dir_file_fuzz', p)}
          />
        )}
      </Box>

      {/* Tab 5 — Tier 5: Analysis */}
      <Box {...panelProps(5)}>
        {tab === 5 && (
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            <WafDetectionSection
              config={config.waf_detection.config}
              enabled={config.waf_detection.enabled}
              onToggle={(v) => toggleSection('waf_detection', v)}
              onChange={(p) => updateSection('waf_detection', p)}
            />
            <WafBypassSection
              config={config.waf_bypass.config}
              enabled={config.waf_bypass.enabled}
              onToggle={(v) => toggleSection('waf_bypass', v)}
              onChange={(p) => updateSection('waf_bypass', p)}
            />
            <LeaksSecretsSection
              config={config.leaks_and_secrets.config}
              enabled={config.leaks_and_secrets.enabled}
              onToggle={(v) => toggleSection('leaks_and_secrets', v)}
              onChange={(p) => updateSection('leaks_and_secrets', p)}
            />
            <VigoliumAnalysisSection
              config={config.vigolium_analysis.config}
              enabled={config.vigolium_analysis.enabled}
              onToggle={(v) => toggleSection('vigolium_analysis', v)}
              onChange={(p) => updateSection('vigolium_analysis', p)}
            />
          </Box>
        )}
      </Box>

      {/* Tab 6 — Tier 6: Vuln Scan */}
      <Box {...panelProps(6)}>
        {tab === 6 && (
          <VulnerabilitySection
            config={config.vulnerability_scan.config}
            enabled={config.vulnerability_scan.enabled}
            onToggle={(v) => toggleSection('vulnerability_scan', v)}
            onChange={(p) => updateSection('vulnerability_scan', p)}
          />
        )}
      </Box>

      {/* Tab 7 — Tier 7: Intelligence */}
      <Box {...panelProps(7)}>
        {tab === 7 && (
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            <AttackPathSection
              config={config.attack_path_modeling.config}
              enabled={config.attack_path_modeling.enabled}
              onToggle={(v) => toggleSection('attack_path_modeling', v)}
              onChange={(p) => updateSection('attack_path_modeling', p)}
            />
            <VigoliumAuditSection
              config={config.vigolium_audit.config}
              enabled={config.vigolium_audit.enabled}
              onToggle={(v) => toggleSection('vigolium_audit', v)}
              onChange={(p) => updateSection('vigolium_audit', p)}
            />
          </Box>
        )}
      </Box>

      {/* Tab 8 — YAML Preview */}
      <Box {...panelProps(8)}>
        {tab === 8 && (
          <YamlPreviewPanel
            yaml={yaml}
            yamlError={yamlError}
            onChange={setYaml}
          />
        )}
      </Box>
    </Box>
  );
};
