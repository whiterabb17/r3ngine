import React, { useState } from 'react';
import {
  Box, Stepper, Step, StepLabel, StepContent, Button, Typography,
} from '@mui/material';
import { ChevronLeft, ChevronRight } from 'lucide-react';
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
import { Tier7Section } from './sections/Tier7Section';
import { useThemeTokens } from '../../../theme/useThemeTokens';

interface EngineConfigWizardProps {
  state: UseEngineConfigReturn;
}

export const EngineConfigWizard: React.FC<EngineConfigWizardProps> = ({ state }) => {
  const [activeStep, setActiveStep] = useState(0);
  const { tokens } = useThemeTokens();
  const { config, updateSection, toggleSection, updateGlobal } = state;

  const steps = [
    {
      label: 'Global Settings',
      content: <GlobalSettingsSection config={config.global} onChange={updateGlobal} />,
    },
    {
      label: 'Tier 1 — Discovery',
      description: 'Subdomain enumeration, OSINT, DNS security, SpiderFoot, and Vigolium harvest run in parallel.',
      content: (
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          <SubdomainDiscoverySection config={config.subdomain_discovery.config} enabled={config.subdomain_discovery.enabled} onToggle={(v) => toggleSection('subdomain_discovery', v)} onChange={(p) => updateSection('subdomain_discovery', p)} />
          <DnsSecuritySection enabled={config.dns_security.enabled} onToggle={(v) => toggleSection('dns_security', v)} />
          <OsintSection config={config.osint.config} enabled={config.osint.enabled} onToggle={(v) => toggleSection('osint', v)} onChange={(p) => updateSection('osint', p)} />
          <SpiderfootSection config={config.spiderfoot_scan.config} enabled={config.spiderfoot_scan.enabled} onToggle={(v) => toggleSection('spiderfoot_scan', v)} onChange={(p) => updateSection('spiderfoot_scan', p)} />
          <VigoliumHarvestSection config={config.vigolium_harvest.config} enabled={config.vigolium_harvest.enabled} onToggle={(v) => toggleSection('vigolium_harvest', v)} onChange={(p) => updateSection('vigolium_harvest', p)} />
          <VigoliumDiscoverySection config={config.vigolium_discovery.config} enabled={config.vigolium_discovery.enabled} onToggle={(v) => toggleSection('vigolium_discovery', v)} onChange={(p) => updateSection('vigolium_discovery', p)} />
          <FirewallVpnSection config={config.firewall_vpn_scan.config} enabled={config.firewall_vpn_scan.enabled} onToggle={(v) => toggleSection('firewall_vpn_scan', v)} onChange={(p) => updateSection('firewall_vpn_scan', p)} />
        </Box>
      ),
    },
    {
      label: 'Tier 2 — Surface',
      description: 'HTTP crawl, port scan, and screenshot run in parallel after discovery.',
      content: (
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          <HttpCrawlSection config={config.http_crawl.config} enabled={config.http_crawl.enabled} onToggle={(v) => toggleSection('http_crawl', v)} onChange={(p) => updateSection('http_crawl', p)} />
          <PortScanSection config={config.port_scan.config} enabled={config.port_scan.enabled} onToggle={(v) => toggleSection('port_scan', v)} onChange={(p) => updateSection('port_scan', p)} />
          <ScreenshotSection config={config.screenshot.config} enabled={config.screenshot.enabled} onToggle={(v) => toggleSection('screenshot', v)} onChange={(p) => updateSection('screenshot', p)} />
        </Box>
      ),
    },
    {
      label: 'Tier 3 — Recon',
      description: 'URL fetching, API discovery, and parameter extraction run sequentially.',
      content: (
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          <FetchUrlSection config={config.fetch_url.config} enabled={config.fetch_url.enabled} onToggle={(v) => toggleSection('fetch_url', v)} onChange={(p) => updateSection('fetch_url', p)} />
          <WebApiDiscoverySection config={config.web_api_discovery.config} enabled={config.web_api_discovery.enabled} onToggle={(v) => toggleSection('web_api_discovery', v)} onChange={(p) => updateSection('web_api_discovery', p)} />
          <ParamDiscoverySection config={config.param_discovery.config} enabled={config.param_discovery.enabled} onToggle={(v) => toggleSection('param_discovery', v)} onChange={(p) => updateSection('param_discovery', p)} />
        </Box>
      ),
    },
    {
      label: 'Tier 4 — Fuzzing',
      description: 'Directory and file enumeration.',
      content: <DirFileFuzzSection config={config.dir_file_fuzz.config} enabled={config.dir_file_fuzz.enabled} onToggle={(v) => toggleSection('dir_file_fuzz', v)} onChange={(p) => updateSection('dir_file_fuzz', p)} />,
    },
    {
      label: 'Tier 5 — Analysis',
      description: 'WAF detection, secret scanning, and Vigolium analysis run in parallel.',
      content: (
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          <WafDetectionSection config={config.waf_detection.config} enabled={config.waf_detection.enabled} onToggle={(v) => toggleSection('waf_detection', v)} onChange={(p) => updateSection('waf_detection', p)} />
          <WafBypassSection config={config.waf_bypass.config} enabled={config.waf_bypass.enabled} onToggle={(v) => toggleSection('waf_bypass', v)} onChange={(p) => updateSection('waf_bypass', p)} />
          <LeaksSecretsSection config={config.leaks_and_secrets.config} enabled={config.leaks_and_secrets.enabled} onToggle={(v) => toggleSection('leaks_and_secrets', v)} onChange={(p) => updateSection('leaks_and_secrets', p)} />
          <VigoliumAnalysisSection config={config.vigolium_analysis.config} enabled={config.vigolium_analysis.enabled} onToggle={(v) => toggleSection('vigolium_analysis', v)} onChange={(p) => updateSection('vigolium_analysis', p)} />
        </Box>
      ),
    },
    {
      label: 'Tier 6 — Vulnerability Scan',
      description: 'Nuclei, Dalfox, WPScan, Vigolium and active exploitation checks.',
      content: <VulnerabilitySection config={config.vulnerability_scan.config} enabled={config.vulnerability_scan.enabled} onToggle={(v) => toggleSection('vulnerability_scan', v)} onChange={(p) => updateSection('vulnerability_scan', p)} />,
    },
    {
      label: 'Tier 7 — Intelligence',
      description: 'Attack path modeling and deep Vigolium audit run after all other tiers.',
      content: (
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          <AttackPathSection config={config.attack_path_modeling.config} enabled={config.attack_path_modeling.enabled} onToggle={(v) => toggleSection('attack_path_modeling', v)} onChange={(p) => updateSection('attack_path_modeling', p)} />
          <Tier7Section config={config.tier_7.config} enabled={config.tier_7.enabled} onToggle={(v) => toggleSection('tier_7', v)} onChange={(p) => updateSection('tier_7', p)} />
          <VigoliumAuditSection config={config.vigolium_audit.config} enabled={config.vigolium_audit.enabled} onToggle={(v) => toggleSection('vigolium_audit', v)} onChange={(p) => updateSection('vigolium_audit', p)} />
        </Box>
      ),
    },
  ];

  const btnSx = { fontFamily: 'Orbitron', fontSize: '0.65rem', fontWeight: 700 };

  return (
    <Stepper activeStep={activeStep} orientation="vertical">
      {steps.map((step, index) => (
        <Step key={step.label}>
          <StepLabel
            sx={{
              '& .MuiStepIcon-root.Mui-active': { color: tokens.accent.primary },
              '& .MuiStepIcon-root.Mui-completed': { color: tokens.accent.primary },
              '& .MuiStepLabel-label': { fontFamily: 'Orbitron', fontWeight: 700, fontSize: '0.75rem' },
            }}
          >
            {step.label}
          </StepLabel>
          <StepContent>
            {step.description && (
              <Typography variant="caption" sx={{ color: 'text.secondary', display: 'block', mb: 1.5 }}>
                {step.description}
              </Typography>
            )}
            {step.content}
            <Box sx={{ display: 'flex', gap: 1, mt: 2 }}>
              {index > 0 && (
                <Button size="small" variant="outlined" onClick={() => setActiveStep(index - 1)}
                  startIcon={<ChevronLeft size={14} />} sx={btnSx}>
                  Back
                </Button>
              )}
              {index < steps.length - 1 && (
                <Button size="small" variant="contained" onClick={() => setActiveStep(index + 1)}
                  endIcon={<ChevronRight size={14} />}
                  sx={{ ...btnSx, bgcolor: tokens.accent.primary, '&:hover': { bgcolor: tokens.accent.primary } }}>
                  Next
                </Button>
              )}
            </Box>
          </StepContent>
        </Step>
      ))}
    </Stepper>
  );
};
