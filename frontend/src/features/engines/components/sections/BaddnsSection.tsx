import React from 'react';
import { Alert, Button, Typography } from '@mui/material';
import { alpha } from '@mui/material/styles';
import type { SectionState, SubdomainDiscoveryConfig } from '../../types/engineConfig';
import { SectionCard } from '../shared/SectionCard';
import { useThemeTokens } from '../../../../theme/useThemeTokens';

interface Props {
  enabled: boolean;
  onToggle: (v: boolean) => void;
  /** The subdomain discovery section, whose tool list can run baddns as well. */
  subdomainDiscovery: SectionState<SubdomainDiscoveryConfig>;
  onSubdomainToolsChange: (usesTools: string[]) => void;
}

export const BaddnsSection: React.FC<Props> = ({ enabled, onToggle, subdomainDiscovery, onSubdomainToolsChange }) => {
  const { tokens, theme } = useThemeTokens();
  const tools = subdomainDiscovery.config.uses_tools;
  const alsoInSubdomainDiscovery = enabled && subdomainDiscovery.enabled && tools.includes('baddns');

  return (
    <SectionCard
      title="BadDNS"
      description="Standalone subdomain takeover and DNS misconfiguration check of the target domain, at Tier 1."
      enabled={enabled}
      onToggle={onToggle}
    >
      <Typography variant="body2" sx={{ color: 'text.secondary' }}>
        Runs baddns as its own step with its own timeline entry, so it also works without subdomain
        discovery. Picking baddns in the Subdomain Discovery tools runs the same check inside that
        step instead. Takeovers are reported as critical vulnerabilities either way.
      </Typography>
      {alsoInSubdomainDiscovery && (
        <Alert
          severity="warning"
          action={
            <Button color="inherit" size="small" onClick={() => onSubdomainToolsChange(tools.filter((t) => t !== 'baddns'))}>
              Run it only here
            </Button>
          }
          sx={{
            mt: 1.5,
            py: 0.25,
            fontSize: '0.8rem',
            bgcolor: alpha(tokens.accent.warning, 0.08),
            color: theme.palette.text.primary,
            border: `1px solid ${alpha(tokens.accent.warning, 0.3)}`,
            '& .MuiAlert-icon': { color: tokens.accent.warning },
          }}
        >
          baddns is also selected in Subdomain Discovery, so it runs twice at the same time against the same domain.
        </Alert>
      )}
    </SectionCard>
  );
};
