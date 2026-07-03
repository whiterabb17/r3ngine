import React from 'react';
import { Grid, FormControlLabel, Checkbox, Typography } from '@mui/material';
import type { FirewallVpnConfig } from '../../types/engineConfig';
import { SectionCard } from '../shared/SectionCard';
import { TagInput } from '../shared/TagInput';
import { useThemeTokens } from '../../../../theme/useThemeTokens';

interface Props {
  config: FirewallVpnConfig;
  enabled: boolean;
  onToggle: (v: boolean) => void;
  onChange: (p: Partial<FirewallVpnConfig>) => void;
}

export const FirewallVpnSection: React.FC<Props> = ({ config, enabled, onToggle, onChange }) => {
  const { tokens } = useThemeTokens();
  const chkSx = { color: tokens.accent.primary, '&.Mui-checked': { color: tokens.accent.primary } };

  return (
    <SectionCard
      title="Firewall / VPN Scan"
      description="Identifies IPSec VPN endpoints and audits SSL/TLS. Runs at Tier 1."
      enabled={enabled}
      onToggle={onToggle}
    >
      <Grid container spacing={1} sx={{ mb: 2 }}>
        {([['run_ike_scan', 'IKE scan (IPSec VPN detection)'], ['run_sslscan', 'SSL scan (TLS audit)']] as const).map(([field, label]) => (
          <Grid size={{ xs: 12 }} key={field}>
            <FormControlLabel
              control={
                <Checkbox
                  checked={config[field]}
                  size="small"
                  onChange={(e) => onChange({ [field]: e.target.checked })}
                  sx={chkSx}
                />
              }
              label={<Typography variant="body2">{label}</Typography>}
            />
          </Grid>
        ))}
      </Grid>
      <TagInput
        label="Ports"
        value={config.ports.map(String)}
        onChange={(v) => onChange({ ports: v.map(Number).filter((n) => !isNaN(n)) })}
        placeholder="443"
        helperText="Port numbers to scan"
      />
    </SectionCard>
  );
};
