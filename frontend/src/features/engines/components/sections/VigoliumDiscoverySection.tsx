import React from 'react';
import { Grid, TextField, MenuItem } from '@mui/material';
import type { VigoliumDiscoveryConfig } from '../../types/engineConfig';
import { SectionCard } from '../shared/SectionCard';
import { getFieldSx } from '../../../../theme/semanticColors';
import { useThemeTokens } from '../../../../theme/useThemeTokens';

interface Props {
  config: VigoliumDiscoveryConfig;
  enabled: boolean;
  onToggle: (v: boolean) => void;
  onChange: (p: Partial<VigoliumDiscoveryConfig>) => void;
}

export const VigoliumDiscoverySection: React.FC<Props> = ({ config, enabled, onToggle, onChange }) => {
  const { tokens, isLight } = useThemeTokens();
  const fieldSx = getFieldSx(isLight, tokens);

  return (
    <SectionCard
      title="Vigolium Discovery"
      description="Active target probing — runs in parallel at Tier 1."
      enabled={enabled}
      onToggle={onToggle}
    >
      <Grid container spacing={2}>
        <Grid size={{ xs: 12, sm: 4 }}>
          <TextField
            select
            label="Strategy"
            size="small"
            fullWidth
            value={config.strategy}
            onChange={(e) => onChange({ strategy: e.target.value as VigoliumDiscoveryConfig['strategy'] })}
            sx={fieldSx}
          >
            {['fast', 'balanced', 'thorough'].map((o) => (
              <MenuItem key={o} value={o}>{o}</MenuItem>
            ))}
          </TextField>
        </Grid>
        <Grid size={{ xs: 6, sm: 2 }}>
          <TextField
            label="Concurrency"
            type="number"
            size="small"
            fullWidth
            value={config.concurrency}
            onChange={(e) => onChange({ concurrency: Math.max(1, Number(e.target.value)) })}
            slotProps={{ htmlInput: { min: 1 } }}
            sx={fieldSx}
          />
        </Grid>
        <Grid size={{ xs: 6, sm: 3 }}>
          <TextField
            label="Rate Limit"
            type="number"
            size="small"
            fullWidth
            value={config.rate_limit}
            onChange={(e) => onChange({ rate_limit: Math.max(1, Number(e.target.value)) })}
            slotProps={{ htmlInput: { min: 1 } }}
            sx={fieldSx}
          />
        </Grid>
        <Grid size={{ xs: 6, sm: 3 }}>
          <TextField
            label="Timeout"
            size="small"
            fullWidth
            value={config.timeout}
            onChange={(e) => onChange({ timeout: e.target.value })}
            helperText="e.g. 10s, 1m"
            sx={fieldSx}
          />
        </Grid>
      </Grid>
    </SectionCard>
  );
};
