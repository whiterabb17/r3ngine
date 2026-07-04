import React from 'react';
import { Grid, TextField, MenuItem } from '@mui/material';
import type { SpiderfootConfig } from '../../types/engineConfig';
import { SectionCard } from '../shared/SectionCard';
import { getFieldSx } from '../../../../theme/semanticColors';
import { useThemeTokens } from '../../../../theme/useThemeTokens';

interface Props {
  config: SpiderfootConfig;
  enabled: boolean;
  onToggle: (v: boolean) => void;
  onChange: (p: Partial<SpiderfootConfig>) => void;
}

export const SpiderfootSection: React.FC<Props> = ({ config, enabled, onToggle, onChange }) => {
  const { tokens, isLight } = useThemeTokens();
  const fieldSx = getFieldSx(isLight, tokens);

  return (
    <SectionCard
      title="SpiderFoot"
      description="Attack surface intelligence. Runs in parallel at Tier 1."
      enabled={enabled}
      onToggle={onToggle}
    >
      <Grid container spacing={2}>
        <Grid size={{ xs: 12, sm: 6 }}>
          <TextField
            label="Modules"
            size="small"
            fullWidth
            value={config.modules}
            onChange={(e) => onChange({ modules: e.target.value })}
            helperText="Use 'all' or a comma-separated list of SF module names"
            sx={fieldSx}
          />
        </Grid>
        <Grid size={{ xs: 6, sm: 3 }}>
          <TextField
            select
            label="Intensity"
            size="small"
            fullWidth
            value={config.intensity}
            onChange={(e) => onChange({ intensity: e.target.value as SpiderfootConfig['intensity'] })}
            sx={fieldSx}
          >
            {['normal', 'aggressive', 'light'].map((o) => (
              <MenuItem key={o} value={o}>{o}</MenuItem>
            ))}
          </TextField>
        </Grid>
        <Grid size={{ xs: 6, sm: 3 }}>
          <TextField
            label="Threads"
            type="number"
            size="small"
            fullWidth
            value={config.threads}
            onChange={(e) => onChange({ threads: Math.max(1, Math.min(50, Number(e.target.value))) })}
            slotProps={{ htmlInput: { min: 1, max: 50 } }}
            sx={fieldSx}
          />
        </Grid>
      </Grid>
    </SectionCard>
  );
};
