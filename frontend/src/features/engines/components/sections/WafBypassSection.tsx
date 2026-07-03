import React from 'react';
import { Grid, TextField, FormControlLabel, Checkbox, Typography } from '@mui/material';
import type { WafBypassConfig } from '../../types/engineConfig';
import { SectionCard } from '../shared/SectionCard';
import { getFieldSx } from '../../../../theme/semanticColors';
import { useThemeTokens } from '../../../../theme/useThemeTokens';

const BOOL_FIELDS = [
  ['use_benchmarking', 'HTTP header manipulation benchmarking'],
  ['use_nuclei', 'Nuclei bypass templates'],
] as const;

interface Props {
  config: WafBypassConfig;
  enabled: boolean;
  onToggle: (v: boolean) => void;
  onChange: (p: Partial<WafBypassConfig>) => void;
}

export const WafBypassSection: React.FC<Props> = ({ config, enabled, onToggle, onChange }) => {
  const { tokens, isLight } = useThemeTokens();
  const fieldSx = getFieldSx(isLight, tokens);
  const chkSx = { color: tokens.accent.primary, '&.Mui-checked': { color: tokens.accent.primary } };

  return (
    <SectionCard
      title="WAF Bypass"
      description="Tests header manipulation and Nuclei bypass templates (Tier 5)."
      enabled={enabled}
      onToggle={onToggle}
    >
      <Grid container spacing={2} sx={{ alignItems: 'center' }}>
        <Grid size={{ xs: 6, sm: 3 }}>
          <TextField
            label="Timeout (s)"
            type="number"
            size="small"
            fullWidth
            value={config.timeout}
            onChange={(e) => onChange({ timeout: Math.max(1, Number(e.target.value)) })}
            slotProps={{ htmlInput: { min: 1 } }}
            sx={fieldSx}
          />
        </Grid>
        <Grid size={{ xs: 6, sm: 3 }}>
          <TextField
            label="Threads"
            type="number"
            size="small"
            fullWidth
            value={config.threads}
            onChange={(e) => onChange({ threads: Math.max(1, Number(e.target.value)) })}
            slotProps={{ htmlInput: { min: 1 } }}
            sx={fieldSx}
          />
        </Grid>
        <Grid size={{ xs: 12 }}>
          {BOOL_FIELDS.map(([field, label]) => (
            <FormControlLabel
              key={field}
              control={
                <Checkbox
                  checked={config[field]}
                  size="small"
                  onChange={(e) => onChange({ [field]: e.target.checked })}
                  sx={chkSx}
                />
              }
              label={<Typography variant="body2">{label}</Typography>}
              sx={{ mr: 2 }}
            />
          ))}
        </Grid>
      </Grid>
    </SectionCard>
  );
};
