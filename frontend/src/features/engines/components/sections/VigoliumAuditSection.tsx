import React from 'react';
import { Grid, TextField, MenuItem, FormControlLabel, Checkbox, Typography } from '@mui/material';
import type { VigoliumAuditConfig } from '../../types/engineConfig';
import { SectionCard } from '../shared/SectionCard';
import { getFieldSx } from '../../../../theme/semanticColors';
import { useThemeTokens } from '../../../../theme/useThemeTokens';

interface Props {
  config: VigoliumAuditConfig;
  enabled: boolean;
  onToggle: (v: boolean) => void;
  onChange: (p: Partial<VigoliumAuditConfig>) => void;
}

export const VigoliumAuditSection: React.FC<Props> = ({ config, enabled, onToggle, onChange }) => {
  const { tokens, isLight } = useThemeTokens();
  const fieldSx = getFieldSx(isLight, tokens);

  return (
    <SectionCard
      title="Vigolium Audit"
      description="Deep AI-assisted security audit run after all scan tiers complete (Tier 7)."
      enabled={enabled}
      onToggle={onToggle}
    >
      <Grid container spacing={2} sx={{ alignItems: 'center' }}>
        <Grid size={{ xs: 12, sm: 4 }}>
          <TextField
            select
            label="Intensity"
            size="small"
            fullWidth
            value={config.intensity}
            onChange={(e) => onChange({ intensity: e.target.value as VigoliumAuditConfig['intensity'] })}
            sx={fieldSx}
          >
            {(['quick', 'balanced', 'deep'] as const).map((o) => (
              <MenuItem key={o} value={o}>{o}</MenuItem>
            ))}
          </TextField>
        </Grid>
        <Grid size={{ xs: 6, sm: 3 }}>
          <TextField
            label="Timeout (s)"
            type="number"
            size="small"
            fullWidth
            value={config.timeout}
            onChange={(e) => onChange({ timeout: Math.max(60, Number(e.target.value)) })}
            slotProps={{ htmlInput: { min: 60 } }}
            helperText="Default: 3600 (1 hour)"
            sx={fieldSx}
          />
        </Grid>
        <Grid size={{ xs: 12, sm: 5 }}>
          <FormControlLabel
            control={
              <Checkbox
                checked={config.use_ai}
                size="small"
                onChange={(e) => onChange({ use_ai: e.target.checked })}
                sx={{ color: tokens.accent.primary, '&.Mui-checked': { color: tokens.accent.primary } }}
              />
            }
            label={
              <Typography variant="body2">
                Use AI as audit agent
                <Typography component="span" variant="caption" sx={{ color: 'text.secondary', ml: 1 }}>
                  (requires configured LLM in settings)
                </Typography>
              </Typography>
            }
          />
        </Grid>
      </Grid>
    </SectionCard>
  );
};
