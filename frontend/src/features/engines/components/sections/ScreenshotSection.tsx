import React from 'react';
import { Grid, TextField, MenuItem, FormControlLabel, Checkbox, Typography } from '@mui/material';
import type { ScreenshotConfig } from '../../types/engineConfig';
import { SectionCard } from '../shared/SectionCard';
import { getFieldSx } from '../../../../theme/semanticColors';
import { useThemeTokens } from '../../../../theme/useThemeTokens';

const INTENSITY_OPTIONS: ScreenshotConfig['intensity'][] = ['normal', 'aggressive', 'light'];

interface Props {
  config: ScreenshotConfig;
  enabled: boolean;
  onToggle: (v: boolean) => void;
  onChange: (patch: Partial<ScreenshotConfig>) => void;
}

export const ScreenshotSection: React.FC<Props> = ({ config, enabled, onToggle, onChange }) => {
  const { tokens, isLight } = useThemeTokens();
  const fieldSx = getFieldSx(isLight, tokens);

  return (
    <SectionCard
      title="Screenshot"
      description="Captures screenshots of discovered endpoints. Runs in parallel at Tier 2."
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
            onChange={(e) => onChange({ intensity: e.target.value as ScreenshotConfig['intensity'] })}
            sx={fieldSx}
          >
            {INTENSITY_OPTIONS.map((o) => (
              <MenuItem key={o} value={o}>
                {o}
              </MenuItem>
            ))}
          </TextField>
        </Grid>
        <Grid size={{ xs: 6, sm: 2 }}>
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
        <Grid size={{ xs: 6, sm: 2 }}>
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
        <Grid size={{ xs: 12, sm: 4 }}>
          <FormControlLabel
            control={
              <Checkbox
                checked={config.enable_http_crawl}
                size="small"
                onChange={(e) => onChange({ enable_http_crawl: e.target.checked })}
                sx={{ color: tokens.accent.primary, '&.Mui-checked': { color: tokens.accent.primary } }}
              />
            }
            label={<Typography variant="body2">Enable HTTP crawl</Typography>}
          />
        </Grid>
      </Grid>
    </SectionCard>
  );
};
