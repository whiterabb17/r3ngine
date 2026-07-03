import React from 'react';
import { Box, Grid, TextField, MenuItem, FormControlLabel, Checkbox, Typography } from '@mui/material';
import type { GlobalConfig } from '../../types/engineConfig';
import { TagInput } from '../shared/TagInput';
import { getFieldSx } from '../../../../theme/semanticColors';
import { useThemeTokens } from '../../../../theme/useThemeTokens';

interface GlobalSettingsSectionProps {
  config: GlobalConfig;
  onChange: (patch: Partial<GlobalConfig>) => void;
}

const INTENSITY_OPTIONS = ['normal', 'aggressive', 'light'] as const;

export const GlobalSettingsSection: React.FC<GlobalSettingsSectionProps> = ({ config, onChange }) => {
  const { tokens, isLight } = useThemeTokens();
  const fieldSx = getFieldSx(isLight, tokens);

  return (
    <Box>
      <Typography variant="body2" sx={{ color: 'text.secondary', mb: 2 }}>
        These values apply as defaults across all tools. Individual sections can override them.
      </Typography>

      <Grid container spacing={2}>
        <Grid size={{ xs: 6, sm: 3 }}>
          <TextField
            label="Threads"
            type="number"
            size="small"
            fullWidth
            value={config.threads}
            onChange={(e) => onChange({ threads: Math.max(1, Math.min(100, Number(e.target.value))) })}
            slotProps={{ htmlInput: { min: 1, max: 100 } }}
            sx={fieldSx}
          />
        </Grid>
        <Grid size={{ xs: 6, sm: 3 }}>
          <TextField
            label="Timeout (s)"
            type="number"
            size="small"
            fullWidth
            value={config.timeout}
            onChange={(e) => onChange({ timeout: Math.max(1, Math.min(300, Number(e.target.value))) })}
            slotProps={{ htmlInput: { min: 1, max: 300 } }}
            sx={fieldSx}
          />
        </Grid>
        <Grid size={{ xs: 6, sm: 3 }}>
          <TextField
            label="Rate Limit (req/s)"
            type="number"
            size="small"
            fullWidth
            value={config.rate_limit}
            onChange={(e) => onChange({ rate_limit: Math.max(1, Math.min(500, Number(e.target.value))) })}
            slotProps={{ htmlInput: { min: 1, max: 500 } }}
            sx={fieldSx}
          />
        </Grid>
        <Grid size={{ xs: 6, sm: 3 }}>
          <TextField
            label="Retries"
            type="number"
            size="small"
            fullWidth
            value={config.retries}
            onChange={(e) => onChange({ retries: Math.max(0, Math.min(10, Number(e.target.value))) })}
            slotProps={{ htmlInput: { min: 0, max: 10 } }}
            sx={fieldSx}
          />
        </Grid>
        <Grid size={{ xs: 12, sm: 6 }}>
          <TextField
            select
            label="Intensity"
            size="small"
            fullWidth
            value={config.intensity}
            onChange={(e) => onChange({ intensity: e.target.value as GlobalConfig['intensity'] })}
            sx={fieldSx}
          >
            {INTENSITY_OPTIONS.map((o) => (
              <MenuItem key={o} value={o}>{o}</MenuItem>
            ))}
          </TextField>
        </Grid>
        <Grid size={{ xs: 12, sm: 6 }}>
          <FormControlLabel
            control={
              <Checkbox
                checked={config.enable_http_crawl}
                onChange={(e) => onChange({ enable_http_crawl: e.target.checked })}
                size="small"
                sx={{ color: tokens.accent.primary, '&.Mui-checked': { color: tokens.accent.primary } }}
              />
            }
            label={
              <Typography variant="body2">
                Enable HTTP crawl globally
                <Typography component="span" variant="caption" sx={{ color: 'text.secondary', ml: 1 }}>
                  (default for all tools)
                </Typography>
              </Typography>
            }
          />
        </Grid>
        <Grid size={{ xs: 12 }}>
          <TagInput
            label="Custom Headers"
            value={config.custom_headers}
            onChange={(v) => onChange({ custom_headers: v })}
            placeholder="e.g. X-Foo: bar"
            helperText="Applied to FFUF, Nuclei, Dalfox, HTTP Crawl, and Fetch URL"
          />
        </Grid>
      </Grid>
    </Box>
  );
};
