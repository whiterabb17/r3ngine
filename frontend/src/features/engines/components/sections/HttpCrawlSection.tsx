import React from 'react';
import { Grid, TextField, FormControlLabel, Checkbox, Typography } from '@mui/material';
import type { HttpCrawlConfig } from '../../types/engineConfig';
import { SectionCard } from '../shared/SectionCard';
import { getFieldSx } from '../../../../theme/semanticColors';
import { useThemeTokens } from '../../../../theme/useThemeTokens';

interface Props {
  config: HttpCrawlConfig;
  enabled: boolean;
  onToggle: (v: boolean) => void;
  onChange: (patch: Partial<HttpCrawlConfig>) => void;
}

export const HttpCrawlSection: React.FC<Props> = ({ config, enabled, onToggle, onChange }) => {
  const { tokens, isLight } = useThemeTokens();
  const fieldSx = getFieldSx(isLight, tokens);

  return (
    <SectionCard
      title="HTTP Crawl"
      description="Probes discovered subdomains and populates the endpoint DB. Required for Tier 3+."
      enabled={enabled}
      onToggle={onToggle}
    >
      <Grid container spacing={2} sx={{ alignItems: 'center' }}>
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
        <Grid size={{ xs: 12, sm: 6 }}>
          <FormControlLabel
            control={
              <Checkbox
                checked={config.follow_redirect}
                size="small"
                onChange={(e) => onChange({ follow_redirect: e.target.checked })}
                sx={{ color: tokens.accent.primary, '&.Mui-checked': { color: tokens.accent.primary } }}
              />
            }
            label={<Typography variant="body2">Follow redirects</Typography>}
          />
        </Grid>
      </Grid>
    </SectionCard>
  );
};
