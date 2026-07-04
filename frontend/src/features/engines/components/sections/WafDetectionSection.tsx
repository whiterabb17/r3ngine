import React from 'react';
import { Grid, FormControlLabel, Checkbox, Typography } from '@mui/material';
import type { WafDetectionConfig } from '../../types/engineConfig';
import { SectionCard } from '../shared/SectionCard';
import { useThemeTokens } from '../../../../theme/useThemeTokens';

const BOOL_FIELDS = [
  ['enable_http_crawl', 'Enable HTTP crawl'],
  ['use_shodan', 'Use Shodan for origin IP discovery'],
  ['use_censys', 'Use Censys for origin IP discovery'],
] as const;

interface Props {
  config: WafDetectionConfig;
  enabled: boolean;
  onToggle: (v: boolean) => void;
  onChange: (p: Partial<WafDetectionConfig>) => void;
}

export const WafDetectionSection: React.FC<Props> = ({ config, enabled, onToggle, onChange }) => {
  const { tokens } = useThemeTokens();
  const chkSx = { color: tokens.accent.primary, '&.Mui-checked': { color: tokens.accent.primary } };

  return (
    <SectionCard
      title="WAF Detection"
      description="Detects WAF presence and discovers origin IPs via Shodan/Censys (Tier 5)."
      enabled={enabled}
      onToggle={onToggle}
    >
      <Grid container spacing={1}>
        {BOOL_FIELDS.map(([field, label]) => (
          <Grid key={field} size={{ xs: 12 }}>
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
    </SectionCard>
  );
};
