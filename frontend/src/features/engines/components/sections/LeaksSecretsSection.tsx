import React from 'react';
import { Grid, FormControlLabel, Checkbox, Typography } from '@mui/material';
import type { LeaksSecretsConfig } from '../../types/engineConfig';
import { SectionCard } from '../shared/SectionCard';
import { useThemeTokens } from '../../../../theme/useThemeTokens';

const BOOL_FIELDS = [
  ['gitleaks', 'Gitleaks — scan JS files for secrets'],
  ['trufflehog', 'TruffleHog — scan JS files for secrets'],
  ['leaklookup', 'LeakLookup — query leak-lookup.com API for domain leaks'],
] as const;

interface Props {
  config: LeaksSecretsConfig;
  enabled: boolean;
  onToggle: (v: boolean) => void;
  onChange: (p: Partial<LeaksSecretsConfig>) => void;
}

export const LeaksSecretsSection: React.FC<Props> = ({ config, enabled, onToggle, onChange }) => {
  const { tokens } = useThemeTokens();
  const chkSx = { color: tokens.accent.primary, '&.Mui-checked': { color: tokens.accent.primary } };

  return (
    <SectionCard
      title="Leaks & Secrets"
      description="Secret scanning on discovered JS files and domain leak lookups (Tier 5)."
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
