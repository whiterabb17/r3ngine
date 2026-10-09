import React from 'react';
import { Box, Checkbox, FormControlLabel, Grid, TextField, Typography } from '@mui/material';
import type { DnsSecurityConfig } from '../../types/engineConfig';
import { SectionCard } from '../shared/SectionCard';
import { getFieldSx } from '../../../../theme/semanticColors';
import { useThemeTokens } from '../../../../theme/useThemeTokens';

const BOOL_FIELDS = [
  ['enable_axfr', 'Zone transfer (AXFR) check'],
  ['enable_dnssec_check', 'DNSSEC validation'],
  ['enable_dns_brute', 'DNS brute force'],
] as const;

interface Props {
  config: DnsSecurityConfig;
  enabled: boolean;
  onToggle: (v: boolean) => void;
  onChange: (p: Partial<DnsSecurityConfig>) => void;
}

export const DnsSecuritySection: React.FC<Props> = ({ config, enabled, onToggle, onChange }) => {
  const { tokens, isLight } = useThemeTokens();
  const fieldSx = getFieldSx(isLight, tokens);
  const chkSx = { color: tokens.accent.primary, '&.Mui-checked': { color: tokens.accent.primary } };

  return (
    <SectionCard
      title="DNS Security"
      description="DNS misconfiguration and takeover detection, run after subdomain discovery."
      enabled={enabled}
      onToggle={onToggle}
    >
      <Grid container spacing={2} sx={{ alignItems: 'center' }}>
        <Grid size={{ xs: 12, sm: 8 }}>
          <Box sx={{ display: 'flex', flexWrap: 'wrap' }}>
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
          </Box>
        </Grid>
        <Grid size={{ xs: 12, sm: 4 }}>
          <TextField
            label="Amplification threshold"
            type="number"
            size="small"
            fullWidth
            value={config.amplification_threshold}
            onChange={(e) => onChange({ amplification_threshold: Math.max(1, Number(e.target.value) || 1) })}
            slotProps={{ htmlInput: { min: 1 } }}
            helperText="Response/query size ratio that flags a resolver as an amplifier"
            sx={fieldSx}
          />
        </Grid>
      </Grid>
    </SectionCard>
  );
};
