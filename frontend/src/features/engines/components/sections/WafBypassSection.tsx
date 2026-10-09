import React from 'react';
import { FormControlLabel, Checkbox, Typography, Box } from '@mui/material';
import type { WafBypassConfig } from '../../types/engineConfig';
import { SectionCard } from '../shared/SectionCard';
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
  const { tokens } = useThemeTokens();
  const chkSx = { color: tokens.accent.primary, '&.Mui-checked': { color: tokens.accent.primary } };

  return (
    <SectionCard
      title="WAF Bypass"
      description="Tests header manipulation and Nuclei bypass templates (Tier 5)."
      enabled={enabled}
      onToggle={onToggle}
    >
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
    </SectionCard>
  );
};
