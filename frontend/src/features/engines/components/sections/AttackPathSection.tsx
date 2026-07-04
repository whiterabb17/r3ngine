import React from 'react';
import { Grid, TextField } from '@mui/material';
import type { AttackPathConfig } from '../../types/engineConfig';
import { SectionCard } from '../shared/SectionCard';
import { getFieldSx } from '../../../../theme/semanticColors';
import { useThemeTokens } from '../../../../theme/useThemeTokens';

interface Props {
  config: AttackPathConfig;
  enabled: boolean;
  onToggle: (v: boolean) => void;
  onChange: (p: Partial<AttackPathConfig>) => void;
}

export const AttackPathSection: React.FC<Props> = ({ config, enabled, onToggle, onChange }) => {
  const { tokens, isLight } = useThemeTokens();
  const fieldSx = getFieldSx(isLight, tokens);

  return (
    <SectionCard
      title="Attack Path Modeling"
      description="Builds attack paths from scan results using Neo4j graph analysis (Tier 7)."
      enabled={enabled}
      onToggle={onToggle}
    >
      <Grid container spacing={2}>
        <Grid size={{ xs: 6, sm: 3 }}>
          <TextField
            label="Top N Paths"
            type="number"
            size="small"
            fullWidth
            value={config.top_n}
            onChange={(e) => onChange({ top_n: Math.max(1, Math.min(20, Number(e.target.value))) })}
            slotProps={{ htmlInput: { min: 1, max: 20 } }}
            helperText="Number of attack paths to surface"
            sx={fieldSx}
          />
        </Grid>
      </Grid>
    </SectionCard>
  );
};
