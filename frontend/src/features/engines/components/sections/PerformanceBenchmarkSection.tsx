import React from 'react';
import { Grid, TextField, Typography } from '@mui/material';
import type { PerformanceBenchmarkConfig } from '../../types/engineConfig';
import { SectionCard } from '../shared/SectionCard';
import { getFieldSx } from '../../../../theme/semanticColors';
import { useThemeTokens } from '../../../../theme/useThemeTokens';

interface Props {
  config: PerformanceBenchmarkConfig;
  enabled: boolean;
  onToggle: (v: boolean) => void;
  onChange: (patch: Partial<PerformanceBenchmarkConfig>) => void;
}

export const PerformanceBenchmarkSection: React.FC<Props> = ({
  config, enabled, onToggle, onChange,
}) => {
  const { tokens, isLight } = useThemeTokens();
  const fieldSx = getFieldSx(isLight, tokens);

  return (
    <SectionCard
      title="Performance Benchmark"
      description="Runs Lighthouse against default live endpoints (same Tier 3 wave as screenshots)."
      enabled={enabled}
      onToggle={onToggle}
    >
      <Typography variant="body2" sx={{ color: 'text.secondary', mb: 2 }}>
        Captures performance, accessibility, best-practices, and SEO scores plus Core Web Vitals
        (LCP, FCP, CLS, TTFB). Opt-in — Lighthouse is slower than a screenshot pass.
      </Typography>
      <Grid container spacing={2} sx={{ alignItems: 'center' }}>
        <Grid size={{ xs: 6, sm: 3 }}>
          <TextField
            label="Max URLs"
            type="number"
            size="small"
            fullWidth
            value={config.max_urls}
            onChange={(e) => onChange({ max_urls: Math.max(1, Math.min(50, Number(e.target.value))) })}
            slotProps={{ htmlInput: { min: 1, max: 50 } }}
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
            onChange={(e) => onChange({ timeout: Math.max(15, Math.min(120, Number(e.target.value))) })}
            slotProps={{ htmlInput: { min: 15, max: 120 } }}
            sx={fieldSx}
          />
        </Grid>
      </Grid>
    </SectionCard>
  );
};
