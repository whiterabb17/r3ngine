import React from 'react';
import { Box, Typography, Slider } from '@mui/material';
import type { ParamDiscoveryConfig } from '../../types/engineConfig';
import { SectionCard } from '../shared/SectionCard';
import { useThemeTokens } from '../../../../theme/useThemeTokens';

interface Props {
  config: ParamDiscoveryConfig;
  enabled: boolean;
  onToggle: (v: boolean) => void;
  onChange: (patch: Partial<ParamDiscoveryConfig>) => void;
}

export const ParamDiscoverySection: React.FC<Props> = ({ config, enabled, onToggle, onChange }) => {
  const { tokens } = useThemeTokens();

  return (
    <SectionCard
      title="Parameter Discovery"
      description="Custom Parameter Discovery Engine (CPDE) — reads kiterunner/arjun output (Tier 3c)."
      enabled={enabled}
      onToggle={onToggle}
    >
      <Box sx={{ px: 1 }}>
        <Typography variant="body2" sx={{ mb: 1 }}>
          Minimum Confidence: <strong>{config.min_confidence}%</strong>
        </Typography>
        <Slider
          value={config.min_confidence}
          onChange={(_, v) => onChange({ min_confidence: v as number })}
          min={0}
          max={100}
          step={5}
          sx={{ color: tokens.accent.primary, maxWidth: 320 }}
        />
        <Typography variant="caption" sx={{ color: 'text.secondary' }}>
          Parameters below this confidence threshold are excluded from results.
        </Typography>
      </Box>
    </SectionCard>
  );
};
