import React from 'react';
import { Typography } from '@mui/material';
import { SectionCard } from '../shared/SectionCard';

interface Props {
  enabled: boolean;
  onToggle: (v: boolean) => void;
}

export const ScreenshotSection: React.FC<Props> = ({ enabled, onToggle }) => (
  <SectionCard
    title="Screenshot"
    description="Captures screenshots of discovered endpoints. Runs in parallel at Tier 2."
    enabled={enabled}
    onToggle={onToggle}
  >
    <Typography variant="body2" sx={{ color: 'text.secondary' }}>
      Takes a screenshot of every live HTTP endpoint so you can review them visually. No additional settings.
    </Typography>
  </SectionCard>
);
