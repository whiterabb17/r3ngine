import React from 'react';
import { Typography } from '@mui/material';
import { SectionCard } from '../shared/SectionCard';

interface Props {
  enabled: boolean;
  onToggle: (v: boolean) => void;
}

export const DnsSecuritySection: React.FC<Props> = ({ enabled, onToggle }) => (
  <SectionCard
    title="DNS Security"
    description="DNS misconfiguration and takeover detection."
    enabled={enabled}
    onToggle={onToggle}
  >
    <Typography variant="body2" sx={{ color: 'text.secondary' }}>
      No additional configuration — enabling this section runs DNS security checks after subdomain discovery.
    </Typography>
  </SectionCard>
);
