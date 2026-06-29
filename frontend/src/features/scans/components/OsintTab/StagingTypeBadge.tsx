import React from 'react';
import { Chip } from '@mui/material';
import {
  ShieldCheck, Globe, Mail, User, Phone, Share2, Server,
  Cpu, AlertTriangle, Cloud, Network, Database, Bitcoin,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

interface BadgeConfig {
  color: string;
  icon: LucideIcon;
  label: string;
}

const BADGE_CONFIG: Record<string, BadgeConfig> = {
  SSL:       { color: '#00bcd4', icon: ShieldCheck,   label: 'SSL' },
  DNS:       { color: '#3f51b5', icon: Globe,         label: 'DNS' },
  Email:     { color: '#00ff62', icon: Mail,          label: 'Email' },
  Employee:  { color: '#9c27b0', icon: User,          label: 'Employee' },
  Phone:     { color: '#ff9800', icon: Phone,         label: 'Phone' },
  Social:    { color: '#e91e63', icon: Share2,        label: 'Social' },
  IP:        { color: '#f44336', icon: Server,        label: 'IP' },
  Port:      { color: '#f44336', icon: Server,        label: 'Port' },
  Tech:      { color: '#fffc00', icon: Cpu,           label: 'Tech' },
  OS:        { color: '#fffc00', icon: Cpu,           label: 'OS' },
  Leak:      { color: '#ff5722', icon: AlertTriangle, label: 'Leak' },
  Crypto:    { color: '#ffc107', icon: Bitcoin,       label: 'Crypto' },
  Hosting:   { color: '#607d8b', icon: Cloud,         label: 'Hosting' },
  Subdomain: { color: '#00f3ff', icon: Network,       label: 'Subdomain' },
};

const DEFAULT_CONFIG: BadgeConfig = {
  color: 'rgba(255,255,255,0.3)',
  icon: Database,
  label: 'Other',
};

interface StagingTypeBadgeProps {
  osintType: string;
}

export const StagingTypeBadge: React.FC<StagingTypeBadgeProps> = ({ osintType }) => {
  const config = BADGE_CONFIG[osintType] ?? DEFAULT_CONFIG;
  const Icon = config.icon;

  return (
    <Chip
      icon={<Icon size={10} color={config.color} />}
      label={config.label}
      size="small"
      sx={{
        fontSize: '10px',
        height: 18,
        fontWeight: 800,
        bgcolor: 'action.hover',
        color: config.color,
        border: `1px solid ${config.color}40`,
        borderLeft: `3px solid ${config.color}`,
        textTransform: 'uppercase',
        '& .MuiChip-icon': { marginLeft: '6px' },
      }}
    />
  );
};
