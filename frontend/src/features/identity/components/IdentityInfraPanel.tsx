import React from 'react';
import {
  Box, Typography, CircularProgress, Chip, Stack, LinearProgress, Tooltip,
} from '@mui/material';
import { Server, Shield, AlertTriangle, Key, Mail, Globe, Lock } from 'lucide-react';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import { useIdentityInfra, type IdentityRecord } from '../api/useIdentityInfra';

interface IdentityInfraPanelProps {
  scanId: number;
  projectSlug?: string;
}

const INFRA_ICONS: Record<string, React.ReactNode> = {
  adfs: <Shield size={14} />,
  owa: <Mail size={14} />,
  exchange: <Mail size={14} />,
  ldap: <Server size={14} />,
  sso: <Key size={14} />,
  saml_idp: <Globe size={14} />,
  vpn_portal: <Lock size={14} />,
  ntlm_endpoint: <AlertTriangle size={14} />,
  generic_auth_portal: <Globe size={14} />,
};

const INFRA_LABELS: Record<string, string> = {
  adfs: 'ADFS',
  owa: 'OWA',
  exchange: 'Exchange',
  ldap: 'LDAP',
  sso: 'SSO Portal',
  saml_idp: 'SAML IdP',
  vpn_portal: 'VPN Portal',
  ntlm_endpoint: 'NTLM',
  generic_auth_portal: 'Auth Portal',
};

type RiskLevel = 'error' | 'warning' | 'info';

const INFRA_RISK: Record<string, RiskLevel> = {
  adfs: 'error',
  ldap: 'error',
  ntlm_endpoint: 'error',
  exchange: 'warning',
  owa: 'warning',
  saml_idp: 'warning',
  vpn_portal: 'info',
  sso: 'info',
  generic_auth_portal: 'info',
};

function ConfidenceBar({ value }: { value: number }) {
  const { tokens } = useThemeTokens();
  const barColor = value > 0.8
    ? tokens.accent.error
    : value > 0.6
    ? tokens.accent.warning
    : tokens.accent.info;

  return (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mt: 0.5 }}>
      <LinearProgress
        variant="determinate"
        value={value * 100}
        sx={{
          flexGrow: 1,
          height: 4,
          borderRadius: 2,
          bgcolor: 'action.disabledBackground',
          '& .MuiLinearProgress-bar': { bgcolor: barColor },
        }}
      />
      <Typography variant="caption" sx={{ fontSize: '0.6rem', color: 'text.disabled', minWidth: 28 }}>
        {Math.round(value * 100)}%
      </Typography>
    </Box>
  );
}

function IdentityCard({ record }: { record: IdentityRecord }) {
  const { tokens } = useThemeTokens();
  const risk = INFRA_RISK[record.infra_type] || 'info';
  const accentColor =
    risk === 'error' ? tokens.accent.error :
    risk === 'warning' ? tokens.accent.warning :
    tokens.accent.info;

  return (
    <Box
      sx={{
        p: 2,
        border: `1px solid ${accentColor}40`,
        borderLeft: `3px solid ${accentColor}`,
        borderRadius: 1.5,
        bgcolor: 'background.paper',
      }}
    >
      <Stack direction="row" sx={{ justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }}>
          <Box sx={{ color: accentColor }}>
            {INFRA_ICONS[record.infra_type] ?? <Globe size={14} />}
          </Box>
          <Box>
            <Typography variant="body2" sx={{ fontWeight: 700, fontFamily: 'monospace' }}>
              {record.host}
            </Typography>
            {record.url && (
              <Typography
                variant="caption"
                sx={{ color: 'text.disabled', fontFamily: 'monospace', fontSize: '0.65rem' }}
              >
                {record.url}
              </Typography>
            )}
          </Box>
        </Stack>
        <Stack direction="row" spacing={0.5}>
          <Chip
            size="small"
            label={INFRA_LABELS[record.infra_type] ?? record.infra_type.toUpperCase()}
            sx={{
              bgcolor: `${accentColor}15`,
              color: accentColor,
              fontWeight: 700,
              fontSize: '0.6rem',
              height: 18,
            }}
          />
          {record.is_externally_accessible && (
            <Tooltip title="Externally accessible">
              <Chip
                size="small"
                label="EXT"
                sx={{
                  bgcolor: `${tokens.accent.error}15`,
                  color: tokens.accent.error,
                  fontWeight: 700,
                  fontSize: '0.6rem',
                  height: 18,
                }}
              />
            </Tooltip>
          )}
        </Stack>
      </Stack>

      <Stack direction="row" sx={{ justifyContent: 'space-between', alignItems: 'center', mt: 1 }}>
        <Typography
          variant="caption"
          color="text.disabled"
          sx={{ fontSize: '0.65rem', textTransform: 'uppercase' }}
        >
          {record.detection_method.replace(/_/g, ' ')}
        </Typography>
        <Box sx={{ width: 120 }}>
          <ConfidenceBar value={record.confidence_score} />
        </Box>
      </Stack>
    </Box>
  );
}

export const IdentityInfraPanel: React.FC<IdentityInfraPanelProps> = ({ scanId, projectSlug }) => {
  const { data, isLoading, isError } = useIdentityInfra(scanId, projectSlug);
  const { tokens } = useThemeTokens();

  if (isLoading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
        <CircularProgress size={24} />
      </Box>
    );
  }

  if (isError || !data) {
    return (
      <Typography color="error" sx={{ p: 2 }}>
        Failed to load identity infrastructure data.
      </Typography>
    );
  }

  if (data.count === 0) {
    return (
      <Box sx={{ p: 4, textAlign: 'center' }}>
        <Shield size={32} style={{ opacity: 0.4 }} />
        <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
          No identity infrastructure detected for this scan.
        </Typography>
      </Box>
    );
  }

  const highRisk = data.results.filter(r =>
    ['adfs', 'ldap', 'ntlm_endpoint'].includes(r.infra_type)
  ).length;

  return (
    <Box>
      <Box
        sx={{
          mb: 2.5, p: 2, borderRadius: 1.5,
          bgcolor: 'rgba(0,0,0,0.03)', border: 1, borderColor: 'divider',
          display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 2,
        }}
      >
        {[
          { label: 'TOTAL', value: data.count, color: tokens.accent.primary },
          { label: 'HIGH RISK', value: highRisk, color: tokens.accent.error },
          { label: 'TYPES', value: Object.keys(data.summary).length, color: tokens.accent.info },
        ].map(stat => (
          <Box key={stat.label} sx={{ textAlign: 'center' }}>
            <Typography
              sx={{ fontSize: '1.1rem', fontWeight: 900, color: stat.color, fontFamily: 'Orbitron' }}
            >
              {stat.value}
            </Typography>
            <Typography
              sx={{ fontSize: '0.55rem', color: 'text.disabled', fontWeight: 700, letterSpacing: 0.5 }}
            >
              {stat.label}
            </Typography>
          </Box>
        ))}
      </Box>

      <Stack direction="row" spacing={0.75} sx={{ mb: 2, flexWrap: 'wrap', gap: 0.75 }}>
        {Object.entries(data.summary).map(([type, count]) => {
          const risk = INFRA_RISK[type] || 'info';
          const chipColor = risk === 'error' ? tokens.accent.error : tokens.accent.warning;
          return (
            <Chip
              key={type}
              size="small"
              label={`${INFRA_LABELS[type] ?? type}: ${count}`}
              icon={<Box sx={{ display: 'flex' }}>{INFRA_ICONS[type]}</Box>}
              sx={{ bgcolor: `${chipColor}12`, fontSize: '0.65rem', height: 22 }}
            />
          );
        })}
      </Stack>

      <Stack spacing={1.25}>
        {data.results.map(record => (
          <IdentityCard key={record.id} record={record} />
        ))}
      </Stack>
    </Box>
  );
};
