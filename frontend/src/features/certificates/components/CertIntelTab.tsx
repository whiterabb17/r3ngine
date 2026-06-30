import React from 'react';
import {
  Box, Typography, CircularProgress, Chip, Stack, Tooltip,
} from '@mui/material';
import { ShieldAlert, ShieldCheck, Clock, AlertTriangle } from 'lucide-react';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import { useCertificates, type CertificateRecord } from '../api/useCertificates';

interface CertIntelTabProps {
  scanId: number;
}

function CertRiskChips({ cert }: { cert: CertificateRecord }) {
  const { tokens } = useThemeTokens();
  return (
    <Stack direction="row" spacing={0.5} sx={{ flexWrap: 'wrap', gap: 0.5 }}>
      {cert.is_expired && (
        <Chip
          size="small"
          label="EXPIRED"
          icon={<Clock size={12} />}
          sx={{ bgcolor: `${tokens.accent.error}15`, color: tokens.accent.error, fontWeight: 700, fontSize: '0.6rem' }}
        />
      )}
      {cert.self_signed && (
        <Chip
          size="small"
          label="SELF-SIGNED"
          icon={<ShieldAlert size={12} />}
          sx={{ bgcolor: `${tokens.accent.warning}15`, color: tokens.accent.warning, fontWeight: 700, fontSize: '0.6rem' }}
        />
      )}
      {cert.has_weak_cipher && (
        <Chip
          size="small"
          label="WEAK CIPHER"
          icon={<AlertTriangle size={12} />}
          sx={{ bgcolor: `${tokens.accent.warning}15`, color: tokens.accent.warning, fontWeight: 700, fontSize: '0.6rem' }}
        />
      )}
      {cert.mismatched && (
        <Chip
          size="small"
          label="MISMATCHED"
          sx={{ bgcolor: `${tokens.accent.error}15`, color: tokens.accent.error, fontWeight: 700, fontSize: '0.6rem' }}
        />
      )}
      {!cert.is_expired && !cert.self_signed && !cert.has_weak_cipher && !cert.mismatched && (
        <Chip
          size="small"
          label="CLEAN"
          icon={<ShieldCheck size={12} />}
          sx={{ bgcolor: `${tokens.accent.success}15`, color: tokens.accent.success, fontWeight: 700, fontSize: '0.6rem' }}
        />
      )}
    </Stack>
  );
}

export const CertIntelTab: React.FC<CertIntelTabProps> = ({ scanId }) => {
  const { data, isLoading, isError } = useCertificates(scanId);
  const { tokens, isLight } = useThemeTokens();

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
        Failed to load certificate intelligence.
      </Typography>
    );
  }

  if (data.count === 0) {
    return (
      <Box sx={{ p: 4, textAlign: 'center' }}>
        <ShieldCheck size={32} style={{ opacity: 0.4 }} />
        <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
          No certificate intelligence collected for this scan.
        </Typography>
      </Box>
    );
  }

  const riskyCount = data.results.filter(
    c => c.is_expired || c.self_signed || c.has_weak_cipher || c.mismatched
  ).length;

  return (
    <Box>
      <Box
        sx={{
          mb: 3, p: 2, borderRadius: 1.5,
          bgcolor: isLight ? 'rgba(0,0,0,0.02)' : 'rgba(0,0,0,0.25)',
          border: 1, borderColor: 'divider',
          display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 2,
        }}
      >
        {[
          { label: 'TOTAL', value: data.count, color: tokens.accent.info },
          { label: 'ISSUES', value: riskyCount, color: tokens.accent.error },
          { label: 'CLEAN', value: data.count - riskyCount, color: tokens.accent.success },
        ].map(stat => (
          <Box key={stat.label} sx={{ textAlign: 'center' }}>
            <Typography sx={{ fontSize: '1.1rem', fontWeight: 900, color: stat.color, fontFamily: 'Orbitron' }}>
              {stat.value}
            </Typography>
            <Typography sx={{ fontSize: '0.55rem', color: 'text.disabled', fontWeight: 700, letterSpacing: 0.5 }}>
              {stat.label}
            </Typography>
          </Box>
        ))}
      </Box>

      <Stack spacing={1.5}>
        {data.results.map(cert => (
          <Box
            key={cert.id}
            sx={{
              p: 2, border: 1,
              borderColor: (cert.is_expired || cert.mismatched) ? tokens.accent.error :
                           (cert.has_weak_cipher || cert.self_signed) ? tokens.accent.warning :
                           'divider',
              borderRadius: 1.5,
              bgcolor: 'background.paper',
            }}
          >
            <Stack direction="row" sx={{ justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <Box>
                <Typography variant="body2" sx={{ fontWeight: 700, fontFamily: 'monospace' }}>
                  {cert.host}:{cert.port}
                </Typography>
                {cert.subject_cn && (
                  <Typography variant="caption" color="text.secondary">
                    CN: {cert.subject_cn}
                  </Typography>
                )}
              </Box>
              <CertRiskChips cert={cert} />
            </Stack>

            <Stack direction="row" spacing={2} sx={{ mt: 1 }}>
              {cert.issuer_cn && (
                <Typography variant="caption" color="text.disabled">
                  Issuer: {cert.issuer_cn}
                </Typography>
              )}
              {cert.tls_version && (
                <Typography variant="caption" color="text.disabled">
                  TLS: {cert.tls_version.toUpperCase()}
                </Typography>
              )}
              {cert.not_after && (
                <Tooltip title={`Expires: ${new Date(cert.not_after).toLocaleDateString()}`}>
                  <Typography variant="caption" color={cert.is_expired ? tokens.accent.error : 'text.disabled'}>
                    Exp: {new Date(cert.not_after).toLocaleDateString()}
                  </Typography>
                </Tooltip>
              )}
            </Stack>

            {cert.cipher && (
              <Typography
                variant="caption"
                sx={{
                  display: 'block', mt: 0.5, fontFamily: 'monospace', fontSize: '0.65rem',
                  color: cert.has_weak_cipher ? tokens.accent.warning : 'text.disabled',
                }}
              >
                {cert.cipher}
              </Typography>
            )}
          </Box>
        ))}
      </Stack>
    </Box>
  );
};
