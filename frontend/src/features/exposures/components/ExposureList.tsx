import React, { useState } from 'react';
import { Box, Grid, Typography, CircularProgress, Chip, Stack } from '@mui/material';
import { useExposures } from '../api/useExposures';
import { ExposureCard } from './ExposureCard';
import type { Exposure } from '../types';
import { useThemeTokens } from '@/theme/useThemeTokens';
import { ExposureDetailsDrawer } from './ExposureDetailsDrawer';

const STATUS_ORDER = ['open', 'verified', 'remediated', 'false_positive'] as const;
const STATUS_LABELS: Record<string, string> = {
  open: 'OPEN',
  verified: 'VERIFIED',
  remediated: 'REMEDIATED',
  false_positive: 'FALSE POS',
};

interface StatsBarProps {
  exposures: Exposure[];
}

const ExposureStatsBar: React.FC<StatsBarProps> = ({ exposures }) => {
  const { tokens, isLight } = useThemeTokens();
  const counts = STATUS_ORDER.reduce<Record<string, number>>((acc, s) => {
    acc[s] = exposures.filter((e) => e.status === s).length;
    return acc;
  }, {});
  const highRisk = exposures.filter((e) => e.risk_score >= 7).length;
  const statColor = (s: string) =>
    s === 'open' ? tokens.accent.error :
    s === 'verified' ? tokens.accent.warning :
    s === 'remediated' ? tokens.accent.success :
    tokens.accent.info;

  return (
    <Box
      sx={{
        mb: 3,
        p: 2,
        borderRadius: 1.5,
        bgcolor: isLight ? 'rgba(0,0,0,0.02)' : 'rgba(0,0,0,0.25)',
        border: 1,
        borderColor: 'divider',
        display: 'grid',
        gridTemplateColumns: 'repeat(5, 1fr)',
        gap: 2,
      }}
    >
      {STATUS_ORDER.map((s) => (
        <Box key={s} sx={{ textAlign: 'center' }}>
          <Typography sx={{ fontSize: '1.1rem', fontWeight: 900, color: statColor(s), fontFamily: 'Orbitron' }}>
            {counts[s]}
          </Typography>
          <Typography sx={{ fontSize: '0.55rem', color: 'text.disabled', fontWeight: 700, letterSpacing: 0.5 }}>
            {STATUS_LABELS[s]}
          </Typography>
        </Box>
      ))}
      <Box sx={{ textAlign: 'center', borderLeft: 1, borderColor: 'divider', pl: 2 }}>
        <Typography sx={{ fontSize: '1.1rem', fontWeight: 900, color: tokens.accent.error, fontFamily: 'Orbitron' }}>
          {highRisk}
        </Typography>
        <Typography sx={{ fontSize: '0.55rem', color: 'text.disabled', fontWeight: 700, letterSpacing: 0.5 }}>
          HIGH RISK
        </Typography>
      </Box>
    </Box>
  );
};

interface ExposureListProps {
  scan_id?: string;
  target_id?: string;
}

export const ExposureList: React.FC<ExposureListProps> = ({ scan_id, target_id }) => {
  const [selectedExposure, setSelectedExposure] = useState<Exposure | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const { tokens } = useThemeTokens();

  const { data, isLoading, error } = useExposures({
    scan_history: scan_id,
    target_id,
  });

  if (isLoading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Typography color="error" sx={{ p: 2 }}>
        Error loading exposures. Please try again.
      </Typography>
    );
  }

  const exposures = data?.results || [];
  const filteredExposures = statusFilter === 'all'
    ? exposures
    : exposures.filter((e) => e.status === statusFilter);

  return (
    <Box>
      {exposures.length > 0 && <ExposureStatsBar exposures={exposures} />}

      {exposures.length > 0 && (
        <Stack direction="row" spacing={1} sx={{ mb: 2, flexWrap: 'wrap', gap: 1 }}>
          {(['all', 'open', 'verified', 'remediated', 'false_positive'] as const).map((s) => (
            <Chip
              key={s}
              label={s === 'all' ? `ALL (${exposures.length})` : STATUS_LABELS[s]}
              size="small"
              onClick={() => setStatusFilter(s)}
              variant={statusFilter === s ? 'filled' : 'outlined'}
              sx={{
                height: 22,
                fontSize: '0.6rem',
                fontWeight: 700,
                fontFamily: 'Orbitron',
                cursor: 'pointer',
                ...(statusFilter === s && {
                  bgcolor: tokens.surface.secondary,
                  color: 'text.primary',
                }),
              }}
            />
          ))}
        </Stack>
      )}

      {exposures.length === 0 ? (
        <Box sx={{ p: 4, textAlign: 'center' }}>
          <Typography variant="body1" sx={{ color: 'text.secondary' }}>
            No exposures detected for this target/scan.
          </Typography>
        </Box>
      ) : (
        <Grid container spacing={3}>
          {filteredExposures.map((exposure) => (
            <Grid size={{ xs: 12, sm: 6, md: 4 }} key={exposure.id}>
              <ExposureCard exposure={exposure} onClick={(exp) => setSelectedExposure(exp)} />
            </Grid>
          ))}
        </Grid>
      )}

      {selectedExposure && (
        <ExposureDetailsDrawer exposure={selectedExposure} onClose={() => setSelectedExposure(null)} />
      )}
    </Box>
  );
};
