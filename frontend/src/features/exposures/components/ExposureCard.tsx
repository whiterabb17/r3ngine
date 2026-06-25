import React, { useState } from 'react';
import { Box, Typography, Button, Chip, Stack, Snackbar, Alert } from '@mui/material';
import type { Exposure } from '../types';
import { useThemeTokens } from '@/theme/useThemeTokens';
import { useMutateExposureStatus } from '../api/useExposures';

function deriveAssetSummary(evidence: Exposure['evidence']): string | null {
  if (!evidence || evidence.length === 0) return null;
  const d = evidence[0].evidence_data;
  return (d?.url ?? d?.name ?? d?.host ?? d?.value ?? d?.target) as string | null ?? null;
}

interface ExposureCardProps {
  exposure: Exposure;
  onClick: (exposure: Exposure) => void;
}

export const ExposureCard: React.FC<ExposureCardProps> = ({ exposure, onClick }) => {
  const { tokens } = useThemeTokens();
  const [snackbar, setSnackbar] = useState<{
    open: boolean;
    message: string;
    severity: 'success' | 'error';
  }>({ open: false, message: '', severity: 'success' });

  const mutateStatus = useMutateExposureStatus(
    () => setSnackbar({ open: true, message: 'Exposure status updated', severity: 'success' }),
    (msg) => setSnackbar({ open: true, message: msg, severity: 'error' }),
  );

  const assetSummary = deriveAssetSummary(exposure.evidence);

  const handleResolve = (e: React.MouseEvent) => {
    e.stopPropagation();
    mutateStatus.mutate({ id: exposure.id, status: 'remediated' });
  };

  const handleFalsePositive = (e: React.MouseEvent) => {
    e.stopPropagation();
    mutateStatus.mutate({ id: exposure.id, status: 'false_positive' });
  };

  return (
    <>
      <Box
        onClick={() => onClick(exposure)}
        sx={{
          p: 3,
          cursor: 'pointer',
          backgroundColor: 'background.paper',
          border: `1px solid ${tokens.border.subtle}`,
          borderRadius: 2,
          transition: 'transform 0.2s, box-shadow 0.2s',
          '&:hover': {
            transform: 'translateY(-2px)',
            boxShadow: 4,
            borderColor: tokens.border.strong,
          },
        }}
      >
        <Stack direction="row" sx={{ justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
          <Stack direction="row" spacing={1} sx={{ flexWrap: 'wrap', gap: 1 }}>
            {exposure.type && exposure.type.length > 0 ? (
              exposure.type.map((t) => (
                <Chip
                  key={t}
                  label={t}
                  size="small"
                  sx={{
                    backgroundColor: tokens.surface.secondary,
                    color: tokens.text.primary,
                    fontWeight: 600,
                    borderRadius: 1,
                  }}
                />
              ))
            ) : (
              <Typography variant="body2" color="text.secondary">
                Unclassified Asset
              </Typography>
            )}
          </Stack>
          <Chip
            label={`Risk: ${exposure.risk_score.toFixed(1)}`}
            sx={{
              backgroundColor:
                exposure.risk_score >= 7 ? `${tokens.accent.error}15` :
                exposure.risk_score >= 4 ? `${tokens.accent.warning}15` :
                `${tokens.accent.info}15`,
              color:
                exposure.risk_score >= 7 ? tokens.accent.error :
                exposure.risk_score >= 4 ? tokens.accent.warning :
                tokens.accent.info,
              fontWeight: 700,
            }}
          />
        </Stack>

        {assetSummary && (
          <Typography
            noWrap
            variant="caption"
            sx={{
              display: 'block',
              mt: 1,
              mb: 1,
              color: 'text.secondary',
              fontFamily: 'monospace',
              fontSize: '0.72rem',
            }}
            title={assetSummary}
          >
            {assetSummary}
          </Typography>
        )}

        <Typography variant="body2" sx={{ color: 'text.secondary', mb: 2 }}>
          Status:{' '}
          <Box component="span" sx={{ fontWeight: 600, color: 'text.primary' }}>
            {exposure.status.toUpperCase()}
          </Box>
        </Typography>

        <Stack direction="row" spacing={1} sx={{ mt: 2 }}>
          {exposure.status === 'open' && (
            <>
              <Button
                size="small"
                variant="contained"
                disabled={mutateStatus.isPending}
                sx={{ backgroundColor: `${tokens.accent.success}1A`, color: tokens.accent.success }}
                onClick={handleResolve}
              >
                {mutateStatus.isPending ? 'Saving…' : 'Resolve'}
              </Button>
              <Button
                size="small"
                variant="outlined"
                color="inherit"
                disabled={mutateStatus.isPending}
                onClick={handleFalsePositive}
              >
                False Positive
              </Button>
            </>
          )}
        </Stack>
      </Box>

      <Snackbar
        open={snackbar.open}
        autoHideDuration={3000}
        onClose={() => setSnackbar((s) => ({ ...s, open: false }))}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert
          severity={snackbar.severity}
          onClose={() => setSnackbar((s) => ({ ...s, open: false }))}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </>
  );
};
