import React from 'react';
import { Box, Typography, Button, Chip, Stack } from '@mui/material';
import type { Exposure } from '../types';
import { useThemeTokens } from '@/theme/useThemeTokens';
import { useMutateExposureStatus } from '../api/useExposures';

interface ExposureCardProps {
  exposure: Exposure;
  onClick: (exposure: Exposure) => void;
}

export const ExposureCard: React.FC<ExposureCardProps> = ({ exposure, onClick }) => {
  const { tokens } = useThemeTokens();
  const mutateStatus = useMutateExposureStatus();

  const handleResolve = (e: React.MouseEvent) => {
    e.stopPropagation();
    mutateStatus.mutate({ id: exposure.id, status: 'remediated' });
  };

  const handleFalsePositive = (e: React.MouseEvent) => {
    e.stopPropagation();
    mutateStatus.mutate({ id: exposure.id, status: 'false_positive' });
  };

  return (
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
                  borderRadius: 1
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
            backgroundColor: exposure.risk_score >= 7 ? `${tokens.accent.error}15` : 
                           exposure.risk_score >= 4 ? `${tokens.accent.warning}15` : 
                           `${tokens.accent.info}15`,
            color: exposure.risk_score >= 7 ? tokens.accent.error : 
                   exposure.risk_score >= 4 ? tokens.accent.warning : 
                   tokens.accent.info,
            fontWeight: 700
          }} 
        />
      </Stack>

      <Typography variant="body2" sx={{ color: 'text.secondary', mb: 2 }}>
        Status: <span style={{ fontWeight: 600, color: 'text.primary' }}>{exposure.status.toUpperCase()}</span>
      </Typography>

      <Stack direction="row" spacing={1} sx={{ mt: 2 }}>
        {exposure.status === 'open' && (
          <>
            <Button 
              size="small" 
              variant="contained" 
              sx={{ backgroundColor: `${tokens.accent.success}1A`, color: tokens.accent.success }}
              onClick={handleResolve}
            >
              Resolve
            </Button>
            <Button 
              size="small" 
              variant="outlined" 
              color="inherit"
              onClick={handleFalsePositive}
            >
              False Positive
            </Button>
          </>
        )}
      </Stack>
    </Box>
  );
};
