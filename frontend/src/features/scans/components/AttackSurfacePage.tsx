import React from 'react';
import { useParams } from '@tanstack/react-router';
import { Box, Typography, Button, Stack } from '@mui/material';
import { ChevronLeft } from 'lucide-react';
import { Link as RouterLink } from '@tanstack/react-router';
import { AttackSurfaceTab } from './AttackSurfaceTab';
import { useThemeTokens } from '../../../theme/useThemeTokens';

export const AttackSurfacePage: React.FC = () => {
  const { tokens } = useThemeTokens();
  const { projectSlug, scanId } = useParams({ from: '/$projectSlug/attack_surface/$scanId' });

  return (
    <Box sx={{ p: 3 }}>
      <Box sx={{ mb: 3, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Box>
          <Stack direction="row" spacing={1} sx={{ alignItems: 'center', mb: 1 }}>
            <Button
              component={RouterLink}
              to={`/${projectSlug}/scans`}
              startIcon={<ChevronLeft size={16} />}
              sx={{
                color: 'text.secondary',
                fontFamily: 'Orbitron',
                fontSize: '0.7rem',
                '&:hover': { color: tokens.accent.primary, bgcolor: 'transparent' }
              }}
            >
              BACK TO SCANS
            </Button>
          </Stack>
          {/* <Typography variant="h5" sx={{ fontWeight: 900, fontFamily: 'Orbitron', color: 'text.primary', letterSpacing: 2 }}>
            ATTACK SURFACE MAP
          </Typography>
          <Typography variant="body2" sx={{ color: 'text.secondary', fontFamily: 'Orbitron', fontSize: '0.7rem' }}>
            VISUALIZING INFRASTRUCTURE NODES AND RELATIONSHIPS FOR SCAN #{scanId}
          </Typography> */}
        </Box>
      </Box>

      <AttackSurfaceTab
        projectSlug={projectSlug}
        scanId={parseInt(scanId)}
      />
    </Box>
  );
};
