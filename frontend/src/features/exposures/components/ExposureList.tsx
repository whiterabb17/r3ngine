import React, { useState } from 'react';
import { Box, Grid, Typography, CircularProgress } from '@mui/material';
import { useExposures } from '../api/useExposures';
import { ExposureCard } from './ExposureCard';
import type { Exposure } from '../types';
import { useSemanticColors } from '@/theme/useSemanticColors';

import { ExposureDetailsDrawer } from './ExposureDetailsDrawer';

interface ExposureListProps {
  scan_id?: string;
  target_id?: string;
}

export const ExposureList: React.FC<ExposureListProps> = ({ scan_id, target_id }) => {
  const [selectedExposure, setSelectedExposure] = useState<Exposure | null>(null);
  const semantic = useSemanticColors();
  
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

  if (exposures.length === 0) {
    return (
      <Box sx={{ p: 4, textAlign: 'center' }}>
        <Typography variant="body1" sx={{ color: 'text.secondary' }}>
          No exposures detected for this target/scan.
        </Typography>
      </Box>
    );
  }

  return (
    <Box>
      <Grid container spacing={3}>
        {exposures.map((exposure) => (
          <Grid size={{ xs: 12, sm: 6, md: 4 }} key={exposure.id}>
            <ExposureCard 
              exposure={exposure} 
              onClick={(exp) => setSelectedExposure(exp)} 
            />
          </Grid>
        ))}
      </Grid>
      
      {selectedExposure && (
        <ExposureDetailsDrawer 
          exposure={selectedExposure} 
          onClose={() => setSelectedExposure(null)} 
        />
      )}
    </Box>
  );
};
