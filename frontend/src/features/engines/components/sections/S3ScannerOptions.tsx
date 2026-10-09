import React from 'react';
import { Box, Grid, Typography } from '@mui/material';
import type { S3ScannerConfig } from '../../types/engineConfig';
import { S3SCANNER_DEFAULT_PROVIDERS } from '../../types/engineConfig';
import { BoundedNumberField } from '../shared/BoundedNumberField';
import { ChipSelect } from '../shared/ChipSelect';
import { useScannerOptionStyles } from './scannerOptionStyles';

interface Props {
  config: S3ScannerConfig;
  onChange: (next: S3ScannerConfig) => void;
}

/** `vulnerability_scan.s3scanner`, read by the s3scanner task. */
export const S3ScannerOptions: React.FC<Props> = ({ config, onChange }) => {
  const { fieldSx, subSectionSx } = useScannerOptionStyles();

  return (
    <Box sx={subSectionSx}>
      <Typography variant="caption" sx={{ color: 'text.secondary', display: 'block', mb: 1 }}>
        S3Scanner Options
      </Typography>
      <Grid container spacing={2} sx={{ alignItems: 'flex-start' }}>
        <Grid size={{ xs: 12, sm: 8 }}>
          <ChipSelect
            label="Providers"
            options={S3SCANNER_DEFAULT_PROVIDERS}
            value={config.providers}
            onChange={(providers) => onChange({ ...config, providers })}
          />
        </Grid>
        <Grid size={{ xs: 12, sm: 4 }}>
          <BoundedNumberField
            label="Threads" value={config.threads} min={1} max={500} unsetLabel="engine threads"
            onChange={(threads) => onChange({ ...config, threads })} sx={fieldSx}
          />
        </Grid>
      </Grid>
      {config.providers.length === 0 && (
        <Typography variant="caption" sx={{ color: 'warning.main', display: 'block' }}>
          No provider selected — S3Scanner will not check any bucket.
        </Typography>
      )}
    </Box>
  );
};
