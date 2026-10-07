import React from 'react';
import { Box, Checkbox, FormControlLabel, Grid, Typography } from '@mui/material';
import type { BatchingConfig } from '../../types/engineConfig';
import { BoundedNumberField } from './BoundedNumberField';
import { useScannerOptionStyles } from '../sections/scannerOptionStyles';

interface Props {
  config: BatchingConfig;
  onChange: (next: BatchingConfig) => void;
}

/**
 * `batching:` of a per-host tool. A large target is split into batches of hosts, each
 * its own step with its own time limit, so one slow host no longer costs the whole run
 * and a Retry continues where it stopped. Bounds match `web/reNgine/chunking.py`.
 */
export const BatchingOptions: React.FC<Props> = ({ config, onChange }) => {
  const { fieldSx, chkSx, subSectionSx } = useScannerOptionStyles();
  const set = (patch: Partial<BatchingConfig>) => onChange({ ...config, ...patch });

  return (
    <Box sx={subSectionSx}>
      <Typography variant="caption" sx={{ color: 'text.secondary', display: 'block', mb: 1 }}>
        Batches for large targets
      </Typography>
      <Grid container spacing={2} sx={{ alignItems: 'center' }}>
        <Grid size={{ xs: 12, sm: 4 }}>
          <FormControlLabel
            control={
              <Checkbox
                checked={config.enabled}
                size="small"
                onChange={(e) => set({ enabled: e.target.checked })}
                sx={chkSx}
              />
            }
            label={<Typography variant="body2">Run in batches of hosts</Typography>}
          />
        </Grid>
        <Grid size={{ xs: 6, sm: 2 }}>
          <BoundedNumberField
            label="Hosts / batch" value={config.batch_size} min={1} max={500}
            onChange={(batch_size) => set({ batch_size })} sx={fieldSx}
          />
        </Grid>
        <Grid size={{ xs: 6, sm: 2 }}>
          <BoundedNumberField
            label="At a time" value={config.max_parallel} min={1} max={5}
            onChange={(max_parallel) => set({ max_parallel })} sx={fieldSx}
          />
        </Grid>
        <Grid size={{ xs: 6, sm: 2 }}>
          <BoundedNumberField
            label="Batch limit (min)" value={config.batch_timeout_minutes} min={10} max={720}
            onChange={(batch_timeout_minutes) => set({ batch_timeout_minutes })} sx={fieldSx}
          />
        </Grid>
        <Grid size={{ xs: 6, sm: 2 }}>
          <BoundedNumberField
            label="Total budget (h)" value={config.max_total_hours} min={1} max={72}
            onChange={(max_total_hours) => set({ max_total_hours })} sx={fieldSx}
            helperText="Then a Retry continues"
          />
        </Grid>
      </Grid>
    </Box>
  );
};
