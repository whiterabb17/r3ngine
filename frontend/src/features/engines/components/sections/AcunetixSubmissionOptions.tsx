import React from 'react';
import { Box, Checkbox, FormControlLabel, Grid, TextField, Typography } from '@mui/material';
import type { AcunetixConfig } from '../../types/engineConfig';
import { BoundedNumberField } from '../shared/BoundedNumberField';
import { useScannerOptionStyles } from './scannerOptionStyles';

interface Props {
  config: AcunetixConfig;
  onChange: (next: AcunetixConfig) => void;
}

/**
 * `vulnerability_scan.acunetix` — independent of run_acunetix, which only scans the apex
 * domain in Tier 6. This pushes live subdomains as targets.
 */
export const AcunetixSubmissionOptions: React.FC<Props> = ({ config, onChange }) => {
  const { fieldSx, chkSx } = useScannerOptionStyles();
  const set = (patch: Partial<AcunetixConfig>) => onChange({ ...config, ...patch });

  return (
    <Box sx={{ mt: 2 }}>
      <Typography variant="caption" sx={{ color: 'text.secondary', display: 'block', mb: 1 }}>
        Acunetix Target Submission
      </Typography>
      <Grid container spacing={2} sx={{ alignItems: 'center' }}>
        <Grid size={{ xs: 12, sm: 5 }}>
          <FormControlLabel
            control={
              <Checkbox
                checked={config.submit_live_subdomains}
                size="small"
                onChange={(e) => set({ submit_live_subdomains: e.target.checked })}
                sx={chkSx}
              />
            }
            label={<Typography variant="body2">Send every live subdomain to Acunetix</Typography>}
          />
        </Grid>
        <Grid size={{ xs: 12, sm: 3 }}>
          <TextField
            fullWidth size="small" type="number" label="Re-submit after (days)"
            value={config.resubmit_after_days}
            onChange={(e) => set({ resubmit_after_days: Math.max(0, Number(e.target.value) || 0) })}
            sx={fieldSx}
            helperText="A host sent within this window is skipped"
          />
        </Grid>
        <Grid size={{ xs: 12, sm: 4 }}>
          <FormControlLabel
            control={
              <Checkbox
                checked={config.start_scan_on_submit}
                size="small"
                onChange={(e) => set({ start_scan_on_submit: e.target.checked })}
                sx={chkSx}
              />
            }
            label={<Typography variant="body2">Start a scan for each new target</Typography>}
          />
        </Grid>
        <Grid size={{ xs: 12, sm: 4 }}>
          <BoundedNumberField
            label="Batch size" value={config.submission_batch_size} min={1} max={200}
            onChange={(submission_batch_size) => set({ submission_batch_size })} sx={fieldSx}
            helperText="Hosts sent per batch"
          />
        </Grid>
        <Grid size={{ xs: 12, sm: 4 }}>
          <BoundedNumberField
            label="Pause between batches (s)" value={config.submission_batch_pause} min={0} max={300}
            onChange={(submission_batch_pause) => set({ submission_batch_pause })} sx={fieldSx}
          />
        </Grid>
        <Grid size={{ xs: 12, sm: 4 }}>
          <BoundedNumberField
            label="Max scans per run" value={config.max_scans_per_run} min={1} max={500}
            onChange={(max_scans_per_run) => set({ max_scans_per_run })} sx={fieldSx}
            helperText={
              config.start_scan_on_submit
                ? 'The rest are added as targets and scanned on a later run'
                : 'Applies when scans are started on submit'
            }
          />
        </Grid>
      </Grid>
    </Box>
  );
};
