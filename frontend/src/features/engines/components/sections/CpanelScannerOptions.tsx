import React from 'react';
import { Box, Checkbox, FormControlLabel, Grid, MenuItem, TextField, Typography } from '@mui/material';
import type { CpanelScannerConfig } from '../../types/engineConfig';
import { useScannerOptionStyles } from './scannerOptionStyles';

interface Props {
  config: CpanelScannerConfig;
  onChange: (next: CpanelScannerConfig) => void;
}

/** `vulnerability_scan.cpanel_scanner`, read by cpanel_scan. It has no run_ flag of its own. */
export const CpanelScannerOptions: React.FC<Props> = ({ config, onChange }) => {
  const { fieldSx, chkSx } = useScannerOptionStyles();
  const set = (patch: Partial<CpanelScannerConfig>) => onChange({ ...config, ...patch });

  return (
    <Box sx={{ mt: 2 }}>
      <Typography variant="caption" sx={{ color: 'text.secondary', display: 'block', mb: 1 }}>
        cPanel Scanner
      </Typography>
      <Grid container spacing={2} sx={{ alignItems: 'center' }}>
        <Grid size={{ xs: 12, sm: 3 }}>
          <FormControlLabel
            control={
              <Checkbox
                checked={config.run_cpanel2shell}
                size="small"
                onChange={(e) => set({ run_cpanel2shell: e.target.checked })}
                sx={chkSx}
              />
            }
            label={<Typography variant="body2">Run cpanel2shell</Typography>}
          />
        </Grid>
        <Grid size={{ xs: 12, sm: 5 }}>
          <TextField
            label="User Wordlist Path"
            size="small"
            fullWidth
            value={config.cpanel_user_wordlist}
            onChange={(e) => set({ cpanel_user_wordlist: e.target.value })}
            helperText="A missing file falls back to the bundled list"
            sx={fieldSx}
          />
        </Grid>
        <Grid size={{ xs: 12, sm: 4 }}>
          <TextField
            select
            label="Proxy"
            size="small"
            fullWidth
            value={config.proxy_type}
            onChange={(e) => set({ proxy_type: e.target.value as CpanelScannerConfig['proxy_type'] })}
            sx={fieldSx}
          >
            <MenuItem value="rotating">rotating (one per target)</MenuItem>
            <MenuItem value="single">single (one for the whole scan)</MenuItem>
          </TextField>
        </Grid>
      </Grid>
    </Box>
  );
};
