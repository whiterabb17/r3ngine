import React from 'react';
import { Box, Grid, MenuItem, TextField, Typography } from '@mui/material';
import type { VulnerabilityScanConfig } from '../../types/engineConfig';
import { useScannerOptionStyles } from './scannerOptionStyles';

const DETECTION_OPTIONS = ['mixed', 'passive', 'aggressive'] as const;

type WpscanFields = Pick<VulnerabilityScanConfig, 'wpscan_enumeration' | 'wpscan_detection_mode'>;

interface Props {
  config: WpscanFields;
  onChange: (patch: Partial<WpscanFields>) => void;
}

/** `vulnerability_scan.wpscan_*`, read by wpscan_scan. */
export const WpscanOptions: React.FC<Props> = ({ config, onChange }) => {
  const { fieldSx, subSectionSx } = useScannerOptionStyles();

  return (
    <Box sx={subSectionSx}>
      <Typography variant="caption" sx={{ color: 'text.secondary', display: 'block', mb: 1 }}>
        WPScan Options
      </Typography>
      <Grid container spacing={2}>
        <Grid size={{ xs: 12, sm: 6 }}>
          <TextField
            label="Enumeration"
            size="small"
            fullWidth
            value={config.wpscan_enumeration}
            onChange={(e) => onChange({ wpscan_enumeration: e.target.value })}
            placeholder="vp,vt,u"
            helperText="vp = vulnerable plugins, vt = vulnerable themes, u = users"
            sx={fieldSx}
          />
        </Grid>
        <Grid size={{ xs: 12, sm: 6 }}>
          <TextField
            select
            label="Detection Mode"
            size="small"
            fullWidth
            value={config.wpscan_detection_mode}
            onChange={(e) =>
              onChange({ wpscan_detection_mode: e.target.value as WpscanFields['wpscan_detection_mode'] })
            }
            sx={fieldSx}
          >
            {DETECTION_OPTIONS.map((o) => (
              <MenuItem key={o} value={o}>
                {o}
              </MenuItem>
            ))}
          </TextField>
        </Grid>
      </Grid>
    </Box>
  );
};
