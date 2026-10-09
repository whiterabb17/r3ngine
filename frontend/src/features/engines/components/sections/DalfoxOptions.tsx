import React from 'react';
import { Box, Checkbox, FormControlLabel, Grid, TextField, Typography } from '@mui/material';
import type { DalfoxConfig } from '../../types/engineConfig';
import { BoundedNumberField } from '../shared/BoundedNumberField';
import { useScannerOptionStyles } from './scannerOptionStyles';

type DalfoxSwitch = 'waf_evasion' | 'deep_scan' | 'remote_payloads' | 'remote_wordlists';

const SWITCHES: readonly (readonly [DalfoxSwitch, string])[] = [
  ['waf_evasion', 'WAF evasion'],
  ['deep_scan', 'Deep scan'],
  ['remote_payloads', 'Remote payloads (PortSwigger, PayloadBox)'],
  ['remote_wordlists', 'Remote wordlists (Burp, Assetnote)'],
];

interface Props {
  config: DalfoxConfig;
  onChange: (next: DalfoxConfig) => void;
}

/** `vulnerability_scan.dalfox`, read by dalfox_xss_scan. */
export const DalfoxOptions: React.FC<Props> = ({ config, onChange }) => {
  const { fieldSx, chkSx, subSectionSx } = useScannerOptionStyles();
  const set = (patch: Partial<DalfoxConfig>) => onChange({ ...config, ...patch });

  return (
    <Box sx={subSectionSx}>
      <Typography variant="caption" sx={{ color: 'text.secondary', display: 'block', mb: 1 }}>
        Dalfox Options
      </Typography>
      <Grid container spacing={0} sx={{ mb: 1 }}>
        {SWITCHES.map(([field, label]) => (
          <Grid key={field} size={{ xs: 12, sm: 6 }}>
            <FormControlLabel
              control={
                <Checkbox
                  checked={config[field]}
                  size="small"
                  onChange={(e) => set({ [field]: e.target.checked })}
                  sx={chkSx}
                />
              }
              label={<Typography variant="body2">{label}</Typography>}
            />
          </Grid>
        ))}
      </Grid>
      <Grid container spacing={2}>
        <Grid size={{ xs: 6, sm: 3 }}>
          <BoundedNumberField
            label="Workers" value={config.threads} min={1} max={500} unsetLabel="engine threads"
            onChange={(v) => set({ threads: v })} sx={fieldSx}
          />
        </Grid>
        <Grid size={{ xs: 6, sm: 3 }}>
          <BoundedNumberField
            label="Delay (ms)" value={config.delay} min={0} max={10000}
            onChange={(v) => set({ delay: v })} sx={fieldSx}
          />
        </Grid>
        <Grid size={{ xs: 6, sm: 3 }}>
          <BoundedNumberField
            label="Request timeout (s)" value={config.timeout} min={1} max={600} unsetLabel="dalfox default"
            onChange={(v) => set({ timeout: v })} sx={fieldSx}
          />
        </Grid>
        <Grid size={{ xs: 6, sm: 3 }}>
          <BoundedNumberField
            label="Scan timeout (s)" value={config.scan_timeout} min={0} max={7200}
            onChange={(v) => set({ scan_timeout: v })} helperText="0 = no limit" sx={fieldSx}
          />
        </Grid>
        <Grid size={{ xs: 12, sm: 6 }}>
          <TextField
            label="Blind XSS server"
            size="small"
            fullWidth
            value={config.blind_xss_server}
            onChange={(e) => set({ blind_xss_server: e.target.value.trim() })}
            placeholder="https://callback.example.com"
            helperText="Callback URL for blind XSS payloads"
            sx={fieldSx}
          />
        </Grid>
        <Grid size={{ xs: 12, sm: 6 }}>
          <TextField
            label="User agent"
            size="small"
            fullWidth
            value={config.user_agent}
            onChange={(e) => set({ user_agent: e.target.value })}
            helperText="Empty uses the engine-wide user_agent"
            sx={fieldSx}
          />
        </Grid>
      </Grid>
    </Box>
  );
};
