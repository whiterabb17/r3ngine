import React from 'react';
import { Box, Checkbox, FormControlLabel, Grid, MenuItem, TextField, Typography } from '@mui/material';
import type { VigoliumVulnConfig } from '../../types/engineConfig';
import { useScannerOptionStyles } from './scannerOptionStyles';

const STRATEGY_OPTIONS = ['fast', 'balanced', 'thorough'] as const;

const SCOPE_ORIGIN_OPTIONS = [
  { value: 'all',      label: 'All',      description: 'Follow any host encountered during scanning' },
  { value: 'relaxed',  label: 'Relaxed',  description: 'Stay within the same apex domain (e.g. *.example.com)' },
  { value: 'balanced', label: 'Balanced', description: 'Same host + common subdomains (recommended)' },
  { value: 'strict',   label: 'Strict',   description: 'Exact target host only — no subdomain following' },
] as const;

const PHASES = [
  ['run_phase_a', 'Discovery Phase', 'Spidering + surface discovery'],
  ['run_phase_b', 'Vulnerability Phase', 'Known-issue scan + dynamic assessment'],
] as const;

interface Props {
  config: VigoliumVulnConfig;
  onChange: (next: VigoliumVulnConfig) => void;
}

/** `vulnerability_scan.vigolium`, read by the Tier 6 vigolium task. */
export const VigoliumVulnOptions: React.FC<Props> = ({ config, onChange }) => {
  const { fieldSx, chkSx, subSectionSx } = useScannerOptionStyles();
  const set = (patch: Partial<VigoliumVulnConfig>) => onChange({ ...config, ...patch });

  const labelled = (title: string, caption: string) => (
    <Box>
      <Typography variant="body2">{title}</Typography>
      <Typography variant="caption" sx={{ color: 'text.secondary' }}>{caption}</Typography>
    </Box>
  );

  return (
    <Box sx={subSectionSx}>
      <Typography variant="caption" sx={{ color: 'text.secondary', display: 'block', mb: 1 }}>
        Vigolium (Vulnerability)
      </Typography>

      <Typography variant="caption" sx={{ color: 'text.secondary', display: 'block', mb: 0.5 }}>
        Phases
      </Typography>
      <Grid container spacing={0} sx={{ mb: 1.5 }}>
        {PHASES.map(([field, title, caption]) => (
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
              label={labelled(title, caption)}
            />
          </Grid>
        ))}
      </Grid>
      {!config.run_phase_a && !config.run_phase_b && (
        <Typography variant="caption" sx={{ color: 'warning.main', display: 'block', mb: 1.5 }}>
          ⚠ All Vigolium phases are disabled — the scan will be skipped entirely.
        </Typography>
      )}

      <Grid container spacing={2}>
        <Grid size={{ xs: 12, sm: 4 }}>
          <TextField
            select
            label="Strategy"
            size="small"
            fullWidth
            value={config.strategy}
            onChange={(e) => set({ strategy: e.target.value as VigoliumVulnConfig['strategy'] })}
            sx={fieldSx}
          >
            {STRATEGY_OPTIONS.map((o) => (
              <MenuItem key={o} value={o}>
                {o}
              </MenuItem>
            ))}
          </TextField>
        </Grid>
        <Grid size={{ xs: 6, sm: 2 }}>
          <TextField
            label="Concurrency"
            type="number"
            size="small"
            fullWidth
            value={config.concurrency}
            onChange={(e) => set({ concurrency: Math.max(1, Number(e.target.value)) })}
            slotProps={{ htmlInput: { min: 1 } }}
            sx={fieldSx}
          />
        </Grid>
        <Grid size={{ xs: 6, sm: 3 }}>
          <TextField
            label="Rate Limit"
            type="number"
            size="small"
            fullWidth
            value={config.rate_limit}
            onChange={(e) => set({ rate_limit: Math.max(1, Number(e.target.value)) })}
            slotProps={{ htmlInput: { min: 1 } }}
            sx={fieldSx}
          />
        </Grid>
        <Grid size={{ xs: 6, sm: 3 }}>
          <TextField
            label="Timeout"
            size="small"
            fullWidth
            value={config.timeout}
            onChange={(e) => set({ timeout: e.target.value })}
            helperText="e.g. 15s"
            sx={fieldSx}
          />
        </Grid>
        <Grid size={{ xs: 12, sm: 12 }}>
          <TextField
            select
            label="Scope Origin"
            size="small"
            fullWidth
            value={config.scope_origin}
            onChange={(e) => set({ scope_origin: e.target.value as VigoliumVulnConfig['scope_origin'] })}
            helperText="Controls which hosts vigolium is allowed to follow during scanning"
            sx={fieldSx}
          >
            {SCOPE_ORIGIN_OPTIONS.map((o) => (
              <MenuItem key={o.value} value={o.value}>
                <Box>
                  <Typography variant="body2" component="span" sx={{ fontWeight: 500 }}>
                    {o.label}
                  </Typography>
                  <Typography variant="caption" sx={{ color: 'text.secondary', display: 'block' }}>
                    {o.description}
                  </Typography>
                </Box>
              </MenuItem>
            ))}
          </TextField>
        </Grid>
        <Grid size={{ xs: 12 }} sx={{ display: 'flex', alignItems: 'center' }}>
          <FormControlLabel
            control={
              <Checkbox
                checked={config.skip_spidering}
                size="small"
                onChange={(e) => set({ skip_spidering: e.target.checked })}
                sx={chkSx}
              />
            }
            label={labelled('Skip Spidering', 'Omit browser-based crawling from Phase A (uses --skip spidering)')}
          />
        </Grid>
      </Grid>
    </Box>
  );
};
