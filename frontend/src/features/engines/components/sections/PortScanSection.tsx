import React from 'react';
import { Grid, TextField, FormControlLabel, Checkbox, Typography, Collapse, Box } from '@mui/material';
import { alpha } from '@mui/material/styles';
import type { PortScanConfig } from '../../types/engineConfig';
import { SectionCard } from '../shared/SectionCard';
import { ChipSelect } from '../shared/ChipSelect';
import { TagInput } from '../shared/TagInput';
import { getFieldSx } from '../../../../theme/semanticColors';
import { useThemeTokens } from '../../../../theme/useThemeTokens';

const PORT_PRESETS = ['top-100', 'top-1000', 'full'];

interface Props {
  config: PortScanConfig;
  enabled: boolean;
  onToggle: (v: boolean) => void;
  onChange: (patch: Partial<PortScanConfig>) => void;
}

export const PortScanSection: React.FC<Props> = ({ config, enabled, onToggle, onChange }) => {
  const { tokens, isLight } = useThemeTokens();
  const fieldSx = getFieldSx(isLight, tokens);
  const chkSx = { color: tokens.accent.primary, '&.Mui-checked': { color: tokens.accent.primary } };

  return (
    <SectionCard
      title="Port Scan"
      description="Port and service discovery via naabu. Runs in parallel at Tier 2."
      enabled={enabled}
      onToggle={onToggle}
    >
      <ChipSelect
        label="Ports"
        options={PORT_PRESETS}
        value={config.ports.filter((p) => PORT_PRESETS.includes(p))}
        onChange={(v) => onChange({ ports: v })}
        helperText="Select a preset or add custom ranges via the tag input below"
      />
      <TagInput
        label="Custom Port Ranges"
        value={config.ports.filter((p) => !PORT_PRESETS.includes(p))}
        onChange={(v) => onChange({ ports: [...config.ports.filter((p) => PORT_PRESETS.includes(p)), ...v] })}
        placeholder="8080-8090"
      />

      <Grid container spacing={2} sx={{ mt: 0 }}>
        <Grid size={{ xs: 6, sm: 3 }}>
          <TextField
            label="Rate Limit"
            type="number"
            size="small"
            fullWidth
            value={config.rate_limit}
            onChange={(e) => onChange({ rate_limit: Math.max(1, Number(e.target.value)) })}
            slotProps={{ htmlInput: { min: 1 } }}
            sx={fieldSx}
          />
        </Grid>
        <Grid size={{ xs: 6, sm: 3 }}>
          <TextField
            label="Threads"
            type="number"
            size="small"
            fullWidth
            value={config.threads}
            onChange={(e) => onChange({ threads: Math.max(1, Number(e.target.value)) })}
            slotProps={{ htmlInput: { min: 1 } }}
            sx={fieldSx}
          />
        </Grid>
        <Grid size={{ xs: 6, sm: 3 }}>
          <TextField
            label="Timeout (s)"
            type="number"
            size="small"
            fullWidth
            value={config.timeout}
            onChange={(e) => onChange({ timeout: Math.max(1, Number(e.target.value)) })}
            slotProps={{ htmlInput: { min: 1 } }}
            sx={fieldSx}
          />
        </Grid>
      </Grid>

      <Box sx={{ mt: 1 }}>
        {(['passive', 'enable_http_crawl', 'exclude_subdomains'] as const).map((field) => (
          <FormControlLabel
            key={field}
            control={
              <Checkbox
                checked={config[field]}
                size="small"
                onChange={(e) => onChange({ [field]: e.target.checked })}
                sx={chkSx}
              />
            }
            label={
              <Typography variant="body2">
                {field === 'passive' && 'Passive scan only'}
                {field === 'enable_http_crawl' && 'Enable HTTP crawl'}
                {field === 'exclude_subdomains' && 'Exclude subdomains'}
              </Typography>
            }
            sx={{ mr: 2 }}
          />
        ))}
        <FormControlLabel
          control={
            <Checkbox
              checked={config.enable_nmap}
              size="small"
              onChange={(e) => onChange({ enable_nmap: e.target.checked })}
              sx={chkSx}
            />
          }
          label={<Typography variant="body2">Enable nmap (service/script scanning)</Typography>}
          sx={{ mr: 2 }}
        />
      </Box>

      {/* Nmap sub-fields — only shown when enable_nmap is checked */}
      <Collapse in={config.enable_nmap}>
        <Box sx={{ mt: 2, pl: 2, borderLeft: `2px solid ${alpha(tokens.accent.primary, 0.25)}` }}>
          <Grid container spacing={2}>
            <Grid size={{ xs: 12 }}>
              <TextField
                label="Nmap Command"
                size="small"
                fullWidth
                value={config.nmap_cmd}
                onChange={(e) => onChange({ nmap_cmd: e.target.value })}
                placeholder="nmap -vv -Pn"
                sx={fieldSx}
              />
            </Grid>
            <Grid size={{ xs: 12, sm: 6 }}>
              <TextField
                label="Nmap Script"
                size="small"
                fullWidth
                value={config.nmap_script}
                onChange={(e) => onChange({ nmap_script: e.target.value })}
                sx={fieldSx}
              />
            </Grid>
            <Grid size={{ xs: 12, sm: 6 }}>
              <TextField
                label="Nmap Script Args"
                size="small"
                fullWidth
                value={config.nmap_script_args}
                onChange={(e) => onChange({ nmap_script_args: e.target.value })}
                sx={fieldSx}
              />
            </Grid>
          </Grid>
        </Box>
      </Collapse>

      <Box sx={{ mt: 2 }}>
        <TagInput
          label="Exclude Ports"
          value={config.exclude_ports}
          onChange={(v) => onChange({ exclude_ports: v })}
          placeholder="22"
        />
      </Box>
    </SectionCard>
  );
};
