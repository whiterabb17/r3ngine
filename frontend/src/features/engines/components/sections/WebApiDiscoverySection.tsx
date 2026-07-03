import React from 'react';
import { Grid, TextField, FormControlLabel, Checkbox, Typography } from '@mui/material';
import type { WebApiDiscoveryConfig } from '../../types/engineConfig';
import { SectionCard } from '../shared/SectionCard';
import { ChipSelect } from '../shared/ChipSelect';
import { getFieldSx } from '../../../../theme/semanticColors';
import { useThemeTokens } from '../../../../theme/useThemeTokens';

const API_TOOLS = [
  'kiterunner', 'arjun', 'linkfinder', 'paramspider', 'aquatone',
  'semgrep', 'retire', 'jwt_tool', 'graphql-cop', 'favirecon',
  'sourcemapper', 'grpcurl', 'julius', 'gqlspection',
];

const RUN_FLAGS = [
  'run_favirecon',
  'run_sourcemapper',
  'run_grpcurl',
  'run_julius',
  'run_gqlspection',
] as const;

interface Props {
  config: WebApiDiscoveryConfig;
  enabled: boolean;
  onToggle: (v: boolean) => void;
  onChange: (patch: Partial<WebApiDiscoveryConfig>) => void;
}

export const WebApiDiscoverySection: React.FC<Props> = ({ config, enabled, onToggle, onChange }) => {
  const { tokens, isLight } = useThemeTokens();
  const fieldSx = getFieldSx(isLight, tokens);
  const chkSx = { color: tokens.accent.primary, '&.Mui-checked': { color: tokens.accent.primary } };

  return (
    <SectionCard
      title="Web API Discovery"
      description="API recon via kiterunner, arjun, GraphQL, gRPC and more (Tier 3b)."
      enabled={enabled}
      onToggle={onToggle}
    >
      <ChipSelect
        label="Tools"
        options={API_TOOLS}
        value={config.uses_tools}
        onChange={(v) => onChange({ uses_tools: v })}
      />
      <Grid container spacing={2}>
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
        <Grid size={{ xs: 12, sm: 6 }}>
          <TextField
            label="Kiterunner Wordlist"
            size="small"
            fullWidth
            value={config.kr_wordlist}
            onChange={(e) => onChange({ kr_wordlist: e.target.value })}
            placeholder="routes-small.kite"
            sx={fieldSx}
          />
        </Grid>
        <Grid size={{ xs: 12 }}>
          <FormControlLabel
            control={
              <Checkbox
                checked={config.scan_only_active}
                size="small"
                onChange={(e) => onChange({ scan_only_active: e.target.checked })}
                sx={chkSx}
              />
            }
            label={<Typography variant="body2">Scan only active subdomains</Typography>}
            sx={{ mr: 2 }}
          />
          {RUN_FLAGS.map((field) => (
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
              label={<Typography variant="body2">{field.replace('run_', '')}</Typography>}
              sx={{ mr: 2 }}
            />
          ))}
        </Grid>
      </Grid>
    </SectionCard>
  );
};
