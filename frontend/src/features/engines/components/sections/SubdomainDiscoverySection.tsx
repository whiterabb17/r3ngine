import React from 'react';
import { Grid, TextField, FormControlLabel, Checkbox, Typography } from '@mui/material';
import type { SubdomainDiscoveryConfig } from '../../types/engineConfig';
import { SectionCard } from '../shared/SectionCard';
import { ChipSelect } from '../shared/ChipSelect';
import { TagInput } from '../shared/TagInput';
import { getFieldSx } from '../../../../theme/semanticColors';
import { useThemeTokens } from '../../../../theme/useThemeTokens';

const SUBDOMAIN_TOOLS = [
  'subfinder', 'chaos', 'ctfr', 'sublist3r', 'tlsx',
  'oneforall', 'netlas', 'baddns', 'amass-passive', 'amass-active',
];

interface Props {
  config: SubdomainDiscoveryConfig;
  enabled: boolean;
  onToggle: (v: boolean) => void;
  onChange: (patch: Partial<SubdomainDiscoveryConfig>) => void;
}

export const SubdomainDiscoverySection: React.FC<Props> = ({ config, enabled, onToggle, onChange }) => {
  const { tokens, isLight } = useThemeTokens();
  const fieldSx = getFieldSx(isLight, tokens);

  return (
    <SectionCard
      title="Subdomain Discovery"
      description="Enumerate subdomains using passive and active tools."
      enabled={enabled}
      onToggle={onToggle}
    >
      <ChipSelect
        label="Tools"
        options={SUBDOMAIN_TOOLS}
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
            onChange={(e) => onChange({ threads: Math.max(1, Math.min(100, Number(e.target.value))) })}
            slotProps={{ htmlInput: { min: 1, max: 100 } }}
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
            onChange={(e) => onChange({ timeout: Math.max(1, Math.min(120, Number(e.target.value))) })}
            slotProps={{ htmlInput: { min: 1, max: 120 } }}
            sx={fieldSx}
          />
        </Grid>
        <Grid size={{ xs: 12, sm: 6 }}>
          {config.use_amass_config && (
            <TextField
              label="Amass Wordlist"
              size="small"
              fullWidth
              value={config.amass_wordlist}
              onChange={(e) => onChange({ amass_wordlist: e.target.value })}
              placeholder="deepmagic.com-prefixes-top50000"
              sx={fieldSx}
            />
          )}
        </Grid>
        <Grid size={{ xs: 12 }}>
          {(['enable_http_crawl', 'bbot', 'use_subfinder_config', 'use_amass_config'] as const).map((field) => (
            <FormControlLabel
              key={field}
              control={
                <Checkbox
                  checked={config[field]}
                  size="small"
                  onChange={(e) => onChange({ [field]: e.target.checked })}
                  sx={{ color: tokens.accent.primary, '&.Mui-checked': { color: tokens.accent.primary } }}
                />
              }
              label={
                <Typography variant="body2">
                  {field === 'enable_http_crawl' && 'Enable HTTP crawl'}
                  {field === 'bbot' && 'Enable bbot'}
                  {field === 'use_subfinder_config' && 'Use subfinder config'}
                  {field === 'use_amass_config' && 'Use amass config'}
                  {field === 'bbot' && (
                    <Typography component="span" variant="caption" sx={{ color: 'text.secondary', ml: 1 }}>
                      (slow but thorough passive OSINT)
                    </Typography>
                  )}
                </Typography>
              }
              sx={{ mr: 2 }}
            />
          ))}
        </Grid>
      </Grid>
    </SectionCard>
  );
};
