import React from 'react';
import { Grid, TextField, FormControlLabel, Checkbox, Typography } from '@mui/material';
import type { FetchUrlConfig } from '../../types/engineConfig';
import { SectionCard } from '../shared/SectionCard';
import { ChipSelect } from '../shared/ChipSelect';
import { TagInput } from '../shared/TagInput';
import { getFieldSx } from '../../../../theme/semanticColors';
import { useThemeTokens } from '../../../../theme/useThemeTokens';

const FETCH_TOOLS = ['gospider', 'hakrawler', 'waybackurls', 'katana', 'gau'];
const FALLBACK_GF_PATTERNS = [
  'api-keys', 'command-injection', 'cors', 'crlf', 'debug_logic',
  'email-injection', 'graphql', 'http-smuggling', 'idor', 'img-traversal',
  'interestingEXT', 'interestingparams', 'interestingsubs', 'jsvar', 'jwt',
  'lfi', 'mass-assignment', 'nosqli', 'oauth', 'open-redirect',
  'path-traversal', 'prototype-pollution', 'rce', 'redirect', 'sqli',
  'ssrf', 's3-bucket', 'ssti', 'upload', 'websocket', 'xss', 'xxe'
];
const DEDUP_FIELDS = ['content_length', 'page_title'];

interface Props {
  config: FetchUrlConfig;
  enabled: boolean;
  onToggle: (v: boolean) => void;
  onChange: (patch: Partial<FetchUrlConfig>) => void;
  availableGfPatterns?: string[];
}

export const FetchUrlSection: React.FC<Props> = ({ config, enabled, onToggle, onChange, availableGfPatterns }) => {
  const { tokens, isLight } = useThemeTokens();
  const fieldSx = getFieldSx(isLight, tokens);
  const chkSx = { color: tokens.accent.primary, '&.Mui-checked': { color: tokens.accent.primary } };

  return (
    <SectionCard
      title="Fetch URLs"
      description="Crawls endpoints and gathers URLs for deeper analysis (Tier 3)."
      enabled={enabled}
      onToggle={onToggle}
    >
      <ChipSelect
        label="Tools"
        options={FETCH_TOOLS}
        value={config.uses_tools}
        onChange={(v) => onChange({ uses_tools: v })}
      />
      <ChipSelect
        label="GF Patterns"
        options={availableGfPatterns ?? FALLBACK_GF_PATTERNS}
        value={config.gf_patterns}
        onChange={(v) => onChange({ gf_patterns: v })}
        helperText="URL patterns to flag during crawl"
      />
      <ChipSelect
        label="Deduplication Fields"
        options={DEDUP_FIELDS}
        value={config.duplicate_fields}
        onChange={(v) => onChange({ duplicate_fields: v })}
      />
      <TagInput
        label="Ignore File Extensions"
        value={config.ignore_file_extensions}
        onChange={(v) => onChange({ ignore_file_extensions: v })}
        placeholder="png"
      />
      <Grid container spacing={2} sx={{ alignItems: 'center' }}>
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
        <Grid size={{ xs: 12, sm: 9 }}>
          {(['remove_duplicate_endpoints', 'enable_http_crawl'] as const).map((field) => (
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
                  {field === 'remove_duplicate_endpoints' && 'Remove duplicate endpoints'}
                  {field === 'enable_http_crawl' && 'Enable HTTP crawl'}
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
