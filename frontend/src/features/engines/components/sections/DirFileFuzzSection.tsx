import React from 'react';
import { Grid, TextField, FormControlLabel, Checkbox, Typography } from '@mui/material';
import type { DirFileFuzzConfig } from '../../types/engineConfig';
import { SectionCard } from '../shared/SectionCard';
import { ChipSelect } from '../shared/ChipSelect';
import { TagInput } from '../shared/TagInput';
import { getFieldSx } from '../../../../theme/semanticColors';
import { useThemeTokens } from '../../../../theme/useThemeTokens';

const STATUS_OPTIONS = ['200', '204', '301', '302', '403', '500'];

const BOOL_FIELDS = [
  ['run_dirsearch', 'dirsearch'],
  ['run_feroxbuster', 'feroxbuster'],
  ['auto_calibration', 'Auto calibration'],
  ['enable_http_crawl', 'HTTP crawl'],
  ['follow_redirect', 'Follow redirects'],
  ['stop_on_error', 'Stop on error'],
] as const;

interface Props {
  config: DirFileFuzzConfig;
  enabled: boolean;
  onToggle: (v: boolean) => void;
  onChange: (patch: Partial<DirFileFuzzConfig>) => void;
}

export const DirFileFuzzSection: React.FC<Props> = ({ config, enabled, onToggle, onChange }) => {
  const { tokens, isLight } = useThemeTokens();
  const fieldSx = getFieldSx(isLight, tokens);
  const chkSx = { color: tokens.accent.primary, '&.Mui-checked': { color: tokens.accent.primary } };

  return (
    <SectionCard
      title="Dir / File Fuzz"
      description="Directory and file enumeration via dirsearch / feroxbuster (Tier 4)."
      enabled={enabled}
      onToggle={onToggle}
    >
      <Grid container spacing={1} sx={{ mb: 1 }}>
        {BOOL_FIELDS.map(([field, label]) => (
          <Grid key={field} size={{ xs: 12, sm: 6 }}>
            <FormControlLabel
              control={
                <Checkbox
                  checked={config[field]}
                  size="small"
                  onChange={(e) => onChange({ [field]: e.target.checked })}
                  sx={chkSx}
                />
              }
              label={<Typography variant="body2">{label}</Typography>}
            />
          </Grid>
        ))}
      </Grid>

      <TagInput
        label="Extensions"
        value={config.extensions}
        onChange={(v) => onChange({ extensions: v })}
        placeholder="php"
      />

      <ChipSelect
        label="Match HTTP Status"
        options={STATUS_OPTIONS}
        value={config.match_http_status.map(String)}
        onChange={(v) => onChange({ match_http_status: v.map(Number) })}
      />

      <Grid container spacing={2}>
        <Grid size={{ xs: 12, sm: 4 }}>
          <TextField
            label="Wordlist Name"
            size="small"
            fullWidth
            value={config.wordlist_name}
            onChange={(e) => onChange({ wordlist_name: e.target.value })}
            sx={fieldSx}
          />
        </Grid>
        <Grid size={{ xs: 6, sm: 2 }}>
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
        <Grid size={{ xs: 6, sm: 2 }}>
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
        <Grid size={{ xs: 6, sm: 2 }}>
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
        <Grid size={{ xs: 6, sm: 2 }}>
          <TextField
            label="Max Time (s)"
            type="number"
            size="small"
            fullWidth
            value={config.max_time}
            onChange={(e) => onChange({ max_time: Math.max(1, Number(e.target.value)) })}
            slotProps={{ htmlInput: { min: 1 } }}
            sx={fieldSx}
          />
        </Grid>
        <Grid size={{ xs: 6, sm: 2 }}>
          <TextField
            label="Recursive Level"
            type="number"
            size="small"
            fullWidth
            value={config.recursive_level}
            onChange={(e) =>
              onChange({ recursive_level: Math.max(0, Math.min(5, Number(e.target.value))) })
            }
            slotProps={{ htmlInput: { min: 0, max: 5 } }}
            sx={fieldSx}
          />
        </Grid>
        <Grid size={{ xs: 6, sm: 3 }}>
          <TextField
            label="Max Repeat / Signature"
            type="number"
            size="small"
            fullWidth
            value={config.max_repeat_by_signature}
            onChange={(e) =>
              onChange({ max_repeat_by_signature: Math.max(1, Number(e.target.value)) })
            }
            slotProps={{ htmlInput: { min: 1 } }}
            sx={fieldSx}
          />
        </Grid>
      </Grid>
    </SectionCard>
  );
};
