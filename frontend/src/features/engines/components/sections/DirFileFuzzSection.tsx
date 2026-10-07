import React from 'react';
import { Alert, Grid, TextField, FormControlLabel, Checkbox, Typography } from '@mui/material';
import { alpha } from '@mui/material/styles';
import type { DirFileFuzzConfig } from '../../types/engineConfig';
import { SectionCard } from '../shared/SectionCard';
import { ChipSelect } from '../shared/ChipSelect';
import { TagInput } from '../shared/TagInput';
import { BatchingOptions } from '../shared/BatchingOptions';
import { getFieldSx } from '../../../../theme/semanticColors';
import { useThemeTokens } from '../../../../theme/useThemeTokens';

const STATUS_OPTIONS = ['200', '204', '301', '302', '403', '500'];

const TOOL_FIELDS = [
  ['run_ffuf', 'ffuf'],
  ['run_dirsearch', 'dirsearch (extra pass)'],
  ['run_feroxbuster', 'feroxbuster (extra pass)'],
] as const;

const OPTION_FIELDS = [
  ['auto_calibration', 'Auto calibration'],
  ['enable_http_crawl', 'HTTP crawl'],
  ['follow_redirect', 'Follow redirects'],
  ['stop_on_error', 'Stop on error'],
] as const;

/** Backend normalises extensions to one dotted, case-insensitive form. */
const extensionKey = (ext: string): string => ext.trim().replace(/^\./, '').toLowerCase();

type BoolField = (typeof TOOL_FIELDS)[number][0] | (typeof OPTION_FIELDS)[number][0];

interface CheckboxGridProps {
  fields: ReadonlyArray<readonly [BoolField, string]>;
  config: DirFileFuzzConfig;
  onChange: (patch: Partial<DirFileFuzzConfig>) => void;
  columns: { xs: number; sm: number };
}

const CheckboxGrid: React.FC<CheckboxGridProps> = ({ fields, config, onChange, columns }) => {
  const { tokens } = useThemeTokens();
  const chkSx = { color: tokens.accent.primary, '&.Mui-checked': { color: tokens.accent.primary } };
  return (
    <Grid container spacing={1} sx={{ mb: 1 }}>
      {fields.map(([field, label]) => (
        <Grid key={field} size={columns}>
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
  );
};

interface Props {
  config: DirFileFuzzConfig;
  enabled: boolean;
  onToggle: (v: boolean) => void;
  onChange: (patch: Partial<DirFileFuzzConfig>) => void;
}

export const DirFileFuzzSection: React.FC<Props> = ({ config, enabled, onToggle, onChange }) => {
  const { tokens, theme, isLight } = useThemeTokens();
  const fieldSx = getFieldSx(isLight, tokens);
  const noFuzzer = !config.run_ffuf && !config.run_dirsearch && !config.run_feroxbuster;

  return (
    <SectionCard
      title="Dir / File Fuzz"
      description="ffuf fuzzes every target by default (Tier 4). dirsearch and feroxbuster are optional extra passes over the same targets and wordlist, repeating those requests."
      enabled={enabled}
      onToggle={onToggle}
    >
      <CheckboxGrid fields={TOOL_FIELDS} config={config} onChange={onChange} columns={{ xs: 12, sm: 4 }} />
      {noFuzzer && (
        <Alert
          severity="warning"
          sx={{
            mb: 1.5,
            py: 0.25,
            fontSize: '0.8rem',
            bgcolor: alpha(tokens.accent.warning, 0.08),
            color: theme.palette.text.primary,
            border: `1px solid ${alpha(tokens.accent.warning, 0.3)}`,
            '& .MuiAlert-icon': { color: tokens.accent.warning },
          }}
        >
          No fuzzer selected: the directory and file fuzzing step will be skipped.
        </Alert>
      )}
      <CheckboxGrid fields={OPTION_FIELDS} config={config} onChange={onChange} columns={{ xs: 12, sm: 6 }} />

      <TagInput
        label="Extensions"
        value={config.extensions}
        onChange={(v) => onChange({ extensions: v })}
        placeholder="php"
        dedupeKey={extensionKey}
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
      <BatchingOptions config={config.batching} onChange={(batching) => onChange({ batching })} />
    </SectionCard>
  );
};
