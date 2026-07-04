import React from 'react';
import { Grid, TextField, MenuItem } from '@mui/material';
import type { OsintConfig } from '../../types/engineConfig';
import { SectionCard } from '../shared/SectionCard';
import { ChipSelect } from '../shared/ChipSelect';
import { TagInput } from '../shared/TagInput';
import { getFieldSx } from '../../../../theme/semanticColors';
import { useThemeTokens } from '../../../../theme/useThemeTokens';

const DISCOVER_OPTIONS = ['emails', 'metainfo', 'employees'];
const DORK_OPTIONS = [
  'login_pages', 'admin_panels', 'dashboard_pages', 'stackoverflow', 'social_media',
  'project_management', 'code_sharing', 'config_files', 'jenkins', 'wordpress_files',
  'php_error', 'exposed_documents', 'db_files', 'git_exposed',
];

interface Props {
  config: OsintConfig;
  enabled: boolean;
  onToggle: (v: boolean) => void;
  onChange: (p: Partial<OsintConfig>) => void;
}

export const OsintSection: React.FC<Props> = ({ config, enabled, onToggle, onChange }) => {
  const { tokens, isLight } = useThemeTokens();
  const fieldSx = getFieldSx(isLight, tokens);

  return (
    <SectionCard
      title="OSINT"
      description="Runs in parallel with subdomain discovery (Tier 1)."
      enabled={enabled}
      onToggle={onToggle}
    >
      <ChipSelect
        label="Discover"
        options={DISCOVER_OPTIONS}
        value={config.discover}
        onChange={(v) => onChange({ discover: v })}
      />
      <ChipSelect
        label="Google Dorks"
        options={DORK_OPTIONS}
        value={config.dorks}
        onChange={(v) => onChange({ dorks: v })}
      />
      <TagInput
        label="Custom Dorks"
        value={config.custom_dorks}
        onChange={(v) => onChange({ custom_dorks: v })}
        placeholder="site:_target_ ext:php"
      />
      <Grid container spacing={2}>
        <Grid size={{ xs: 12, sm: 6 }}>
          <TextField
            select
            label="Intensity"
            size="small"
            fullWidth
            value={config.intensity}
            onChange={(e) => onChange({ intensity: e.target.value as OsintConfig['intensity'] })}
            sx={fieldSx}
          >
            {['normal', 'aggressive', 'light'].map((o) => (
              <MenuItem key={o} value={o}>{o}</MenuItem>
            ))}
          </TextField>
        </Grid>
        <Grid size={{ xs: 12, sm: 6 }}>
          <TextField
            label="Documents Limit"
            type="number"
            size="small"
            fullWidth
            value={config.documents_limit}
            onChange={(e) => onChange({ documents_limit: Math.max(1, Number(e.target.value)) })}
            slotProps={{ htmlInput: { min: 1 } }}
            sx={fieldSx}
          />
        </Grid>
      </Grid>
    </SectionCard>
  );
};
