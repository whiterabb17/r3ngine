import React from 'react';
import { Grid, TextField } from '@mui/material';
import type { OsintConfig } from '../../types/engineConfig';
import { SectionCard } from '../shared/SectionCard';
import { ChipSelect } from '../shared/ChipSelect';
import { TagInput } from '../shared/TagInput';
import { OsintToolsFields } from './OsintToolsFields';
import { OsintGithubFields } from './OsintGithubFields';
import { getFieldSx } from '../../../../theme/semanticColors';
import { useThemeTokens } from '../../../../theme/useThemeTokens';

const DISCOVER_OPTIONS = ['emails', 'metainfo', 'employees'];
const DORK_OPTIONS = [
  'login_pages', 'admin_panels', 'dashboard_pages', 'stackoverflow', 'social_media',
  'project_management', 'code_sharing', 'config_files', 'jenkins', 'wordpress_files',
  'php_error', 'exposed_documents', 'db_files', 'git_exposed',
];
/** osint.dork_engines values the dorking task runs; GoFuzz always runs the dorks above. */
const DORK_ENGINE_OPTIONS = ['dorks_hunter', 'xnldorker'];

interface Props {
  config: OsintConfig;
  enabled: boolean;
  onToggle: (v: boolean) => void;
  onChange: (p: Partial<OsintConfig>) => void;
}

export const OsintSection: React.FC<Props> = ({ config, enabled, onToggle, onChange }) => {
  const { tokens, isLight } = useThemeTokens();
  const fieldSx = getFieldSx(isLight, tokens);
  const ruleCount = config.custom_dork_rules.length;

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
      <ChipSelect
        label="Extra Dork Engines"
        options={DORK_ENGINE_OPTIONS}
        value={config.dork_engines}
        onChange={(v) => onChange({ dork_engines: v })}
        helperText="Each runs its own search for the target on top of the GoFuzz dorks."
      />
      <TagInput
        label="Custom Dorks"
        value={config.custom_dorks}
        onChange={(v) => onChange({ custom_dorks: v })}
        placeholder="site:_target_ ext:php"
        helperText={ruleCount > 0
          ? `Structured lookup_site dorks kept from the YAML: ${ruleCount}. Edit them in the YAML tab.`
          : undefined}
      />
      <Grid container spacing={2}>
        <Grid size={{ xs: 12, sm: 6 }}>
          <TextField
            label="Documents Limit"
            type="number"
            size="small"
            fullWidth
            disabled={!config.discover.includes('metainfo')}
            value={config.documents_limit}
            onChange={(e) => onChange({ documents_limit: Math.max(1, Number(e.target.value)) })}
            slotProps={{ htmlInput: { min: 1 } }}
            helperText="Documents inspected by the metainfo lookup"
            sx={fieldSx}
          />
        </Grid>
      </Grid>
      <OsintToolsFields config={config} onChange={onChange} />
      <OsintGithubFields config={config} onChange={onChange} />
    </SectionCard>
  );
};
