import React from 'react';
import { Box, Typography } from '@mui/material';
import type { OsintConfig } from '../../types/engineConfig';
import { ChipSelect } from '../shared/ChipSelect';
import { FlagCheckbox } from '../shared/FlagCheckbox';
import { TagInput } from '../shared/TagInput';

/** Tools osint.github_analysis.uses_tools can list, in the order the backend runs them. */
const GITHUB_TOOLS = ['enumerepo', 'trufflehog', 'gitleaks', 'noseyparker', 'titus'];

interface Props {
  config: OsintConfig;
  onChange: (patch: Partial<OsintConfig>) => void;
}

/** osint.github_analysis: repository enumeration and secret scanning of the target's GitHub organisations. */
export const OsintGithubFields: React.FC<Props> = ({ config, onChange }) => {
  const noRepoList = config.github_analysis && !config.github_tools.includes('enumerepo');

  return (
    <Box sx={{ mt: 2 }}>
      <Typography variant="caption" sx={{ color: 'text.secondary', display: 'block', mb: 0.5 }}>
        GitHub
      </Typography>
      <FlagCheckbox
        label="GitHub organisation analysis"
        hint="Lists the organisation's repositories and scans them for secrets. Uses the GitHub API key from settings."
        checked={config.github_analysis}
        onChange={(checked) => onChange({ github_analysis: checked })}
      />
      {config.github_analysis && (
        <Box sx={{ pl: { xs: 0, sm: 4 }, mt: 1 }}>
          <ChipSelect
            label="Tools"
            options={GITHUB_TOOLS}
            value={config.github_tools}
            onChange={(v) => onChange({ github_tools: v })}
            helperText={noRepoList
              ? 'Without enumerepo no repositories are listed, so the secret scanners have nothing to scan.'
              : 'enumerepo lists the repositories; the other tools scan what it finds.'}
          />
          <TagInput
            label="GitHub organisations"
            value={config.github_orgs}
            onChange={(v) => onChange({ github_orgs: v })}
            placeholder="acme-corp"
            helperText="Leave empty to derive the organisation from the target domain."
          />
          <FlagCheckbox
            label="Gato"
            hint="Audits the organisations' GitHub Actions workflows; skipped without a GitHub API key."
            checked={config.github_gato}
            onChange={(checked) => onChange({ github_gato: checked })}
          />
        </Box>
      )}
    </Box>
  );
};
