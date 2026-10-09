import React from 'react';
import { Box, Typography } from '@mui/material';
import type { PostCrawlOsintConfig } from '../../types/engineConfig';
import { SectionCard } from '../shared/SectionCard';
import { FlagCheckbox } from '../shared/FlagCheckbox';

interface Props {
  config: PostCrawlOsintConfig;
  enabled: boolean;
  onToggle: (v: boolean) => void;
  onChange: (p: Partial<PostCrawlOsintConfig>) => void;
}

export const PostCrawlOsintSection: React.FC<Props> = ({ config, enabled, onToggle, onChange }) => (
  <SectionCard
    title="Post-Crawl OSINT"
    description="Runs after directory fuzzing (Tier 4a), once live hosts are known."
    enabled={enabled}
    onToggle={onToggle}
  >
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }}>
      <FlagCheckbox
        label="Document metadata (exifray)"
        hint="Finds documents indexed for the domain and saves their author / producer metadata."
        checked={config.metagoofil}
        onChange={(checked) => onChange({ metagoofil: checked })}
      />
      <FlagCheckbox
        label="SwaggerSpy path probe"
        hint="Probes every live subdomain for common Swagger / OpenAPI spec paths."
        checked={config.swaggerspy}
        onChange={(checked) => onChange({ swaggerspy: checked })}
      />
    </Box>
    <Typography variant="caption" sx={{ color: 'text.secondary', display: 'block', mt: 1 }}>
      CredSpy, switched on in the OSINT card, also runs in this step and schedules it by itself.
    </Typography>
  </SectionCard>
);
