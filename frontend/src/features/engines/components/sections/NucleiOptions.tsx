import React from 'react';
import { Box, Checkbox, FormControlLabel, Grid, Typography } from '@mui/material';
import type { NucleiConfig } from '../../types/engineConfig';
import { BoundedNumberField } from '../shared/BoundedNumberField';
import { ChipSelect } from '../shared/ChipSelect';
import { TagInput } from '../shared/TagInput';
import { useScannerOptionStyles } from './scannerOptionStyles';

const SEVERITIES = ['unknown', 'info', 'low', 'medium', 'high', 'critical'];

interface Props {
  config: NucleiConfig;
  onChange: (next: NucleiConfig) => void;
}

/** `vulnerability_scan.nuclei`, read by nuclei_scan and GatherNucleiTagsActivity. */
export const NucleiOptions: React.FC<Props> = ({ config, onChange }) => {
  const { fieldSx, chkSx, subSectionSx } = useScannerOptionStyles();
  const set = (patch: Partial<NucleiConfig>) => onChange({ ...config, ...patch });

  const checkbox = (field: 'use_nuclei_config' | 'auto_update_templates', label: string) => (
    <FormControlLabel
      control={
        <Checkbox
          checked={config[field]}
          size="small"
          onChange={(e) => set({ [field]: e.target.checked })}
          sx={chkSx}
        />
      }
      label={<Typography variant="body2">{label}</Typography>}
    />
  );

  return (
    <Box sx={subSectionSx}>
      <Typography variant="caption" sx={{ color: 'text.secondary', display: 'block', mb: 1 }}>
        Nuclei Options
      </Typography>
      <Grid container spacing={2} sx={{ alignItems: 'center', mb: 1 }}>
        <Grid size={{ xs: 12, sm: 4 }}>{checkbox('use_nuclei_config', 'Use nuclei config file')}</Grid>
        <Grid size={{ xs: 12, sm: 4 }}>{checkbox('auto_update_templates', 'Update templates before scanning')}</Grid>
        <Grid size={{ xs: 12, sm: 4 }}>
          <BoundedNumberField
            label="Templates per batch"
            value={config.max_templates_per_batch}
            min={1}
            max={10000}
            onChange={(v) => set({ max_templates_per_batch: v })}
            helperText="Upper bound on templates in one tag batch"
            sx={fieldSx}
          />
        </Grid>
      </Grid>
      <ChipSelect
        label="Severities"
        options={SEVERITIES}
        value={config.severities}
        onChange={(v) => set({ severities: v })}
        helperText="None selected scans every severity"
      />
      <TagInput
        label="Tags"
        value={config.tags}
        onChange={(v) => set({ tags: v })}
        placeholder="cve,sqli"
        helperText="Added to the tags derived from detected technologies"
      />
      <TagInput
        label="Templates"
        value={config.templates}
        onChange={(v) => set({ templates: v })}
        placeholder="cves/2024/"
        helperText="Specific template paths; with none here or below, the full template tree runs"
      />
      <TagInput
        label="Custom Templates"
        value={config.custom_templates}
        onChange={(v) => set({ custom_templates: v })}
        helperText="Custom templates uploaded in r3ngine"
      />
    </Box>
  );
};
