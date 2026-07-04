import React from 'react';
import { Box, Chip, FormControl, InputLabel, MenuItem, OutlinedInput, Select } from '@mui/material';
import type { Tier7Config } from '../../types/engineConfig';
import { SectionCard } from '../shared/SectionCard';

interface Props {
  config: Tier7Config;
  enabled: boolean;
  onToggle: (v: boolean) => void;
  onChange: (p: Partial<Tier7Config>) => void;
}

export const Tier7Section: React.FC<Props> = ({ config, enabled, onToggle, onChange }) => {
  return (
    <SectionCard title="Finding Grouping" enabled={enabled} onToggle={onToggle}>
      <FormControl fullWidth size="small" disabled={!enabled}>
        <InputLabel id="high-noise-modules-label" sx={{ fontSize: '0.75rem', fontFamily: 'Orbitron', fontWeight: 600 }}>High Noise Modules</InputLabel>
        <Select
          labelId="high-noise-modules-label"
          multiple
          value={config.high_noise_modules || []}
          onChange={(e) => onChange({ high_noise_modules: typeof e.target.value === 'string' ? e.target.value.split(',') : e.target.value as string[] })}
          input={<OutlinedInput label="High Noise Modules" />}
          renderValue={(selected) => (
            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
              {selected.map((value: string) => (
                <Chip key={value} label={value} size="small" />
              ))}
            </Box>
          )}
        >
          {['sourcemap-detect', 'cookie-security-detect', 'exposed-panels', 'default-logins'].map((name) => (
            <MenuItem key={name} value={name}>
              {name}
            </MenuItem>
          ))}
        </Select>
      </FormControl>
    </SectionCard>
  );
};
