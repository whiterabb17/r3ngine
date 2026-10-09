import React from 'react';
import {
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  ListSubheader,
  FormHelperText,
} from '@mui/material';
import type { SelectChangeEvent } from '@mui/material';
import { useScanProfiles } from '../api';
import type { ScanProfile } from '../types';

import { useThemeTokens } from '../../../theme/useThemeTokens';
import type { ResolvedThemeTokens } from '../../../theme/tokens';

interface ProfileSelectorProps {
  value: string | null;
  onChange: (profileName: string | null) => void;
  disabled?: boolean;
}

const CATEGORY_LABELS: Record<ScanProfile['category'], string> = {
  speed: 'Speed',
  evasion: 'Evasion',
  content: 'Content',
  network: 'Network',
  general: 'General',
  hardware: 'Hardware',
};

const CATEGORY_ORDER: ScanProfile['category'][] = [
  'general',
  'speed',
  'network',
  'content',
  'evasion',
  'hardware',
];

const fieldStyles = (tokens: ResolvedThemeTokens) => ({
  '& .MuiOutlinedInput-root': {
    color: 'text.primary',
    '& fieldset': { borderColor: 'rgba(255,255,255,0.1)' },
    '&:hover fieldset': { borderColor: `${tokens.accent.primary}4D` },
    '&.Mui-focused fieldset': { borderColor: tokens.accent.primary },
    bgcolor: 'action.hover',
  },
  '& .MuiInputLabel-root': {
    color: 'text.secondary',
    '&.Mui-focused': { color: tokens.accent.primary },
  },
  '& .MuiSelect-icon': { color: 'text.secondary' },
  '& .MuiFormHelperText-root': { color: 'text.disabled' },
});

export const ProfileSelector: React.FC<ProfileSelectorProps> = ({
  value,
  onChange,
  disabled = false,
}) => {
  const { tokens } = useThemeTokens();
  const { data: profiles, isLoading } = useScanProfiles();

  const handleChange = (event: SelectChangeEvent<string>) => {
    const selected = event.target.value;
    onChange(selected === '' ? null : selected);
  };

  const selectedProfile = profiles?.find((p) => p.name === value) ?? null;

  const groupedProfiles = React.useMemo(() => {
    if (!profiles) return new Map<ScanProfile['category'], ScanProfile[]>();
    const map = new Map<ScanProfile['category'], ScanProfile[]>();
    for (const profile of profiles) {
      const group = map.get(profile.category) ?? [];
      group.push(profile);
      map.set(profile.category, group);
    }
    return map;
  }, [profiles]);

  const menuItems: React.ReactNode[] = [];
  menuItems.push(
    <MenuItem key="__default__" value="">
      Default (no profile)
    </MenuItem>
  );

  for (const category of CATEGORY_ORDER) {
    const group = groupedProfiles.get(category);
    if (!group || group.length === 0) continue;
    menuItems.push(
      <ListSubheader
        key={`header-${category}`}
        sx={{
          bgcolor: 'rgba(0,0,0,0.7)',
          color: `${tokens.accent.primary}B3`,
          fontWeight: 800,
          fontSize: '0.65rem',
          letterSpacing: 1,
          lineHeight: '28px',
        }}
      >
        {CATEGORY_LABELS[category].toUpperCase()}
      </ListSubheader>
    );
    for (const profile of group) {
      menuItems.push(
        <MenuItem key={profile.name} value={profile.name}>
          {profile.name}
          {profile.is_builtin ? ' (built-in)' : ''}
        </MenuItem>
      );
    }
  }

  // Include any categories not in CATEGORY_ORDER
  for (const [category, group] of groupedProfiles.entries()) {
    if (CATEGORY_ORDER.includes(category)) continue;
    menuItems.push(
      <ListSubheader
        key={`header-${category}`}
        sx={{
          bgcolor: 'rgba(0,0,0,0.7)',
          color: `${tokens.accent.primary}B3`,
          fontWeight: 800,
          fontSize: '0.65rem',
          letterSpacing: 1,
          lineHeight: '28px',
        }}
      >
        {category.toUpperCase()}
      </ListSubheader>
    );
    for (const profile of group) {
      menuItems.push(
        <MenuItem key={profile.name} value={profile.name}>
          {profile.name}
          {profile.is_builtin ? ' (built-in)' : ''}
        </MenuItem>
      );
    }
  }

  const helperText = selectedProfile?.description ?? '';

  return (
    <FormControl fullWidth sx={fieldStyles(tokens)} disabled={disabled || isLoading}>
      <InputLabel id="profile-selector-label">Scan Profile</InputLabel>
      <Select
        labelId="profile-selector-label"
        id="profile-selector"
        value={isLoading ? '' : (value ?? '')}
        label="Scan Profile"
        onChange={handleChange}
        MenuProps={{
          slotProps: { paper: {
            sx: {
              bgcolor: 'background.default',
              border: 1, borderColor: 'divider',
              '& .MuiMenuItem-root': {
                color: 'text.primary',
                '&:hover': { bgcolor: 'action.hover' },
                '&.Mui-selected': {
                  bgcolor: `${tokens.accent.primary}1F`,
                  '&:hover': { bgcolor: `${tokens.accent.primary}29` },
                },
              },
            },
          } },
        }}
      >
        {isLoading ? (
          <MenuItem value="" disabled>
            Loading profiles…
          </MenuItem>
        ) : (
          menuItems
        )}
      </Select>
      {helperText && <FormHelperText>{helperText}</FormHelperText>}
    </FormControl>
  );
};
