import React from 'react';
import { Autocomplete, TextField, Chip } from '@mui/material';
import { getFieldSx } from '../../../../theme/semanticColors';
import { useThemeTokens } from '../../../../theme/useThemeTokens';

interface TagInputProps {
  label: string;
  value: string[];
  onChange: (next: string[]) => void;
  placeholder?: string;
  helperText?: string;
  /** Maps a tag to the key used to detect duplicates; later duplicates are ignored. */
  dedupeKey?: (tag: string) => string;
}

const trimmed = (tag: string): string => tag.trim();

const withoutDuplicates = (tags: string[], dedupeKey: (tag: string) => string): string[] => {
  const seen = new Set<string>();
  return tags.filter((tag) => {
    const key = dedupeKey(tag);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
};

export const TagInput: React.FC<TagInputProps> = ({
  label,
  value,
  onChange,
  placeholder,
  helperText,
  dedupeKey = trimmed,
}) => {
  const { tokens, isLight } = useThemeTokens();

  return (
    <Autocomplete<string, true, false, true>
      multiple
      freeSolo
      options={[]}
      value={value}
      onChange={(_event, next) => onChange(withoutDuplicates(next, dedupeKey))}
      renderValue={(tagValues, getItemProps) =>
        tagValues.map((option, index) => {
          const { key, ...itemProps } = getItemProps({ index });
          return (
            <Chip
              key={key}
              {...itemProps}
              label={option}
              size="small"
              sx={{
                bgcolor: isLight ? tokens.accent.primary + '15' : tokens.accent.primary + '25',
                color: tokens.accent.primary,
                border: `1px solid ${tokens.accent.primary + '50'}`,
              }}
            />
          );
        })
      }
      renderInput={(params) => (
        <TextField
          {...params}
          label={label}
          placeholder={placeholder ?? 'Type and press Enter'}
          helperText={helperText}
          size="small"
          sx={getFieldSx(isLight, tokens)}
        />
      )}
      sx={{ mb: 2 }}
    />
  );
};
