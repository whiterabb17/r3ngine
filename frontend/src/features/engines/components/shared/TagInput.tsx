import React from 'react';
import { Autocomplete as MuiAutocomplete, TextField, Chip } from '@mui/material';
import { getFieldSx } from '../../../../theme/semanticColors';
import { useThemeTokens } from '../../../../theme/useThemeTokens';

interface TagInputProps {
  label: string;
  value: string[];
  onChange: (next: string[]) => void;
  placeholder?: string;
  helperText?: string;
}

const Autocomplete = MuiAutocomplete as any;

export const TagInput: React.FC<TagInputProps> = ({ label, value, onChange, placeholder, helperText }) => {
  const { tokens, isLight } = useThemeTokens();

  const renderTags = (tagValues: string[], getTagProps: any) =>
    tagValues.map((option: string, index: number) => (
      <Chip
        {...getTagProps({ index })}
        key={option}
        label={option}
        size="small"
        sx={{
          bgcolor: isLight ? tokens.accent.primary + '15' : tokens.accent.primary + '25',
          color: tokens.accent.primary,
          border: `1px solid ${tokens.accent.primary + '50'}`,
        }}
      />
    ));

  return (
    <Autocomplete
      multiple
      freeSolo
      options={[]}
      value={value}
      onChange={(_: any, next: string[]) => onChange(next)}
      renderTags={renderTags}
      renderInput={(params: any) => (
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
