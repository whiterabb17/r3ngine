import React from 'react';
import { Box, Chip, Typography } from '@mui/material';
import { useThemeTokens } from '../../../../theme/useThemeTokens';

interface ChipSelectProps {
  label: string;
  options: string[];
  value: string[];
  onChange: (next: string[]) => void;
  helperText?: string;
}

export const ChipSelect: React.FC<ChipSelectProps> = ({ label, options, value, onChange, helperText }) => {
  const { tokens, isLight } = useThemeTokens();
  const selected = new Set(value);

  const toggle = (opt: string) => {
    const next = selected.has(opt)
      ? value.filter((v) => v !== opt)
      : [...value, opt];
    onChange(next);
  };

  return (
    <Box sx={{ mb: 2 }}>
      <Typography variant="caption" sx={{ color: 'text.secondary', display: 'block', mb: 0.75 }}>
        {label}
      </Typography>
      <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.75 }}>
        {options.map((opt) => {
          const active = selected.has(opt);
          return (
            <Chip
              key={opt}
              label={opt}
              size="small"
              onClick={() => toggle(opt)}
              sx={{
                cursor: 'pointer',
                bgcolor: active
                  ? isLight ? tokens.accent.primary + '20' : tokens.accent.primary + '30'
                  : isLight ? 'rgba(0,0,0,0.06)' : 'rgba(255,255,255,0.06)',
                color: active ? tokens.accent.primary : 'text.secondary',
                border: `1px solid ${active ? tokens.accent.primary + '60' : 'transparent'}`,
                fontWeight: active ? 600 : 400,
                '&:hover': {
                  bgcolor: active
                    ? isLight ? tokens.accent.primary + '30' : tokens.accent.primary + '40'
                    : isLight ? 'rgba(0,0,0,0.10)' : 'rgba(255,255,255,0.10)',
                },
              }}
            />
          );
        })}
      </Box>
      {helperText && (
        <Typography variant="caption" sx={{ color: 'text.disabled', mt: 0.5, display: 'block' }}>
          {helperText}
        </Typography>
      )}
    </Box>
  );
};
