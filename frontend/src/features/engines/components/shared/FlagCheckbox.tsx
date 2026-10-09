import React from 'react';
import { Box, Checkbox, FormControlLabel, Typography } from '@mui/material';
import { useThemeTokens } from '../../../../theme/useThemeTokens';

interface FlagCheckboxProps {
  label: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
  /** One line under the label saying what the switch runs or when it is skipped. */
  hint?: string;
  disabled?: boolean;
}

/** A labelled engine switch with an optional one-line explanation. */
export const FlagCheckbox: React.FC<FlagCheckboxProps> = ({ label, checked, onChange, hint, disabled = false }) => {
  const { tokens } = useThemeTokens();
  const chkSx = { color: tokens.accent.primary, '&.Mui-checked': { color: tokens.accent.primary } };

  return (
    <FormControlLabel
      disabled={disabled}
      sx={{ alignItems: 'flex-start', mr: 0 }}
      control={
        <Checkbox
          size="small"
          checked={checked}
          onChange={(e) => onChange(e.target.checked)}
          sx={{ ...chkSx, pt: 0.5 }}
        />
      }
      label={
        <Box sx={{ pt: 0.5 }}>
          <Typography variant="body2">{label}</Typography>
          {hint && (
            <Typography variant="caption" sx={{ color: 'text.secondary', display: 'block' }}>
              {hint}
            </Typography>
          )}
        </Box>
      }
    />
  );
};
