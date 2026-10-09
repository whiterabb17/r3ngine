import React from 'react';
import { TextField } from '@mui/material';
import type { SxProps, Theme } from '@mui/material/styles';

interface BoundedNumberFieldProps {
  label: string;
  value: number;
  min: number;
  max: number;
  onChange: (next: number) => void;
  /**
   * Makes 0 mean "not set": the field shows empty with this placeholder, and clearing it
   * writes 0. Without it, clearing the field writes `min`.
   */
  unsetLabel?: string;
  helperText?: string;
  sx?: SxProps<Theme>;
}

/** A whole-number field that keeps its value within the bounds the backend accepts. */
export const BoundedNumberField: React.FC<BoundedNumberFieldProps> = ({
  label, value, min, max, onChange, unsetLabel, helperText, sx,
}) => {
  const unset = unsetLabel !== undefined && value === 0;

  const handleChange = (raw: string) => {
    if (raw.trim() === '') {
      onChange(unsetLabel !== undefined ? 0 : min);
      return;
    }
    const parsed = Number(raw);
    if (Number.isFinite(parsed)) onChange(Math.min(max, Math.max(min, Math.round(parsed))));
  };

  return (
    <TextField
      label={label}
      type="number"
      size="small"
      fullWidth
      value={unset ? '' : value}
      placeholder={unsetLabel}
      onChange={(e) => handleChange(e.target.value)}
      helperText={helperText}
      slotProps={{
        htmlInput: { min, max, step: 1 },
        ...(unsetLabel !== undefined ? { inputLabel: { shrink: true } } : {}),
      }}
      sx={sx}
    />
  );
};
