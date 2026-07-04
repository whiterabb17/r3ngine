import React from 'react';
import { Box, Card, Typography, Switch, FormControlLabel } from '@mui/material';
import { useThemeTokens } from '../../../../theme/useThemeTokens';

interface SectionCardProps {
  title: string;
  description?: string;
  enabled: boolean;
  onToggle: (enabled: boolean) => void;
  children: React.ReactNode;
  /** Pass true for sections whose enable state is controlled by a YAML run_* field (always shown) */
  alwaysShow?: boolean;
}

export const SectionCard: React.FC<SectionCardProps> = ({
  title,
  description,
  enabled,
  onToggle,
  children,
  alwaysShow = false,
}) => {
  const { tokens, isLight } = useThemeTokens();

  return (
    <Card
      sx={{
        mb: 2,
        bgcolor: isLight ? 'background.paper' : 'rgba(10, 10, 20, 0.4)',
        border: isLight
          ? `1px solid ${enabled ? tokens.accent.primary + '40' : 'rgba(0,0,0,0.08)'}`
          : `1px solid ${enabled ? tokens.accent.primary + '40' : 'rgba(255,255,255,0.05)'}`,
        borderRadius: 1,
        overflow: 'hidden',
        transition: 'border-color 0.2s ease',
      }}
    >
      {/* Header */}
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          px: 2,
          py: 1.25,
          bgcolor: isLight ? 'rgba(0,0,0,0.03)' : 'rgba(255,255,255,0.03)',
          borderBottom: isLight ? '1px solid rgba(0,0,0,0.06)' : '1px solid rgba(255,255,255,0.04)',
        }}
      >
        <Box>
          <Typography variant="subtitle2" sx={{ fontWeight: 600, color: enabled ? 'text.primary' : 'text.disabled' }}>
            {title}
          </Typography>
          {description && (
            <Typography variant="caption" sx={{ color: 'text.secondary' }}>
              {description}
            </Typography>
          )}
        </Box>
        {!alwaysShow && (
          <FormControlLabel
            control={
              <Switch
                size="small"
                checked={enabled}
                onChange={(e) => onToggle(e.target.checked)}
                sx={{
                  '& .MuiSwitch-switchBase.Mui-checked': { color: tokens.accent.primary },
                  '& .MuiSwitch-switchBase.Mui-checked + .MuiSwitch-track': { bgcolor: tokens.accent.primary },
                }}
              />
            }
            label={
              <Typography variant="caption" sx={{ color: enabled ? tokens.accent.primary : 'text.disabled' }}>
                {enabled ? 'Enabled' : 'Disabled'}
              </Typography>
            }
            labelPlacement="start"
            sx={{ mr: 0, ml: 0 }}
          />
        )}
      </Box>

      {/* Body */}
      <Box
        sx={{
          px: 2,
          py: 2,
          opacity: enabled ? 1 : 0.4,
          pointerEvents: enabled ? 'auto' : 'none',
          transition: 'opacity 0.2s ease',
        }}
      >
        {children}
      </Box>
    </Card>
  );
};
