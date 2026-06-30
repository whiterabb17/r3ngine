import { useThemeTokens } from '../theme/useThemeTokens';
import React from 'react';
import { Box, Typography, Card, CardContent } from '@mui/material';
import { alpha } from '@mui/material/styles';
import type { SxProps, Theme } from '@mui/material';
import { getSurfaceSx } from '../theme/semanticColors';

export interface KpiCardProps {
  title: string;
  value: number | string;
  icon: React.ComponentType<{ size?: number }>;
  color: string;
  subtitle?: string;
  className?: string;
  sx?: SxProps<Theme>;
  onClick?: () => void;
}

export const KpiCard: React.FC<KpiCardProps> = ({ title, value, icon: Icon, color, subtitle, sx, onClick }) => {
  const { tokens, theme, isLight } = useThemeTokens();

  return (
    <Card
      onClick={onClick}
      sx={{
        height: '100%',
        ...getSurfaceSx(isLight, tokens, theme),
        backdropFilter: 'blur(12px)',
        position: 'relative',
        overflow: 'hidden',
        borderRadius: isLight ? '8px' : '12px',
        transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
        cursor: onClick ? 'pointer' : 'default',
        '&:hover': {
          transform: 'translateY(-4px)',
          borderColor: color,
          boxShadow: isLight ? `0 4px 20px ${alpha(color, 0.1)}` : `0 0 15px ${alpha(color, 0.13)}`,
          '& .kpi-icon-bg': { opacity: 0.15, transform: 'scale(1.1) rotate(-10deg)' }
        },
        ...sx
      }}
    >
      <CardContent sx={{ p: 3 }}>
        {/* Watermark Icon */}
        <Box
          className="kpi-icon-bg"
          sx={{
            position: 'absolute',
            right: -15,
            top: -15,
            opacity: isLight ? 0.05 : 0.08,
            transition: 'all 0.3s ease',
            color: color
          }}
        >
          <Icon size={100} />
        </Box>

        {/* Header Row */}
        <Box sx={{ display: 'flex', alignItems: 'center', mb: 2.5 }}>
          <Box sx={{
            p: 1.2,
            borderRadius: 2,
            bgcolor: alpha(color, 0.08),
            color: color,
            display: 'flex',
            mr: 1.5,
            border: `1px solid ${alpha(color, 0.2)}`,
            boxShadow: isLight ? 'none' : `0 0 15px ${alpha(color, 0.13)}`
          }}>
            <Icon size={22} />
          </Box>
          <Typography variant="overline" sx={{
            fontWeight: 800,
            letterSpacing: 2,
            color: tokens.text.secondary,
            fontFamily: 'var(--r3-heading-font)',
            lineHeight: 1
          }}>
            {title}
          </Typography>
        </Box>

        {/* Value Row */}
        <Typography variant="h3" sx={{
          fontWeight: 900,
          mb: 0.5,
          fontFamily: 'var(--r3-heading-font)',
          letterSpacing: -1,
          color: tokens.text.primary
        }}>
          {typeof value === 'number' ? value.toLocaleString() : value}
        </Typography>

        {/* Footer Row */}
        {subtitle && (
          <Box sx={{ display: 'flex', alignItems: 'center' }}>
            <Box
              sx={{
                width: 6,
                height: 6,
                borderRadius: '50%',
                bgcolor: color,
                mr: 1,
                boxShadow: isLight ? 'none' : `0 0 8px ${color}`
              }}
            />
            <Typography variant="caption" sx={{
              color: tokens.text.muted,
              fontWeight: 800,
              fontSize: '0.65rem',
              letterSpacing: 1
            }}>
              {subtitle.toUpperCase()}
            </Typography>
          </Box>
        )}
      </CardContent>
    </Card>
  );
};
