import React from 'react';
import { Box, Card, CardContent, Typography, useTheme } from '@mui/material';
import { alpha } from '@mui/material/styles';
import clsx from 'clsx';
import { useThemeTokens } from '../theme/useThemeTokens';
import { getElevatedSurfaceSx } from '../theme/semanticColors';

interface TacticalPanelProps {
  title?: string;
  icon?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  borderColor?: string;
  sx?: any;
  headerAction?: React.ReactNode;
}

export const TacticalPanel: React.FC<TacticalPanelProps> = ({ 
  title, 
  icon, 
  children, 
  className,
  borderColor,
  sx = {},
  headerAction
}) => {
  const { theme, isLight, tokens } = useThemeTokens();
  const accentBorder = borderColor || tokens.accent.primary;
  const surfaceSx = getElevatedSurfaceSx(isLight, theme, tokens);

  return (
    <Card 
      className={clsx("relative overflow-hidden group transition-all duration-500", className)}
      sx={{ 
        ...surfaceSx,
        background: isLight
          ? surfaceSx.bgcolor
          : `linear-gradient(135deg, ${alpha(tokens.surface.secondary, 0.72)} 0%, ${alpha(tokens.surface.elevated, 0.92)} 100%)`,
        backdropFilter: isLight ? surfaceSx.backdropFilter : 'blur(25px) saturate(180%)',
        borderRadius: theme.spacing(1),
        position: 'relative',
        boxShadow: isLight
          ? surfaceSx.boxShadow
          : `inset 0 0 30px ${alpha('#000', 0.45)}, 0 15px 35px ${alpha('#000', 0.72)}`,
        /* Minimal hover effect to prevent huge tables from getting too hectic */
        '&:hover': {
          borderColor: isLight ? theme.palette.primary.main : alpha(accentBorder, 0.28),
        },
        ...sx,
        /* Dual Gradient Glow - Disabled in light mode */
        '&::before': {
          content: '""',
          position: 'absolute',
          inset: 0,
          borderRadius: 'inherit',
          background: `radial-gradient(circle at 20% 20%, ${alpha(tokens.accent.secondary, 0.14)}, transparent 50%), radial-gradient(circle at 80% 80%, ${alpha(tokens.accent.primary, 0.1)}, transparent 50%)`,
          opacity: isLight ? 0 : 0.6,
          pointerEvents: 'none',
          zIndex: 0
        }
      }}
    >
      <CardContent sx={{ position: 'relative', zIndex: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 2.5, justifyContent: 'space-between' }}>
            <Box sx={{ display: 'flex', alignItems: 'center' }}>
              {icon && (
                <Box sx={{ 
                  mr: 1.5, 
                  display: 'flex', 
                  filter: isLight ? 'none' : `drop-shadow(0 0 5px ${alpha(tokens.accent.primary, 0.5)})`
                }}>
                  {icon}
                </Box>
              )}
              <Typography variant="h6" sx={{ 
                fontSize: '0.75rem', 
                fontWeight: 800, 
                textTransform: 'uppercase', 
                letterSpacing: 2.5,
                fontFamily: 'var(--r3-heading-font)',
                color: isLight ? theme.palette.text.primary : tokens.text.secondary,
                textShadow: isLight ? 'none' : `0 0 10px ${alpha(tokens.accent.secondary, 0.38)}`
              }}>
                {title}
              </Typography>
            </Box>
            {headerAction && <Box>{headerAction}</Box>}
          </Box>
        {children}
      </CardContent>
    </Card>
  );
};
