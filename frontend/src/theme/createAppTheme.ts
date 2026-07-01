import { createTheme, alpha, type Theme } from '@mui/material/styles';
import type { ThemeTokenSet } from './tokens';

const baseTypography = {
  fontFamily: '"Inter", "Cerebri Sans", sans-serif',
  h1: { fontFamily: 'var(--r3-heading-font)', letterSpacing: '2px' },
  h2: { fontFamily: 'var(--r3-heading-font)', letterSpacing: '2px' },
  h3: { fontFamily: 'var(--r3-heading-font)', letterSpacing: '2px' },
  h4: { fontFamily: 'var(--r3-heading-font)', letterSpacing: '2px' },
  h5: { fontFamily: 'var(--r3-heading-font)', letterSpacing: '1px' },
  h6: { fontFamily: 'var(--r3-heading-font)', letterSpacing: '1px' },
};

function createCyberComponents(tokens: ThemeTokenSet) {
  return {
    MuiCard: {
      styleOverrides: {
        root: {
          background: `linear-gradient(135deg, ${alpha(tokens.surface.secondary, 0.7)} 0%, ${alpha(tokens.surface.primary, 0.9)} 100%)`,
          backdropFilter: 'blur(25px) saturate(180%)',
          border: `1px solid ${alpha('#fff', 0.06)}`,
          boxShadow: `inset 0 1px 1px ${alpha('#fff', 0.15)}, 0 15px 35px rgba(0, 0, 0, 0.8)`,
          borderRadius: tokens.effects.radius,
          transition: `all 0.4s ${tokens.effects.bezier}`,
          '&:hover': {
            transform: 'translateY(-6px) scale(1.005)',
            boxShadow: tokens.effects.glowPrimary,
            borderColor: alpha(tokens.accent.primary, 0.4),
          },
        },
      },
    },
    MuiButton: {
      styleOverrides: {
        root: {
          textTransform: 'uppercase' as const,
          letterSpacing: '1px',
          fontWeight: 700,
          borderRadius: '8px',
          transition: `all 0.3s ${tokens.effects.bezier}`,
          '&:active': { transform: 'scale(0.98)' },
        },
        contained: {
          boxShadow: `0 0 10px ${alpha(tokens.accent.primary, 0.3)}`,
          '&:hover': {
            boxShadow: `0 0 20px ${alpha(tokens.accent.primary, 0.6)}`,
          },
        },
      },
    },
  };
}

function createLightCyberComponents(tokens: ThemeTokenSet) {
  return {
    MuiCard: {
      styleOverrides: {
        root: {
          background: `linear-gradient(135deg, ${alpha(tokens.surface.secondary, 0.9)} 0%, ${alpha(tokens.surface.primary, 0.95)} 100%)`,
          backdropFilter: 'blur(20px)',
          border: `1px solid ${tokens.border.subtle}`,
          boxShadow: '0 4px 20px rgba(0, 0, 0, 0.04), inset 0 1px 0 rgba(255, 255, 255, 0.6)',
          borderRadius: tokens.effects.radius,
          transition: `all 0.4s ${tokens.effects.bezier}`,
          '&:hover': {
            transform: 'translateY(-4px)',
            boxShadow: `0 8px 30px ${alpha(tokens.accent.primary, 0.12)}`,
            borderColor: alpha(tokens.accent.primary, 0.4),
          },
        },
      },
    },
    MuiButton: {
      styleOverrides: {
        root: {
          textTransform: 'uppercase' as const,
          letterSpacing: '1px',
          fontWeight: 700,
          borderRadius: '8px',
          transition: `all 0.3s ${tokens.effects.bezier}`,
          '&:active': { transform: 'scale(0.98)' },
        },
        contained: {
          boxShadow: `0 2px 8px ${alpha(tokens.accent.primary, 0.2)}`,
          '&:hover': {
            boxShadow: `0 4px 16px ${alpha(tokens.accent.primary, 0.4)}`,
          },
        },
      },
    },
  };
}

function createEnterpriseComponents(tokens: ThemeTokenSet) {
  return {
    MuiCard: {
      styleOverrides: {
        root: {
          backgroundColor: tokens.surface.secondary,
          border: `1px solid ${tokens.border.subtle}`,
          borderRadius: tokens.effects.radius,
          boxShadow: '0px 8px 30px rgba(0,0,0,0.04)',
          transition: `all 0.3s ${tokens.effects.bezier}`,
          '&:hover': {
            boxShadow: '0px 12px 40px rgba(0,0,0,0.06)',
            borderColor: tokens.border.strong,
          },
        },
      },
    },
    MuiButton: {
      styleOverrides: {
        root: {
          textTransform: 'none' as const,
          fontWeight: 600,
          borderRadius: tokens.effects.radius,
          transition: `all 0.2s ${tokens.effects.bezier}`,
        },
        contained: {
          boxShadow: '0 2px 8px rgba(0,0,0,0.05)',
          '&:hover': {
            boxShadow: '0 4px 12px rgba(0,0,0,0.08)',
          },
        },
      },
    },
  };
}

export function createAppTheme(tokens: ThemeTokenSet, variant: 'cyber' | 'light-cyber' | 'enterprise'): Theme {
  const isLight = tokens.mode === 'light';
  const shapeRadius = variant === 'enterprise' ? parseInt(tokens.effects.radius, 10) || 12 : parseInt(tokens.effects.radius, 10) || 18;

  const componentFactory =
    variant === 'enterprise'
      ? createEnterpriseComponents
      : variant === 'light-cyber'
        ? createLightCyberComponents
        : createCyberComponents;

  const bodyBg = tokens.surface.primary;
  const hackerBodyExtra =
    variant === 'cyber' && tokens.surface.primary === '#0a0a0f'
      ? `
        background-color: #05050a;
        background-image: linear-gradient(rgba(5, 5, 10, 0.5), rgba(5, 5, 10, 0.75)), url("/staticfiles/img/neon_city.png");
        background-size: cover;
        background-position: center;
        background-attachment: fixed;
        background-repeat: no-repeat;
      `
      : `background-color: ${bodyBg};`;

  return createTheme({
    palette: {
      mode: tokens.mode,
      primary: { main: tokens.accent.primary },
      secondary: { main: tokens.accent.secondary },
      success: { main: tokens.accent.success },
      warning: { main: tokens.accent.warning },
      error: { main: tokens.accent.error },
      info: { main: tokens.accent.info },
      background: {
        default: tokens.surface.primary,
        paper: tokens.surface.secondary,
      },
      text: {
        primary: tokens.text.primary,
        secondary: tokens.text.secondary,
        disabled: tokens.text.disabled,
      },
      divider: tokens.border.subtle,
      action: {
        hover: isLight ? alpha(tokens.text.primary, 0.04) : alpha(tokens.accent.primary, 0.05),
        selected: isLight ? alpha(tokens.accent.primary, 0.08) : alpha(tokens.accent.primary, 0.15),
      },
    },
    typography: {
      ...baseTypography,
      ...(variant === 'enterprise' && {
        h1: { ...baseTypography.h1, letterSpacing: '-0.02em' },
        h2: { ...baseTypography.h2, letterSpacing: '-0.01em' },
        h3: { ...baseTypography.h3, letterSpacing: '-0.01em' },
        h4: { ...baseTypography.h4, letterSpacing: '0em' },
        h5: { ...baseTypography.h5, letterSpacing: '0.01em' },
        h6: { ...baseTypography.h6, letterSpacing: '0.02em' },
      })
    },
    shape: { borderRadius: shapeRadius },
    components: {
      ...componentFactory(tokens),
      MuiCssBaseline: {
        styleOverrides: `
          body {
            ${hackerBodyExtra}
            color: ${tokens.text.primary};
          }
        `,
      },
    },
  });
}
