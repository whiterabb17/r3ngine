import type { Theme } from '@mui/material/styles';
import { alpha } from '@mui/material/styles';
import type { ResolvedThemeTokens, ThemeTokenSet } from './tokens';
import { getResolvedTokens } from './tokens';

export type SeverityLevel =
  | 'critical'
  | 'high'
  | 'medium'
  | 'low'
  | 'info'
  | 'unknown'
  | number
  | string;

function normalizeSeverity(severity: SeverityLevel): keyof ThemeTokenSet['severity'] {
  if (typeof severity === 'number') {
    if (severity === 4) return 'critical';
    if (severity === 3) return 'high';
    if (severity === 2) return 'medium';
    if (severity === 1) return 'low';
    if (severity === 0) return 'info';
    return 'unknown';
  }
  const s = String(severity).toLowerCase();
  if (s === 'critical' || s === '4') return 'critical';
  if (s === 'high' || s === '3') return 'high';
  if (s === 'medium' || s === '2') return 'medium';
  if (s === 'low' || s === '1') return 'low';
  if (s === 'info' || s === '0') return 'info';
  return 'unknown';
}

export function getSeverityColor(
  severity: SeverityLevel,
  tokens: Pick<ResolvedThemeTokens, 'severity'>
): string {
  return tokens.severity[normalizeSeverity(severity)];
}

export function getSeverityLabel(severity: SeverityLevel): string {
  const key = normalizeSeverity(severity);
  return key.toUpperCase();
}

export function getHttpStatusColor(
  status: number,
  tokens: Pick<ResolvedThemeTokens, 'accent' | 'severity' | 'text'>
): string {
  if (status >= 200 && status < 300) return tokens.accent.success;
  if (status >= 300 && status < 400) return tokens.accent.info;
  if (status >= 400 && status < 500) return tokens.accent.warning;
  if (status >= 500) return tokens.accent.error;
  return tokens.text.disabled;
}

export function getChartSeriesColors(tokens: Pick<ResolvedThemeTokens, 'chart'>): string[] {
  return tokens.chart.series;
}

/** Surface styles for glass/elevated cards — theme-aware */
export function getSurfaceSx(isLight: boolean, tokens: ResolvedThemeTokens, theme?: Theme) {
  if (isLight) {
    return {
      bgcolor: tokens.surface.elevated,
      border: `1px solid ${tokens.border.subtle}`,
      boxShadow: '0 4px 20px rgba(0, 0, 0, 0.04), inset 0 1px 0 rgba(255, 255, 255, 0.6)',
    };
  }
  return {
    bgcolor: alpha(theme?.palette.background.paper || tokens.surface.elevated, 0.72),
    backdropFilter: 'blur(10px)',
    border: `1px solid ${tokens.border.subtle}`,
  };
}

export function getElevatedSurfaceSx(isLight: boolean, theme: Theme, tokens: ResolvedThemeTokens) {
  if (isLight) {
    return {
      bgcolor: theme.palette.background.paper,
      border: `1px solid ${theme.palette.divider}`,
      borderRadius: 1,
      boxShadow: theme.shadows[2],
    };
  }
  return {
    bgcolor: alpha(tokens.surface.elevated, 0.82),
    backdropFilter: 'blur(14px)',
    border: `1px solid ${tokens.border.subtle}`,
    borderRadius: 1,
    boxShadow: `0 12px 36px ${alpha('#000', 0.55)}`,
  };
}

/** Menu/dropdown paper styles */
export function getMenuPaperSx(isLight: boolean, theme: Theme, tokens: ResolvedThemeTokens) {
  if (isLight) {
    return {
      bgcolor: theme.palette.background.paper,
      backdropFilter: 'blur(12px)',
      border: `1px solid ${theme.palette.divider}`,
      borderRadius: 1,
      boxShadow: theme.shadows[4],
    };
  }
  return {
    bgcolor: alpha(tokens.surface.elevated, 0.95),
    backdropFilter: 'blur(12px)',
    border: `1px solid ${tokens.border.subtle}`,
    borderRadius: 1,
    boxShadow: `0 8px 32px ${alpha('#000', 0.78)}`,
  };
}

export function getDialogPaperSx(isLight: boolean, theme: Theme, tokens: ResolvedThemeTokens) {
  return {
    ...getElevatedSurfaceSx(isLight, theme, tokens),
    color: theme.palette.text.primary,
    borderRadius: 1,
  };
}

export function getFieldSx(isLight: boolean, tokens: ResolvedThemeTokens, accent = tokens.accent.primary) {
  return {
    '& .MuiOutlinedInput-root': {
      color: 'text.primary',
      '& fieldset': { borderColor: isLight ? tokens.border.subtle : alpha(tokens.text.primary, 0.12) },
      '&:hover fieldset': { borderColor: accent },
      '&.Mui-focused fieldset': { borderColor: accent },
    },
    '& .MuiInputLabel-root': { color: 'text.secondary' },
  };
}

export function getSemanticColors(themeName: string) {
  const tokens = getResolvedTokens(themeName);
  const isLight = tokens.mode === 'light';
  return {
    tokens,
    isLight,
    isCyber: tokens.cyberEffects,
    severity: (level: SeverityLevel) => getSeverityColor(level, tokens),
    httpStatus: (status: number) => getHttpStatusColor(status, tokens),
    chartSeries: () => getChartSeriesColors(tokens),
    surface: (theme?: Theme) => getSurfaceSx(isLight, tokens, theme),
    elevatedSurface: (theme: Theme) => getElevatedSurfaceSx(isLight, theme, tokens),
    menuPaper: (theme: Theme) => getMenuPaperSx(isLight, theme, tokens),
    dialogPaper: (theme: Theme) => getDialogPaperSx(isLight, theme, tokens),
    field: (accent?: string) => getFieldSx(isLight, tokens, accent),
  };
}
