/** Unified semantic token contract — single source of truth for all themes */

export type ThemeType =
  | 'hacker'
  | 'modern'
  | 'enterprise'
  | 'clean'
  | 'script_kiddie'
  | 'v3_light';

export interface ThemeTokenSet {
  mode: 'light' | 'dark';
  surface: {
    primary: string;
    secondary: string;
    glass: string;
    elevated: string;
  };
  text: {
    primary: string;
    secondary: string;
    muted: string;
    disabled: string;
  };
  border: {
    subtle: string;
    strong: string;
  };
  /** Sidebar + header surface — may diverge from content surface (e.g. enterprise's black chrome on an off-white content area) */
  chrome: {
    bg: string;
    text: string;
    textMuted: string;
    border: string;
    navDefault: string;
    navActive: string;
    navActiveBg: string;
  };
  accent: {
    primary: string;
    secondary: string;
    success: string;
    warning: string;
    error: string;
    info: string;
  };
  severity: {
    critical: string;
    high: string;
    medium: string;
    low: string;
    info: string;
    unknown: string;
  };
  chart: {
    series: string[];
    grid: string;
    tooltipBg: string;
    tooltipText: string;
  };
  effects: {
    blur: string;
    radius: string;
    bezier: string;
    glowPrimary: string;
    glowSecondary: string;
  };
  headingFont: 'orbitron' | 'inter';
  cyberEffects: boolean;
}

/** Backward-compatible shape used by legacy components */
export interface LegacyThemeTokens {
  bg: { primary: string; secondary: string; glass: string };
  neon: { cyan: string; pink: string; purple: string };
  cyber: {
    text: string;
    border: string;
    glow: { cyan: string; pink: string };
  };
  accent: ThemeTokenSet['accent'];
  severity: ThemeTokenSet['severity'];
}

export type ResolvedThemeTokens = ThemeTokenSet & LegacyThemeTokens;

const sharedEffects = {
  blur: 'blur(14px)',
  radius: '18px',
  bezier: 'cubic-bezier(0.32, 0.72, 0, 1)',
};

function toLegacy(set: ThemeTokenSet): LegacyThemeTokens {
  return {
    bg: {
      primary: set.surface.primary,
      secondary: set.surface.secondary,
      glass: set.surface.glass,
    },
    neon: {
      cyan: set.accent.primary,
      pink: set.accent.secondary,
      purple: set.accent.secondary,
    },
    cyber: {
      text: set.text.primary,
      border: set.border.subtle,
      glow: {
        cyan: set.effects.glowPrimary,
        pink: set.effects.glowSecondary,
      },
    },
    accent: set.accent,
    severity: set.severity,
  };
}

export function resolveThemeTokens(set: ThemeTokenSet): ResolvedThemeTokens {
  return { ...set, ...toLegacy(set) };
}

const hackerSet: ThemeTokenSet = {
  mode: 'dark',
  surface: {
    primary: '#0a0a0f',
    secondary: '#12121a',
    glass: 'rgba(12, 10, 20, 0.75)',
    elevated: '#12121a',
  },
  text: {
    primary: '#e0e0e0',
    secondary: 'rgba(224, 224, 224, 0.7)',
    muted: 'rgba(255, 255, 255, 0.4)',
    disabled: 'rgba(255, 255, 255, 0.2)',
  },
  border: {
    subtle: 'rgba(0, 243, 255, 0.2)',
    strong: 'rgba(0, 243, 255, 0.4)',
  },
  chrome: {
    bg: '#12121a',
    text: '#e0e0e0',
    textMuted: 'rgba(224, 224, 224, 0.5)',
    border: 'rgba(0, 243, 255, 0.1)',
    navDefault: '#00f3ff',
    navActive: '#bc13fe',
    navActiveBg: 'rgba(0, 243, 255, 0.15)',
  },
  accent: {
    primary: '#00f3ff',
    secondary: '#bc13fe',
    success: '#00ff62',
    warning: '#ff9f00',
    error: '#ff003c',
    info: '#00aaff',
  },
  severity: {
    critical: '#ff003c',
    high: '#ff9f00',
    medium: '#fffc00',
    low: '#00ff62',
    info: '#00f3ff',
    unknown: '#7000ff',
  },
  chart: {
    series: ['#7000ff', '#9020f0', '#b040ff', '#5500cc', '#c060ff', '#4400aa', '#d080ff', '#330088'],
    grid: 'rgba(255, 255, 255, 0.05)',
    tooltipBg: 'rgba(5, 5, 20, 0.95)',
    tooltipText: '#e0e0e0',
  },
  effects: {
    ...sharedEffects,
    glowPrimary: '0 0 15px rgba(0, 243, 255, 0.3)',
    glowSecondary: '0 0 15px rgba(255, 0, 255, 0.3)',
  },
  headingFont: 'orbitron',
  cyberEffects: true,
};

const modernSet: ThemeTokenSet = {
  ...hackerSet,
  surface: {
    primary: '#0f172a',
    secondary: '#1e293b',
    glass: 'rgba(15, 23, 42, 0.8)',
    elevated: '#1e293b',
  },
  text: {
    primary: '#f8fafc',
    secondary: 'rgba(248, 250, 252, 0.7)',
    muted: 'rgba(255, 255, 255, 0.4)',
    disabled: 'rgba(255, 255, 255, 0.2)',
  },
  border: {
    subtle: 'rgba(0, 243, 255, 0.15)',
    strong: 'rgba(0, 243, 255, 0.35)',
  },
  chrome: {
    bg: '#1e293b',
    text: '#f8fafc',
    textMuted: 'rgba(248, 250, 252, 0.5)',
    border: 'rgba(0, 243, 255, 0.1)',
    navDefault: '#00f3ff',
    navActive: '#bc13fe',
    navActiveBg: 'rgba(0, 243, 255, 0.15)',
  },
  effects: {
    ...sharedEffects,
    glowPrimary: '0 0 10px rgba(0, 243, 255, 0.2)',
    glowSecondary: '0 0 10px rgba(255, 0, 255, 0.2)',
  },
};

const enterpriseSet: ThemeTokenSet = {
  mode: 'light',
  surface: {
    primary: '#f5f3ef',
    secondary: '#ffffff',
    glass: 'rgba(245, 243, 239, 0.85)',
    elevated: '#ffffff',
  },
  text: {
    primary: '#141414',
    secondary: 'rgba(20, 20, 20, 0.7)',
    muted: 'rgba(20, 20, 20, 0.5)',
    disabled: 'rgba(20, 20, 20, 0.38)',
  },
  border: {
    subtle: '#e5e0d8',
    strong: '#d8d3ca',
  },
  chrome: {
    bg: '#141414',
    text: '#f5f3ef',
    textMuted: 'rgba(245, 243, 239, 0.55)',
    border: 'rgba(245, 243, 239, 0.1)',
    navDefault: 'rgba(245, 243, 239, 0.55)',
    navActive: '#f5f3ef',
    navActiveBg: '#9c1c2e',
  },
  accent: {
    primary: '#9c1c2e',
    secondary: '#57534e',
    success: '#059669',
    warning: '#d97706',
    error: '#dc2626',
    info: '#0ea5e9',
  },
  severity: {
    critical: '#dc2626',
    high: '#d97706',
    medium: '#b45309',
    low: '#059669',
    info: '#0284c7',
    unknown: '#6d28d9',
  },
  chart: {
    series: ['#9c1c2e', '#57534e', '#78716c', '#dc2626', '#a8a29e', '#44403c', '#d6d3d1', '#1c1917'],
    grid: 'rgba(20, 20, 20, 0.08)',
    tooltipBg: '#ffffff',
    tooltipText: '#141414',
  },
  effects: {
    blur: 'blur(8px)',
    radius: '8px',
    bezier: sharedEffects.bezier,
    glowPrimary: 'none',
    glowSecondary: 'none',
  },
  headingFont: 'inter',
  cyberEffects: false,
};

const v3LightSet: ThemeTokenSet = {
  mode: 'light',
  surface: {
    primary: '#f1f5f9',
    secondary: '#ffffff',
    glass: 'rgba(255, 255, 255, 0.85)',
    elevated: '#ffffff',
  },
  text: {
    primary: '#0f172a',
    secondary: 'rgba(15, 23, 42, 0.65)',
    muted: 'rgba(15, 23, 42, 0.45)',
    disabled: 'rgba(15, 23, 42, 0.35)',
  },
  border: {
    subtle: 'rgba(15, 23, 42, 0.08)',
    strong: 'rgba(15, 23, 42, 0.16)',
  },
  chrome: {
    bg: '#ffffff',
    text: '#0f172a',
    textMuted: 'rgba(15, 23, 42, 0.65)',
    border: 'rgba(14, 165, 233, 0.1)',
    navDefault: 'rgba(15, 23, 42, 0.65)',
    navActive: '#0ea5e9',
    navActiveBg: 'rgba(14, 165, 233, 0.15)',
  },
  accent: {
    primary: '#0ea5e9',
    secondary: '#8b5cf6',
    success: '#10b981',
    warning: '#f59e0b',
    error: '#ef4444',
    info: '#3b82f6',
  },
  severity: {
    critical: '#ef4444',
    high: '#f97316',
    medium: '#eab308',
    low: '#10b981',
    info: '#0ea5e9',
    unknown: '#8b5cf6',
  },
  chart: {
    series: ['#0ea5e9', '#8b5cf6', '#ec4899', '#06b6d4', '#6366f1', '#14b8a6', '#f472b6', '#3b82f6'],
    grid: 'rgba(15, 23, 42, 0.06)',
    tooltipBg: '#ffffff',
    tooltipText: '#0f172a',
  },
  effects: {
    ...sharedEffects,
    radius: '18px',
    glowPrimary: '0 0 10px rgba(14, 165, 233, 0.15)',
    glowSecondary: '0 0 10px rgba(236, 72, 153, 0.15)',
  },
  headingFont: 'inter',
  cyberEffects: false,
};

export const themeDefinitions: Record<ThemeType, ThemeTokenSet> = {
  hacker: hackerSet,
  modern: modernSet,
  enterprise: enterpriseSet,
  v3_light: v3LightSet,
  clean: modernSet,
  script_kiddie: hackerSet,
};

export const selectableThemes: Array<{ id: ThemeType; label: string }> = [
  { id: 'hacker', label: 'V3 Hacker' },
  { id: 'modern', label: 'V3 Hybrid' },
  { id: 'enterprise', label: 'V3 Enterprise' },
  { id: 'v3_light', label: 'V3 Light' },
];

export const sharedThemeEffects = sharedEffects;

/** @deprecated Use themeDefinitions + resolveThemeTokens + sharedThemeEffects */
export const themeTokens: Record<string, ResolvedThemeTokens> = {
  hacker: resolveThemeTokens(hackerSet),
  modern: resolveThemeTokens(modernSet),
  enterprise: resolveThemeTokens(enterpriseSet),
  v3_light: resolveThemeTokens(v3LightSet),
  clean: resolveThemeTokens(modernSet),
  script_kiddie: resolveThemeTokens(hackerSet),
};

export function getThemeTokenSet(themeName: ThemeType | string): ThemeTokenSet {
  const key = themeName === 'v3_awvs' ? 'v3_light' : themeName;
  return themeDefinitions[key as ThemeType] ?? hackerSet;
}

export function getResolvedTokens(themeName: ThemeType | string): ResolvedThemeTokens {
  return resolveThemeTokens(getThemeTokenSet(themeName));
}

/** CSS custom property names injected at runtime */
export const CSS_VAR_MAP = {
  '--r3-bg-primary': (t: ThemeTokenSet) => t.surface.primary,
  '--r3-bg-secondary': (t: ThemeTokenSet) => t.surface.secondary,
  '--r3-bg-glass': (t: ThemeTokenSet) => t.surface.glass,
  '--r3-bg-elevated': (t: ThemeTokenSet) => t.surface.elevated,
  '--r3-text-primary': (t: ThemeTokenSet) => t.text.primary,
  '--r3-text-secondary': (t: ThemeTokenSet) => t.text.secondary,
  '--r3-text-muted': (t: ThemeTokenSet) => t.text.muted,
  '--r3-text-disabled': (t: ThemeTokenSet) => t.text.disabled,
  '--r3-border-subtle': (t: ThemeTokenSet) => t.border.subtle,
  '--r3-border-strong': (t: ThemeTokenSet) => t.border.strong,
  '--r3-accent-primary': (t: ThemeTokenSet) => t.accent.primary,
  '--r3-accent-secondary': (t: ThemeTokenSet) => t.accent.secondary,
  '--r3-accent-success': (t: ThemeTokenSet) => t.accent.success,
  '--r3-accent-warning': (t: ThemeTokenSet) => t.accent.warning,
  '--r3-accent-error': (t: ThemeTokenSet) => t.accent.error,
  '--r3-accent-info': (t: ThemeTokenSet) => t.accent.info,
  '--r3-severity-critical': (t: ThemeTokenSet) => t.severity.critical,
  '--r3-severity-high': (t: ThemeTokenSet) => t.severity.high,
  '--r3-severity-medium': (t: ThemeTokenSet) => t.severity.medium,
  '--r3-severity-low': (t: ThemeTokenSet) => t.severity.low,
  '--r3-severity-info': (t: ThemeTokenSet) => t.severity.info,
  '--r3-severity-unknown': (t: ThemeTokenSet) => t.severity.unknown,
  '--r3-chart-grid': (t: ThemeTokenSet) => t.chart.grid,
  '--r3-chart-tooltip-bg': (t: ThemeTokenSet) => t.chart.tooltipBg,
  '--r3-chart-tooltip-text': (t: ThemeTokenSet) => t.chart.tooltipText,
  '--r3-effect-radius': (t: ThemeTokenSet) => t.effects.radius,
  '--r3-effect-bezier': (t: ThemeTokenSet) => t.effects.bezier,
} as const;

export function applyThemeCssVars(themeName: ThemeType | string): void {
  const set = getThemeTokenSet(themeName);
  const root = document.documentElement;
  for (const [varName, getter] of Object.entries(CSS_VAR_MAP)) {
    root.style.setProperty(varName, getter(set));
  }
  root.style.setProperty(
    '--r3-heading-font',
    set.headingFont === 'inter' ? '"Inter", sans-serif' : '"Orbitron", sans-serif'
  );
}
