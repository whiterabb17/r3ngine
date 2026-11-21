import React, { createContext, useContext, useEffect, useState, type ReactNode } from 'react';
import { ThemeProvider, CssBaseline } from '@mui/material';
import { hackerTheme, modernTheme, enterpriseTheme, v3LightTheme } from '../theme';
import type { Theme } from '@mui/material/styles';

import type { ThemeType } from '../theme/tokens';
import { applyThemeCssVars } from '../theme/tokens';

interface ThemeContextType {
  themeName: ThemeType;
  setTheme: (name: ThemeType) => void;
}

const ThemeContext = createContext<ThemeContextType | undefined>(undefined);

const themes: Record<string, Theme> = {
  hacker: hackerTheme,
  modern: modernTheme,
  enterprise: enterpriseTheme,
  clean: modernTheme,
  script_kiddie: hackerTheme,
  v3_light: v3LightTheme,
};

export const CustomThemeProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [themeName, setThemeName] = useState<ThemeType>(() => {
    const saved = localStorage.getItem('rengine-v3-theme');
    if (saved === 'hacker' || saved === 'modern' || saved === 'enterprise' || saved === 'v3_light' || saved === 'v3_awvs') {
      return saved === 'v3_awvs' ? 'v3_light' : saved as ThemeType;
    }
    return 'hacker';
  });

  const setTheme = (name: ThemeType) => {
    setThemeName(name);
    localStorage.setItem('rengine-v3-theme', name);
  };

  useEffect(() => {
    document.body.setAttribute('data-v3-theme', themeName);
    document.body.setAttribute('data-ui-version', 'v3');

    applyThemeCssVars(themeName);
    // Clear legacy global grain overlay (was painted above all UI)
    document.body.classList.remove('cyber-noise');
  }, [themeName]);

  const activeTheme = themes[themeName] || hackerTheme;

  return (
    <ThemeContext.Provider value={{ themeName, setTheme }}>
      <ThemeProvider theme={activeTheme}>
        <CssBaseline />
        {children}
      </ThemeProvider>
    </ThemeContext.Provider>
  );
};

export const useAppTheme = () => {
  const context = useContext(ThemeContext);
  if (context === undefined) {
    console.error('useAppTheme: Context is undefined. Ensure that the component is wrapped in <CustomThemeProvider>.');
    throw new Error('useAppTheme must be used within a CustomThemeProvider. If you see this, the component tree hierarchy is broken.');
  }
  return context;
};
