import { useThemeTokens } from '../theme/useThemeTokens';
import React from 'react';
import { MenuItem, Typography, Box } from '@mui/material';
import { alpha } from '@mui/material/styles';
import { Palette, Check } from 'lucide-react';
import { useAppTheme } from '../context/ThemeContext';
import { selectableThemes, themeDefinitions } from '../theme/tokens';

export const ThemeSwitcher: React.FC = () => {
  const { tokens, isLight } = useThemeTokens();
  const { themeName, setTheme } = useAppTheme();

  const themes = selectableThemes.map((item) => ({
    ...item,
    color: themeDefinitions[item.id].accent.primary,
  }));

  return (
    <>
      <Box sx={{ px: 2.5, py: 1.5, display: 'flex', alignItems: 'center', gap: 1.5, color: 'text.secondary' }}>
        <Palette size={14} />
        <Typography sx={{ fontSize: '0.7rem', fontWeight: 600, letterSpacing: 0.5, textTransform: 'uppercase' }}>
          Interface Theme
        </Typography>
      </Box>
      
      {themes.map((t) => (
        <MenuItem 
          key={t.id} 
          onClick={() => setTheme(t.id)}
          sx={{ 
            display: 'flex', 
            alignItems: 'center', 
            justifyContent: 'space-between',
            bgcolor: themeName === t.id ? alpha(tokens.accent.primary, isLight ? 0.08 : 0.12) : 'transparent',
            color: themeName === t.id ? tokens.accent.primary : 'text.primary',
            '&:hover': {
              bgcolor: alpha(tokens.accent.primary, isLight ? 0.08 : 0.14),
            },
          }}
        >
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <Box sx={{ width: 10, height: 10, borderRadius: '50%', bgcolor: t.color, boxShadow: isLight ? 'none' : `0 0 5px ${t.color}` }} />
            <Typography sx={{ fontSize: 'inherit', fontFamily: 'inherit', fontWeight: 600 }}>
              {t.label}
            </Typography>
          </Box>
          {themeName === t.id && <Check size={14} style={{ color: t.color }} />}
        </MenuItem>
      ))}
    </>
  );
};
