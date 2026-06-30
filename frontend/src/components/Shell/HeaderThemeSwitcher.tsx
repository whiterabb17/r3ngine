import React, { useState } from 'react';
import {
  IconButton,
  Menu,
  MenuItem,
  Typography,
  Box,
  Tooltip,
  useTheme
} from '@mui/material';
import { alpha } from '@mui/material/styles';
import { Palette, Check } from 'lucide-react';
import type { ThemeType } from '../../theme/tokens';
import { selectableThemes, themeDefinitions } from '../../theme/tokens';
import { getMenuPaperSx } from '../../theme/semanticColors';

import { useAppTheme } from '../../context/ThemeContext';
import { useThemeTokens } from '../../theme/useThemeTokens';



export const HeaderThemeSwitcher: React.FC = () => {
  const { themeName, setTheme } = useAppTheme();
  const { tokens, isLight } = useThemeTokens();
  const theme = useTheme();
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);

  const handleOpen = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  const handleSelect = (name: ThemeType) => {
    setTheme(name);
    handleClose();
  };

  const getThemeDotColor = (id: ThemeType) => {
    switch (id) {
      case 'hacker': return '#bc13fe'; // Purple
      case 'modern': return '#0284c7'; // Blue (Enterprise blue)
      case 'v3_light': return '#f8fafc'; // Off-white
      default: return themeDefinitions[id].accent.primary;
    }
  };

  const themes: { id: ThemeType; label: string; color: string }[] = selectableThemes.map((item) => ({
    ...item,
    color: getThemeDotColor(item.id),
  }));
  return (
    <>
      <Tooltip title="Switch Theme">
        <IconButton
          onClick={handleOpen}
          size="small"
          sx={{
            color: anchorEl ? theme.palette.primary.main : alpha(theme.palette.text.secondary, 0.5),
            bgcolor: anchorEl ? alpha(theme.palette.primary.main, 0.1) : 'transparent',
            '&:hover': {
              color: theme.palette.primary.main,
              bgcolor: alpha(theme.palette.primary.main, 0.05),
            }
          }}
        >
          <Palette size={18} />
        </IconButton>
      </Tooltip>

      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleClose}
        slotProps={{
          paper: {
            sx: {
              ...getMenuPaperSx(isLight, theme, tokens),
              minWidth: 200,
              mt: 1.5,
              overflow: 'hidden',
            }
          }
        }}
        transformOrigin={{ horizontal: 'right', vertical: 'top' }}
        anchorOrigin={{ horizontal: 'right', vertical: 'bottom' }}
      >
        <Box sx={{ px: 2, py: 1.5, borderBottom: `1px solid ${alpha(theme.palette.divider, 0.1)}`, mb: 1 }}>
          <Typography sx={{
            fontSize: '0.7rem',
            color: theme.palette.primary.main,
            fontFamily: 'var(--r3-heading-font)',
            fontWeight: 800,
            letterSpacing: 1
          }}>
            THEME SELECTOR
          </Typography>
        </Box>

        {themes.map((t) => (
          <MenuItem
            key={t.id}
            onClick={() => handleSelect(t.id)}
            sx={{
              py: 1.5,
              px: 2.5,
              gap: 2,
              color: themeName === t.id ? theme.palette.primary.main : alpha(theme.palette.text.primary, 0.7),
              fontFamily: 'var(--r3-heading-font)',
              fontSize: '0.75rem',
              letterSpacing: '1px',
              '&:hover': {
                bgcolor: alpha(theme.palette.primary.main, 0.1),
                color: theme.palette.primary.main,
              }
            }}
          >
            <Box sx={{
              width: 10,
              height: 10,
              borderRadius: '50%',
              bgcolor: t.color,
              boxShadow: isLight ? 'none' : `0 0 5px ${t.color}`
            }} />
            <Typography sx={{ fontSize: 'inherit', fontFamily: 'inherit', fontWeight: 600, flexGrow: 1 }}>
              {t.label}
            </Typography>
            {themeName === t.id && <Check size={14} />}
          </MenuItem>
        ))}
      </Menu>
    </>
  );
};
