import React from 'react';
import { Box, InputBase, Stack, Button, ToggleButtonGroup, ToggleButton, Tooltip } from '@mui/material';
import { Search, Maximize, RefreshCw, Download, Sparkles, LayoutList, Network } from 'lucide-react';
import { useGraphStore } from '../../../store/useGraphStore';
import { useThemeTokens } from '../../../theme/useThemeTokens';

interface Props {
  searchQuery: string;
  onSearch: (query: string) => void;
  onResetZoom: () => void;
  onRefreshLayout: () => void;
  onExport: () => void;
  layoutName: 'fcose' | 'klay' | 'cose';
  onChangeLayout: (layout: 'fcose' | 'klay' | 'cose') => void;
}

export const GraphControlPanel: React.FC<Props> = ({
  searchQuery,
  onSearch,
  onResetZoom,
  onRefreshLayout,
  onExport,
  layoutName,
  onChangeLayout
}) => {
  const { tokens, theme } = useThemeTokens();
  return (
    <Box sx={{ 
      p: 2, 
      display: 'flex', 
      flexDirection: { xs: 'column', md: 'row' }, 
      flexWrap: 'wrap', 
      gap: 2, 
      alignItems: { xs: 'stretch', md: 'center' }, 
      borderBottom: 1, borderColor: 'divider' 
    }}>
       <Box sx={{ 
          display: 'flex', 
          bgcolor: 'action.hover',
          borderRadius: 1, 
          border: `1px solid ${tokens.border.subtle}`,
          width: { xs: '100%', md: '400px' },
          boxShadow: theme.shadows[1],
          alignItems: 'center'
       }}>
          <Box sx={{ p: 1, color: tokens.accent.primary }}><Sparkles size={16} /></Box>
          <InputBase 
            placeholder="Search assets..." 
            value={searchQuery}
            onChange={(e) => onSearch(e.target.value)}
            sx={{ flex: 1, color: 'text.primary', fontSize: '0.8rem', fontStyle: 'italic' }} 
          />
       </Box>
       <Stack direction="row" spacing={1} sx={{ flexWrap: 'wrap', gap: 1 }}>
          <ToggleButtonGroup
            value={layoutName}
            exclusive
            onChange={(e, newLayout) => newLayout && onChangeLayout(newLayout as any)}
            size="small"
            sx={{ 
                bgcolor: 'action.hover',
                '& .MuiToggleButton-root': {
                    color: 'text.secondary',
                    border: `1px solid ${tokens.border.subtle}`,
                    p: '4px 8px',
                    '&.Mui-selected': {
                        color: tokens.accent.primary,
                        bgcolor: `${tokens.accent.primary}15`,
                        borderColor: `${tokens.accent.primary}4D`
                    }
                }
            }}
          >
              <ToggleButton value="fcose">
                  <Tooltip title="Force Layout (Infrastructure Exploration)">
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                          <Network size={14} /> <Box sx={{ fontSize: '10px', fontWeight: 700 }}>fCoSE</Box>
                      </Box>
                  </Tooltip>
              </ToggleButton>
              <ToggleButton value="klay">
                  <Tooltip title="Hierarchical Layout (Attack Paths)">
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                          <LayoutList size={14} /> <Box sx={{ fontSize: '10px', fontWeight: 700 }}>KLay</Box>
                      </Box>
                  </Tooltip>
              </ToggleButton>
          </ToggleButtonGroup>

          <Button size="small" startIcon={<Maximize size={14} />} onClick={onResetZoom} sx={{ bgcolor: `${tokens.accent.info}1A`, color: tokens.accent.info, fontSize: '0.7rem', fontWeight: 800 }}>RESET</Button>
          <Button size="small" startIcon={<RefreshCw size={14} />} onClick={onRefreshLayout} sx={{ bgcolor: `${tokens.accent.secondary}1A`, color: tokens.accent.secondary, fontSize: '0.7rem', fontWeight: 800 }}>RE-RUN LAYOUT</Button>
          <Button size="small" startIcon={<Download size={14} />} onClick={onExport} sx={{ bgcolor: `${tokens.accent.success}1A`, color: tokens.accent.success, fontSize: '0.7rem', fontWeight: 800 }}>EXPORT</Button>
       </Stack>
    </Box>
  );
};
