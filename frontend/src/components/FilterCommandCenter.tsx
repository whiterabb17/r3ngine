import React, { useState } from 'react';
import { Box, Chip, IconButton, Popover, Typography, TextField, List, ListItemText, ListItemIcon, Button, useTheme, MenuItem, alpha } from '@mui/material';
import FilterListIcon from '@mui/icons-material/FilterList';
import { useThemeTokens } from '../theme/useThemeTokens';
import { getSurfaceSx, getMenuPaperSx } from '../theme/semanticColors';

export interface FilterFacetOption {
  label: string;
  value: string;
  color?: string; // Hex color for the token, e.g. '#ff0000'
}

export interface FilterFacet {
  id: string; // The query parameter name e.g. 'severity'
  label: string; // Human readable name e.g. 'Severity'
  type: 'select' | 'text';
  options?: FilterFacetOption[]; // For 'select' type
}

export interface FilterCommandCenterProps {
  facets: FilterFacet[];
  filters: Record<string, string>;
  onFilterChange: (filters: Record<string, string>) => void;
  searchQuery?: string;
  onSearchChange?: (search: string) => void;
  onSearchSubmit?: () => void;
  placeholder?: string;
}

export const FilterCommandCenter: React.FC<FilterCommandCenterProps> = ({
  facets,
  filters,
  onFilterChange,
  searchQuery = '',
  onSearchChange,
  onSearchSubmit,
  placeholder = 'Filter or command...',
}) => {
  const theme = useTheme();
  const { tokens } = useThemeTokens();
  const isLight = tokens.mode === 'light';
  const [anchorEl, setAnchorEl] = useState<HTMLButtonElement | null>(null);
  const [activeFacetId, setActiveFacetId] = useState<string | null>(null);
  
  const handleOpenFilters = (event: React.MouseEvent<HTMLButtonElement>) => {
    setAnchorEl(event.currentTarget);
    setActiveFacetId(null);
  };

  const handleCloseFilters = () => {
    setAnchorEl(null);
    setActiveFacetId(null);
  };

  const handleRemoveFilter = (facetId: string) => {
    const newFilters = { ...filters };
    delete newFilters[facetId];
    onFilterChange(newFilters);
  };

  const handleSelectFacetValue = (facetId: string, value: string) => {
    const currentValues = filters[facetId]
      ? filters[facetId].split(',').map((item) => item.trim()).filter(Boolean)
      : [];
    const nextValues = currentValues.includes(value)
      ? currentValues.filter((item) => item !== value)
      : [...currentValues, value];
    const nextFilters = { ...filters };
    if (nextValues.length > 0) {
      nextFilters[facetId] = nextValues.join(',');
    } else {
      delete nextFilters[facetId];
    }
    onFilterChange(nextFilters);
    handleCloseFilters();
  };

  const open = Boolean(anchorEl);
  const popoverId = open ? 'filter-popover' : undefined;

  const getFacetColor = (facetId: string, value: string) => {
    const facet = facets.find((f) => f.id === facetId);
    if (facet?.options) {
      const option = facet.options.find((o) => o.value === value);
      return option?.color || tokens.accent.primary;
    }
    return tokens.accent.primary;
  };

  const getFacetLabel = (facetId: string, value: string) => {
    const facet = facets.find((f) => f.id === facetId);
    const values = value.split(',').map((item) => item.trim()).filter(Boolean);
    if (facet?.options) {
      const labels = values
        .map((selectedValue) => facet.options?.find((o) => o.value === selectedValue)?.label || selectedValue)
        .filter(Boolean);
      if (labels.length > 0) return labels.join(', ');
    }
    return value;
  };

  return (
    <Box
      sx={{
        display: 'flex',
        alignItems: 'center',
        ...getSurfaceSx(isLight, tokens, theme),
        borderRadius: '8px',
        padding: '4px 12px',
        transition: 'all 0.3s ease',
        '&:focus-within': {
          border: `1px solid ${tokens.accent.primary}`,
          boxShadow: isLight
            ? `0 0 0 3px ${alpha(tokens.accent.primary, 0.12)}`
            : `0 0 10px ${alpha(tokens.accent.primary, 0.4)}`,
        },
      }}
    >
      <IconButton size="small" onClick={handleOpenFilters} sx={{ color: tokens.accent.primary, mr: 1 }}>
        <FilterListIcon fontSize="small" />
      </IconButton>
      
      {Object.entries(filters).map(([facetId, value]) => {
        const facet = facets.find(f => f.id === facetId);
        if (!facet) return null;
        
        return (
          <Chip
            key={facetId}
            label={`${facet.label.toUpperCase()}: ${getFacetLabel(facetId, value).toUpperCase()}`}
            onDelete={() => handleRemoveFilter(facetId)}
            size="small"
            sx={{
              mr: 1,
              backgroundColor: isLight
                ? alpha(getFacetColor(facetId, value), 0.08)
                : alpha(getFacetColor(facetId, value), 0.15),
              border: `1px solid ${getFacetColor(facetId, value)}`,
              color: getFacetColor(facetId, value),
              fontWeight: 'bold',
              letterSpacing: '0.05em',
              '& .MuiChip-deleteIcon': {
                color: getFacetColor(facetId, value),
                '&:hover': {
                  color: 'text.primary',
                }
              }
            }}
          />
        );
      })}

      <TextField
        variant="standard"
        placeholder={Object.keys(filters).length === 0 ? placeholder : ''}
        value={searchQuery}
        onChange={(e) => onSearchChange && onSearchChange(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Enter' && onSearchSubmit) {
            onSearchSubmit();
          }
        }}
        sx={{
          flex: 1,
          '& .MuiInput-underline:before': { borderBottom: 'none' },
          '& .MuiInput-underline:hover:not(.Mui-disabled):before': { borderBottom: 'none' },
          '& .MuiInput-underline:after': { borderBottom: 'none' },
          input: {
            color: 'text.primary',
            fontFamily: 'monospace',
            '&::placeholder': {
              color: tokens.text.muted,
              opacity: 1,
            },
          },
        }}
      />

      <Popover
        id={popoverId}
        open={open}
        anchorEl={anchorEl}
        onClose={handleCloseFilters}
        anchorOrigin={{
          vertical: 'bottom',
          horizontal: 'left',
        }}
        transformOrigin={{
          vertical: 'top',
          horizontal: 'left',
        }}
        sx={{
          '& .MuiPopover-paper': {
            ...getMenuPaperSx(isLight, theme, tokens),
            mt: 1,
            borderRadius: '8px',
            minWidth: 250,
            maxHeight: 400,
            color: 'text.primary',
          }
        }}
      >
        {!activeFacetId ? (
          <List dense sx={{ p: 0 }}>
            {facets.map((facet) => (
              <MenuItem
                key={facet.id}
                onClick={() => setActiveFacetId(facet.id)}
                sx={{
                  borderBottom: `1px solid ${tokens.border.subtle}`,
                  '&:hover': {
                    backgroundColor: isLight
                      ? alpha(tokens.accent.primary, 0.08)
                      : alpha(tokens.accent.primary, 0.15),
                  }
                }}
              >
                <ListItemText 
                  primary={
                    <Typography sx={{ fontFamily: 'monospace', fontWeight: 'bold', color: tokens.accent.primary }}>
                      {facet.label}
                    </Typography>
                  }
                />
              </MenuItem>
            ))}
          </List>
        ) : (
          <Box>
            <Box sx={{ p: 1, borderBottom: `1px solid ${tokens.border.subtle}`, display: 'flex', alignItems: 'center' }}>
              <Button 
                size="small" 
                onClick={() => setActiveFacetId(null)}
                sx={{ color: tokens.text.secondary, minWidth: 'auto', p: 0, mr: 1 }}
              >
                ←
              </Button>
              <Typography variant="body2" sx={{ fontFamily: 'monospace', color: 'text.primary', flex: 1 }}>
                Select {facets.find(f => f.id === activeFacetId)?.label}
              </Typography>
            </Box>
            <List dense sx={{ p: 0 }}>
              {facets.find(f => f.id === activeFacetId)?.options?.map((option) => (
                <MenuItem
                  key={option.value}
                  onClick={() => handleSelectFacetValue(activeFacetId, option.value)}
                  sx={{
                    '&:hover': {
                      backgroundColor: isLight
                        ? alpha(tokens.accent.primary, 0.08)
                        : alpha(tokens.accent.primary, 0.15),
                    }
                  }}
                >
                  <ListItemIcon sx={{ minWidth: 30 }}>
                    {option.color && (
                      <Box sx={{ width: 12, height: 12, borderRadius: '50%', backgroundColor: option.color }} />
                    )}
                  </ListItemIcon>
                  <ListItemText 
                    primary={
                      <Typography sx={{ fontFamily: 'monospace' }}>
                        {option.label}
                      </Typography>
                    }
                  />
                </MenuItem>
              ))}
            </List>
          </Box>
        )}
      </Popover>
    </Box>
  );
};
