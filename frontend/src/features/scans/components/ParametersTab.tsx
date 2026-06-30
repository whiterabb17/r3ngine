import React, { useState } from 'react';
import {
  Box,
  Typography,
  InputBase,
  Button,
  IconButton,
  CircularProgress,
  Pagination,
  Stack,
  Tooltip,
  Chip
} from '@mui/material';
import {
  Search,
  Copy,
  Download,
  Filter,
  LayoutGrid
} from 'lucide-react';

import { useParameters } from '../api';
import { TacticalPanel } from '../../../components/TacticalPanel';
import { copyToClipboard } from '../../endpoints/utils/copy';
import { useThemeTokens } from '../../../theme/useThemeTokens';

interface ParametersTabProps {
  scanId?: number;
  targetId?: number;
}

export const ParametersTab: React.FC<ParametersTabProps> = ({ scanId, targetId }) => {
  const { tokens, isLight } = useThemeTokens();
  const [page, setPage] = useState(1);
  const [searchQuery, setSearchQuery] = useState('');
  const [activeSearch, setActiveSearch] = useState('');
  const [filterOpen, setFilterOpen] = useState(false);
  const [filterLocation, setFilterLocation] = useState<string>('');
  const [filterAuthRelated, setFilterAuthRelated] = useState<'all' | 'true' | 'false'>('all');
  const [filterJs, setFilterJs] = useState(false);
  const [filterOpenApi, setFilterOpenApi] = useState(false);
  const [filterGraphql, setFilterGraphql] = useState(false);
  const [filterConfidenceMin, setFilterConfidenceMin] = useState<number>(0);
  const [filterDataType, setFilterDataType] = useState<string>('');

  const { data, isLoading } = useParameters({
    scan_id: scanId,
    target_id: targetId,
    page,
    search: activeSearch,
    param_location: filterLocation || undefined,
    is_auth_related: filterAuthRelated !== 'all' ? filterAuthRelated === 'true' : undefined,
    observed_in_js: filterJs || undefined,
    observed_in_openapi: filterOpenApi || undefined,
    observed_in_graphql: filterGraphql || undefined,
    confidence_min: filterConfidenceMin > 0 ? filterConfidenceMin : undefined,
    data_type: filterDataType || undefined,
  });

  const activeFilterCount = [
    filterLocation,
    filterAuthRelated !== 'all' ? filterAuthRelated : '',
    filterJs ? 'js' : '',
    filterOpenApi ? 'openapi' : '',
    filterGraphql ? 'graphql' : '',
    filterConfidenceMin > 0 ? 'conf' : '',
    filterDataType,
  ].filter(Boolean).length;

  const clearFilters = () => {
    setFilterLocation('');
    setFilterAuthRelated('all');
    setFilterJs(false);
    setFilterOpenApi(false);
    setFilterGraphql(false);
    setFilterConfidenceMin(0);
    setFilterDataType('');
    setPage(1);
  };

  const handleSearch = () => {
    setPage(1);
    setActiveSearch(searchQuery);
  };

  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 80) return isLight ? tokens.accent.success : '#00ff62';
    if (confidence >= 50) return tokens.accent.primary;
    if (confidence >= 20) return isLight ? tokens.accent.warning : '#ffae00';
    return 'text.disabled';
  };

  return (
    <Box>
      {/* High-Fidelity Search Bar */}
      <Box sx={{ display: 'flex', gap: 2, mb: 3 }}>
        <Box sx={{
          display: 'flex',
          bgcolor: isLight ? 'rgba(0,0,0,0.02)' : 'rgba(255,255,255,0.03)',
          borderRadius: '4px',
          overflow: 'hidden',
          flex: 1,
          border: `1px solid ${isLight ? 'rgba(0,0,0,0.1)' : `${tokens.accent.primary}33`}`,
          boxShadow: `0 0 20px ${tokens.accent.primary}0D`
        }}>
          <InputBase
            placeholder={"Search Parameters..."}
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
            sx={{
              flex: 1,
              px: 3,
              py: 1.5,
              fontSize: '0.9rem',
              color: 'text.primary',
              '&::placeholder': { color: 'text.disabled', opacity: 1 }
            }}
          />
          <Button
            onClick={handleSearch}
            startIcon={<Search size={18} />}
            sx={{
              bgcolor: `${tokens.accent.primary}15`,
              color: tokens.accent.primary,
              px: 4,
              borderRadius: 0,
              fontWeight: 800,
              letterSpacing: 2,
              fontFamily: 'Orbitron',
              borderLeft: `1px solid ${isLight ? 'rgba(0,0,0,0.1)' : `${tokens.accent.primary}33`}`,
              '&:hover': { bgcolor: `${tokens.accent.primary}33` }
            }}
          >
            SEARCH
          </Button>
        </Box>
      </Box>

      {/* Collapsible Filter Panel */}
      {filterOpen && (
        <Box sx={{
          mb: 2, p: 2,
          bgcolor: isLight ? 'rgba(0,0,0,0.02)' : 'rgba(0,243,255,0.03)',
          border: `1px solid ${isLight ? 'rgba(0,0,0,0.08)' : 'rgba(0,243,255,0.15)'}`,
          borderRadius: 1,
          display: 'flex', flexWrap: 'wrap', gap: 2, alignItems: 'flex-end'
        }}>
          {/* Location */}
          <Box sx={{ minWidth: 160 }}>
            <Typography sx={{ fontSize: '9px', fontWeight: 900, color: 'text.secondary', letterSpacing: 1, mb: 0.5, fontFamily: 'Orbitron' }}>LOCATION</Typography>
            <select
              value={filterLocation}
              onChange={e => { setFilterLocation(e.target.value); setPage(1); }}
              style={{
                background: isLight ? '#ffffff' : 'rgba(0,0,0,0.5)',
                border: `1px solid ${isLight ? 'rgba(0,0,0,0.15)' : 'rgba(0,243,255,0.2)'}`,
                color: isLight ? '#000000' : '#ffffff',
                borderRadius: 4,
                padding: '4px 8px',
                fontSize: '11px',
                width: '100%',
                outline: 'none'
              }}
            >
              <option value="" style={{ background: isLight ? '#fff' : '#000', color: isLight ? '#000' : '#fff' }}>All</option>
              <option value="query_string" style={{ background: isLight ? '#fff' : '#000', color: isLight ? '#000' : '#fff' }}>Query String</option>
              <option value="json_body" style={{ background: isLight ? '#fff' : '#000', color: isLight ? '#000' : '#fff' }}>JSON Body</option>
              <option value="header" style={{ background: isLight ? '#fff' : '#000', color: isLight ? '#000' : '#fff' }}>Header</option>
              <option value="form_data" style={{ background: isLight ? '#fff' : '#000', color: isLight ? '#000' : '#fff' }}>Form Data</option>
              <option value="path" style={{ background: isLight ? '#fff' : '#000', color: isLight ? '#000' : '#fff' }}>Path</option>
              <option value="graphql_var" style={{ background: isLight ? '#fff' : '#000', color: isLight ? '#000' : '#fff' }}>GraphQL Var</option>
            </select>
          </Box>

          {/* Source type toggles */}
          <Box>
            <Typography sx={{ fontSize: '9px', fontWeight: 900, color: 'text.secondary', letterSpacing: 1, mb: 0.5, fontFamily: 'Orbitron' }}>SOURCE</Typography>
            <Box sx={{ display: 'flex', gap: 0.5 }}>
              {([['JS', filterJs, setFilterJs], ['OPENAPI', filterOpenApi, setFilterOpenApi], ['GRAPHQL', filterGraphql, setFilterGraphql]] as const).map(([label, active, setter]) => (
                <Chip
                  key={label}
                  label={label}
                  size="small"
                  onClick={() => { (setter as React.Dispatch<React.SetStateAction<boolean>>)((v: boolean) => !v); setPage(1); }}
                  sx={{
                    height: 22, fontSize: '9px', fontWeight: 900, cursor: 'pointer',
                    bgcolor: active ? (isLight ? 'rgba(112,0,255,0.1)' : 'rgba(112,0,255,0.2)') : (isLight ? 'rgba(0,0,0,0.04)' : 'rgba(255,255,255,0.05)'),
                    color: active ? (isLight ? '#7c3aed' : '#a855f7') : 'text.secondary',
                    border: `1px solid ${active ? (isLight ? 'rgba(112,0,255,0.2)' : 'rgba(112,0,255,0.4)') : (isLight ? 'rgba(0,0,0,0.08)' : 'rgba(255,255,255,0.1)')}`,
                  }}
                />
              ))}
            </Box>
          </Box>

          {/* Auth-related */}
          <Box>
            <Typography sx={{ fontSize: '9px', fontWeight: 900, color: 'text.secondary', letterSpacing: 1, mb: 0.5, fontFamily: 'Orbitron' }}>AUTH</Typography>
            <Box sx={{ display: 'flex', gap: 0.5 }}>
              {(['all', 'true', 'false'] as const).map(v => (
                <Chip
                  key={v}
                  label={v === 'all' ? 'ALL' : v === 'true' ? 'AUTH ONLY' : 'NON-AUTH'}
                  size="small"
                  onClick={() => { setFilterAuthRelated(v); setPage(1); }}
                  sx={{
                    height: 22, fontSize: '9px', fontWeight: 900, cursor: 'pointer',
                    bgcolor: filterAuthRelated === v ? (isLight ? 'rgba(255,0,60,0.08)' : 'rgba(255,0,60,0.15)') : (isLight ? 'rgba(0,0,0,0.04)' : 'rgba(255,255,255,0.05)'),
                    color: filterAuthRelated === v ? '#ff003c' : 'text.secondary',
                    border: `1px solid ${filterAuthRelated === v ? 'rgba(255,0,60,0.3)' : (isLight ? 'rgba(0,0,0,0.08)' : 'rgba(255,255,255,0.1)')}`,
                  }}
                />
              ))}
            </Box>
          </Box>

          {/* Min Confidence */}
          <Box sx={{ minWidth: 120 }}>
            <Typography sx={{ fontSize: '9px', fontWeight: 900, color: 'text.secondary', letterSpacing: 1, mb: 0.5, fontFamily: 'Orbitron' }}>
              MIN CONFIDENCE: <Box component="span" sx={{ color: tokens.accent.primary }}>{filterConfidenceMin}%</Box>
            </Typography>
            <input
              type="range" min={0} max={100} step={5}
              value={filterConfidenceMin}
              onChange={e => { setFilterConfidenceMin(Number(e.target.value)); setPage(1); }}
              style={{ width: '100%', accentColor: tokens.accent.primary }}
            />
          </Box>

          {/* Data Type */}
          <Box sx={{ minWidth: 120 }}>
            <Typography sx={{ fontSize: '9px', fontWeight: 900, color: 'text.secondary', letterSpacing: 1, mb: 0.5, fontFamily: 'Orbitron' }}>DATA TYPE</Typography>
            <select
              value={filterDataType}
              onChange={e => { setFilterDataType(e.target.value); setPage(1); }}
              style={{
                background: isLight ? '#ffffff' : 'rgba(0,0,0,0.5)',
                border: `1px solid ${isLight ? 'rgba(0,0,0,0.15)' : 'rgba(0,243,255,0.2)'}`,
                color: isLight ? '#000000' : '#ffffff',
                borderRadius: 4,
                padding: '4px 8px',
                fontSize: '11px',
                width: '100%',
                outline: 'none'
              }}
            >
              <option value="" style={{ background: isLight ? '#fff' : '#000', color: isLight ? '#000' : '#fff' }}>All</option>
              <option value="string" style={{ background: isLight ? '#fff' : '#000', color: isLight ? '#000' : '#fff' }}>string</option>
              <option value="number" style={{ background: isLight ? '#fff' : '#000', color: isLight ? '#000' : '#fff' }}>number</option>
              <option value="boolean" style={{ background: isLight ? '#fff' : '#000', color: isLight ? '#000' : '#fff' }}>boolean</option>
              <option value="object" style={{ background: isLight ? '#fff' : '#000', color: isLight ? '#000' : '#fff' }}>object</option>
              <option value="array" style={{ background: isLight ? '#fff' : '#000', color: isLight ? '#000' : '#fff' }}>array</option>
            </select>
          </Box>

          {/* Clear */}
          {activeFilterCount > 0 && (
            <Button
              onClick={clearFilters}
              size="small"
              sx={{ alignSelf: 'flex-end', color: isLight ? tokens.accent.warning : '#ffae00', border: `1px solid ${isLight ? 'rgba(217,119,6,0.3)' : 'rgba(255,174,0,0.3)'}`, borderRadius: 1, fontSize: '9px', fontWeight: 900, fontFamily: 'Orbitron', px: 2, height: 28 }}
            >
              CLEAR FILTERS
            </Button>
          )}
        </Box>
      )}

      {/* Main Tactical Panel */}
      <TacticalPanel title={"DISCOVERED PARAMETERS"} icon={<LayoutGrid size={14} />}>
        {/* Table Controls */}
        <Box sx={{ p: 2, display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: 1, borderColor: 'divider' }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <Typography sx={{ fontSize: '11px', fontWeight: 700, color: 'text.secondary', letterSpacing: 1 }}>
              RESULTS : <Box component="span" sx={{ color: tokens.accent.primary }}>{data?.count || 0}</Box>
            </Typography>
            <Box sx={{ px: 2, py: 0.5, bgcolor: `${tokens.accent.primary}0D`, borderRadius: 0.5, border: `1px solid ${tokens.accent.primary}15` }}>
              <Typography sx={{ fontSize: '10px', fontWeight: 800, color: tokens.accent.primary, fontFamily: 'Orbitron' }}>
                PAGE {page} OF {Math.ceil((data?.count || 0) / 100) || 1}
              </Typography>
            </Box>
          </Box>
          <Box sx={{ display: 'flex', gap: 1 }}>
            <Tooltip title="Toggle Filters">
              <IconButton
                size="small"
                onClick={() => setFilterOpen(o => !o)}
                sx={{
                  color: filterOpen || activeFilterCount > 0 ? tokens.accent.primary : 'text.secondary',
                  border: `1px solid ${filterOpen || activeFilterCount > 0 ? `${tokens.accent.primary}4D` : 'divider'}`,
                  borderRadius: 1,
                  position: 'relative'
                }}
              >
                <Filter size={16} />
                {activeFilterCount > 0 && (
                  <Box component="span" sx={{
                    position: 'absolute', top: -4, right: -4,
                    width: 14, height: 14, borderRadius: '50%',
                    bgcolor: 'error.main', fontSize: '8px', fontWeight: 900,
                    display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#fff'
                  }}>
                    {activeFilterCount}
                  </Box>
                )}
              </IconButton>
            </Tooltip>
            <Tooltip title="Export Data">
              <IconButton size="small" sx={{ color: tokens.accent.primary, bgcolor: `${tokens.accent.primary}15`, border: `1px solid ${tokens.accent.primary}33`, borderRadius: 1 }}><Download size={16} /></IconButton>
            </Tooltip>
          </Box>
        </Box>

        {/* Responsive Parameters Table */}
        <Box sx={{
          overflowX: 'auto',
          width: '100%',
          '&::-webkit-scrollbar': { height: '6px' },
          '&::-webkit-scrollbar-thumb': { bgcolor: `${tokens.accent.primary}33`, borderRadius: '3px' }
        }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', tableLayout: 'auto' }}>
            <thead>
              <tr style={{
                textAlign: 'left',
                borderBottom: `1px solid ${isLight ? 'rgba(0,0,0,0.08)' : 'rgba(255,255,255,0.1)'}`,
                backgroundColor: isLight ? 'rgba(0,0,0,0.02)' : 'rgba(255,255,255,0.02)'
              }}>
                <th style={{ padding: '12px 16px', color: tokens.accent.primary, fontSize: '10px', fontWeight: 900, letterSpacing: 1.5, fontFamily: 'Orbitron' }}>ENDPOINT URL</th>
                <th style={{ padding: '12px 16px', color: tokens.accent.primary, fontSize: '10px', fontWeight: 900, letterSpacing: 1.5, fontFamily: 'Orbitron' }}>PARAMETER / VALUE</th>
                <th style={{ padding: '12px 16px', color: tokens.accent.primary, fontSize: '10px', fontWeight: 900, letterSpacing: 1.5, fontFamily: 'Orbitron' }}>INTELLIGENCE</th>
                <th style={{ padding: '12px 16px', color: tokens.accent.primary, fontSize: '10px', fontWeight: 900, letterSpacing: 1.5, fontFamily: 'Orbitron' }}>SOURCES / CONFIDENCE</th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr>
                  <td colSpan={4} style={{ padding: '40px', textAlign: 'center' }}>
                    <CircularProgress size={24} sx={{ color: tokens.accent.primary }} />
                  </td>
                </tr>
              ) : data?.results.map((param) => (
                <tr key={param.id} style={{ borderBottom: 1, borderColor: 'divider', transition: 'background 0.2s' }}>
                  <td style={{ padding: '16px', verticalAlign: 'top', maxWidth: '300px' }}>
                    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                      <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 1 }}>
                        <Typography sx={{
                          fontSize: '12px',
                          fontWeight: 500,
                          color: 'text.primary',
                          textDecoration: 'none',
                          wordBreak: 'break-all',
                          '&:hover': { color: tokens.accent.primary }
                        }} component="a" href={/^https?:\/\//i.test(param.endpoint?.http_url ?? '') ? param.endpoint!.http_url : '#'} target="_blank">
                          {param.endpoint?.http_url}
                        </Typography>
                        <IconButton
                          size="small"
                          onClick={() => { const url = param.endpoint?.http_url; if (url) copyToClipboard(url); }}
                          sx={{ color: 'text.disabled', p: 0.5, '&:hover': { color: tokens.accent.primary } }}
                        >
                          <Copy size={12} />
                        </IconButton>
                      </Box>

                    </Box>
                  </td>
                  <td style={{ padding: '16px', verticalAlign: 'top' }}>
                    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Typography sx={{ fontSize: '13px', fontWeight: 700, color: tokens.accent.primary, fontFamily: 'monospace' }}>
                          {param.name}
                        </Typography>
                        {param.data_type && (
                          <Box sx={{ display: 'inline-flex', ml: 1 }}>
                            <Typography sx={{ fontSize: '9px', color: 'text.secondary', bgcolor: 'action.hover', px: 0.75, py: 0.25, borderRadius: 0.5, border: '1px solid', borderColor: 'divider', fontFamily: 'monospace' }}>
                              {param.data_type}
                            </Typography>
                          </Box>
                        )}
                      </Box>
                      {param.value && (
                        <Box sx={{ px: 1, py: 0.5, bgcolor: 'action.hover', borderRadius: 1, border: '1px solid', borderColor: 'divider' }}>
                          <Typography sx={{ fontSize: '11px', color: 'text.secondary', fontFamily: 'monospace', wordBreak: 'break-all' }}>
                            = {param.value}
                          </Typography>
                        </Box>
                      )}
                    </Box>
                  </td>
                  <td style={{ padding: '16px', verticalAlign: 'top' }}>
                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                      {param.is_auth_related && (
                        <Chip label="AUTH KEY" size="small" sx={{ height: 18, fontSize: '9px', fontWeight: 900, bgcolor: isLight ? 'rgba(255,0,60,0.08)' : 'rgba(255,0,60,0.1)', color: '#ff003c', border: '1px solid rgba(255,0,60,0.2)' }} />
                      )}
                      {param.param_location && (
                        <Chip label={param.param_location.replace('_', ' ').toUpperCase()} size="small" sx={{ height: 18, fontSize: '9px', fontWeight: 900, bgcolor: isLight ? 'rgba(0,165,233,0.08)' : 'rgba(0,243,255,0.05)', color: isLight ? '#0369a1' : '#00f3ff', border: `1px solid ${isLight ? 'rgba(3,105,161,0.2)' : 'rgba(0,243,255,0.2)'}` }} />
                      )}
                      {param.observed_in_js && (
                        <Chip label="JS" size="small" sx={{ height: 18, fontSize: '9px', fontWeight: 900, bgcolor: isLight ? 'rgba(112,0,255,0.08)' : 'rgba(112,0,255,0.1)', color: isLight ? '#7c3aed' : '#a855f7', border: `1px solid ${isLight ? 'rgba(112,0,255,0.2)' : 'rgba(112,0,255,0.2)'}` }} />
                      )}
                      {param.observed_in_openapi && (
                        <Chip label="OPENAPI" size="small" sx={{ height: 18, fontSize: '9px', fontWeight: 900, bgcolor: isLight ? 'rgba(59,130,246,0.08)' : 'rgba(59,130,246,0.1)', color: isLight ? '#2563eb' : '#3b82f6', border: `1px solid ${isLight ? 'rgba(37,99,235,0.2)' : 'rgba(59,130,246,0.2)'}` }} />
                      )}
                      {param.observed_in_graphql && (
                        <Chip label="GRAPHQL" size="small" sx={{ height: 18, fontSize: '9px', fontWeight: 900, bgcolor: isLight ? 'rgba(20,184,166,0.08)' : 'rgba(20,184,166,0.1)', color: isLight ? '#0d9488' : '#14b8a6', border: `1px solid ${isLight ? 'rgba(13,148,136,0.2)' : 'rgba(20,184,166,0.2)'}` }} />
                      )}
                      {(!param.is_auth_related && !param.param_location && !param.observed_in_js && !param.observed_in_openapi && !param.observed_in_graphql) && (
                        <Typography sx={{ fontSize: '10px', color: 'text.disabled', fontStyle: 'italic' }}>Standard</Typography>
                      )}
                    </Box>
                  </td>
                  <td style={{ padding: '16px', verticalAlign: 'top' }}>
                    <Stack spacing={1}>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Typography sx={{ fontSize: '10px', color: 'text.secondary', fontFamily: 'Orbitron' }}>CONFIDENCE:</Typography>
                        <Typography sx={{ fontSize: '11px', fontWeight: 900, color: getConfidenceColor(param.confidence) }}>
                          {param.confidence}%
                        </Typography>
                      </Box>
                      <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                        {(param.sources || []).map((source) => (
                          <Chip
                            key={source}
                            label={source.trim().toUpperCase()}
                            size="small"
                            sx={{
                              height: 16,
                              fontSize: '8px',
                              fontWeight: 900,
                              bgcolor: isLight ? 'rgba(112, 0, 255, 0.08)' : 'rgba(112, 0, 255, 0.1)',
                              color: isLight ? '#7c3aed' : '#7000ff',
                              border: `1px solid ${isLight ? 'rgba(112, 0, 255, 0.2)' : 'rgba(112, 0, 255, 0.3)'}`,
                              borderRadius: 0.5
                            }}
                          />
                        ))}
                      </Box>
                    </Stack>
                  </td>
                </tr>
              ))}
              {(!isLoading && data?.results.length === 0) && (
                <tr>
                  <td colSpan={4} style={{ padding: '60px', textAlign: 'center' }}>
                    <Typography sx={{ color: 'text.disabled', fontFamily: 'Orbitron', fontSize: '0.8rem' }}>ZERO PARAMETERS DETECTED</Typography>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </Box>

        {/* Tactical Pagination */}
        <Box sx={{ p: 2, display: 'flex', justifyContent: 'center', borderTop: '1px solid', borderColor: 'divider' }}>
          <Pagination
            count={Math.ceil((data?.count || 0) / 100)}
            page={page}
            onChange={(_, v) => setPage(v)}
            size="small"
            sx={{
              '& .MuiPaginationItem-root': {
                color: 'text.secondary',
                borderColor: 'divider',
                fontFamily: 'Orbitron',
                fontSize: '10px',
                '&.Mui-selected': {
                  bgcolor: `${tokens.accent.primary}15`,
                  color: tokens.accent.primary,
                  borderColor: tokens.accent.primary
                },
                '&:hover': {
                  bgcolor: 'action.hover'
                }
              }
            }}
          />
        </Box>
      </TacticalPanel>
    </Box>
  );
};
