import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  TextField,
  InputAdornment,
  Tabs,
  Tab,
  Stack,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  IconButton,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Divider,
  Alert,
  Link
} from '@mui/material';
import {
  Search,
  Globe,
  Link as LinkIcon,
  ShieldAlert,
  ChevronRight,
  History,
  Clock,
  ExternalLink,
  Target,
  FileCode,
  AlertTriangle
} from 'lucide-react';
import { useSearch, useSearchHistory } from '../api';
import { escapeRegExp, getSafeUrl } from '../../../utils/securityUtils';
import { useParams, useNavigate, useSearch as useUrlSearch } from '@tanstack/react-router';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import type { ResolvedThemeTokens } from '../../../theme/tokens';

const SEVERITY_COLORS: Record<number, string> = {
  4: '#ff1744', // Critical
  3: '#ff5722', // High
  2: '#ffc107', // Medium
  1: '#4caf50', // Low
  0: '#2196f3', // Info
  [-1]: '#9e9e9e' // Unknown
};

const getTabStyle = (tokens: ResolvedThemeTokens) => ({
  fontFamily: 'Orbitron',
  fontWeight: 700,
  fontSize: '0.75rem',
  letterSpacing: 1,
  '&.Mui-selected': { color: tokens.accent.primary }
});

export const SearchPage: React.FC = () => {
  const { tokens } = useThemeTokens();
  const { projectSlug } = useParams({ strict: false });
  const urlSearch = useUrlSearch({ strict: false }) as { query?: string };
  const navigate = useNavigate({ from: '/$projectSlug/search' });
  const [query, setQuery] = useState(urlSearch.query || '');
  const [activeTab, setActiveTab] = useState(0);

  const { data: searchResults, isLoading, error } = useSearch(urlSearch.query || '');
  const { data: searchHistory } = useSearchHistory();

  const handleSearch = (e?: React.FormEvent) => {
    e?.preventDefault();
    if (query.trim()) {
      navigate({ search: { query } });
    }
  };

  const highlightText = (text: string, highlight: string) => {
    if (!highlight.trim()) return text;
    // Escape special characters to prevent ReDoS using centralized utility
    const escapedHighlight = escapeRegExp(highlight);
    const parts = text.split(new RegExp(`(${escapedHighlight})`, 'gi'));
    return (
      <span>
        {parts.map((part, i) => 
          part.toLowerCase() === highlight.toLowerCase() ? (
            <span key={i} style={{ color: tokens.accent.primary, textShadow: `0 0 10px ${tokens.accent.primary}80`, fontWeight: 700 }}>{part}</span>
          ) : (
            part
          )
        )}
      </span>
    );
  };

  return (
    <Box sx={{ p: 4, bgcolor: 'background.default', minHeight: '100vh' }}>
      {/* Search Header */}
      <Box sx={{ maxWidth: 900, mx: 'auto', mb: 6 }}>
        <Typography variant="h4" sx={{ 
          fontFamily: 'Orbitron', 
          fontWeight: 900, 
          color: 'text.primary',
          textAlign: 'center',
          mb: 4,
          textShadow: `0 0 20px ${tokens.accent.primary}4D`
        }}>
          UNIVERSAL SEARCH
        </Typography>

        <form onSubmit={handleSearch}>
          <TextField
            fullWidth
            placeholder="Type target, subdomain, or vulnerability..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            slotProps={{
              input: {
                startAdornment: (
                  <InputAdornment position="start">
                    <Search size={24} style={{ color: tokens.accent.primary, marginRight: 8 }} />
                  </InputAdornment>
                ),
                endAdornment: (
                  <InputAdornment position="end">
                    <IconButton onClick={() => handleSearch()} sx={{ color: tokens.accent.primary }}>
                      <ChevronRight size={24} />
                    </IconButton>
                  </InputAdornment>
                )
              }
            }}
            sx={{
              '& .MuiOutlinedInput-root': {
                bgcolor: 'action.hover',
                border: 1, borderColor: `${tokens.accent.primary}33`,
                borderRadius: '12px',
                fontSize: '1.2rem',
                color: 'text.primary',
                '&:hover': {
                  borderColor: `${tokens.accent.primary}80`,
                  boxShadow: `0 0 15px ${tokens.accent.primary}1A`
                },
                '&.Mui-focused': {
                  borderColor: tokens.accent.primary,
                  boxShadow: `0 0 20px ${tokens.accent.primary}33`
                }
              }
            }}
          />
        </form>

        {/* Search History Chips */}
        {searchHistory?.status && searchHistory.results.length > 0 && !urlSearch.query && (
          <Stack direction="row" spacing={1} sx={{ mt: 3, flexWrap: 'wrap', gap: 1 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, color: 'text.disabled', mr: 1 }}>
              <History size={16} />
              <Typography variant="caption">RECENT:</Typography>
            </Box>
            {searchHistory.results.slice(0, 5).map((item, idx) => (
              <Chip
                key={idx}
                label={item.query}
                onClick={() => {
                  setQuery(item.query);
                  navigate({ search: { query: item.query } });
                }}
                sx={{ 
                  bgcolor: 'action.hover', 
                  color: 'text.secondary',
                  '&:hover': { bgcolor: `${tokens.accent.primary}1A`, color: tokens.accent.primary }
                }}
              />
            ))}
          </Stack>
        )}
      </Box>

      {/* Results Section */}
      <Box sx={{ maxWidth: 1100, mx: 'auto' }}>
        {isLoading ? (
          <Box sx={{ textAlign: 'center', py: 10 }}>
            <CircularProgress sx={{ color: tokens.accent.primary }} />
            <Typography variant="body2" sx={{ mt: 2, color: 'text.disabled', letterSpacing: 2 }}>
              SCANNING_DATABASES...
            </Typography>
          </Box>
        ) : error ? (
          <Alert severity="error" sx={{ bgcolor: 'rgba(211, 47, 47, 0.1)', color: '#ff5252' }}>
            An error occurred during search. Please try again.
          </Alert>
        ) : searchResults?.results ? (
          <>
            <Tabs 
              value={activeTab} 
              onChange={(_, v) => setActiveTab(v)}
              sx={{ borderBottom: 1, borderColor: 'divider', mb: 4 }}
            >
              <Tab label={`SUBDOMAINS (${searchResults.results.subdomains.length})`} sx={getTabStyle(tokens)} />
              <Tab label={`ENDPOINTS (${searchResults.results.endpoints.length})`} sx={getTabStyle(tokens)} />
              <Tab label={`VULNERABILITIES (${searchResults.results.vulnerabilities.length})`} sx={getTabStyle(tokens)} />
              <Tab label={`OTHERS (${Object.keys(searchResults.results.others ?? {}).length})`} sx={getTabStyle(tokens)} />
            </Tabs>

            <Box sx={{ minHeight: 400 }}>
              {activeTab === 0 && (
                <Stack spacing={2}>
                  {searchResults.results.subdomains.length > 0 ? (
                    searchResults.results.subdomains.map((s, idx) => (
                      <Card key={idx} sx={{ bgcolor: 'action.hover', border: 1, borderColor: 'divider' }}>
                        <CardContent sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <Stack direction="row" spacing={3} sx={{ alignItems: "center" }}>
                            <Box sx={{ color: tokens.accent.primary }}><Globe size={20} /></Box>
                            <Box>
                              <Typography variant="subtitle1" sx={{ color: 'text.primary', fontWeight: 600 }}>
                                {highlightText(s.name, urlSearch.query || '')}
                                <Chip 
                                  label={s.http_status} 
                                  size="small" 
                                  sx={{ 
                                    ml: 2, height: 18, fontSize: '0.65rem', 
                                    bgcolor: s.http_status === 200 ? 'rgba(0, 255, 0, 0.1)' : 'rgba(255, 0, 0, 0.1)',
                                    color: s.http_status === 200 ? '#00ff00' : '#ff5252'
                                  }} 
                                />
                              </Typography>
                              {s.page_title && (
                                <Typography variant="body2" sx={{ color: 'text.disabled' }}>
                                  {highlightText(s.page_title, urlSearch.query || '')}
                                </Typography>
                              )}
                              <Typography variant="caption" sx={{ color: 'text.disabled' }}>
                                {s.http_url}
                              </Typography>
                            </Box>
                          </Stack>
                          <IconButton component={Link} href={getSafeUrl(s.http_url) ?? '#'} target="_blank" sx={{ color: 'text.disabled' }}>
                            <ExternalLink size={18} />
                          </IconButton>
                        </CardContent>
                      </Card>
                    ))
                  ) : (
                    <EmptyState message="NO_SUBDOMAINS_FOUND" />
                  )}
                </Stack>
              )}

              {activeTab === 1 && (
                <Stack spacing={2}>
                  {searchResults.results.endpoints.length > 0 ? (
                    searchResults.results.endpoints.map((e, idx) => (
                      <Card key={idx} sx={{ bgcolor: 'action.hover', border: 1, borderColor: 'divider' }}>
                        <CardContent sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <Stack direction="row" spacing={3} sx={{ alignItems: "center" }}>
                            <Box sx={{ color: tokens.accent.secondary }}><LinkIcon size={20} /></Box>
                            <Box>
                              <Typography variant="body2" sx={{ color: 'text.primary', wordBreak: 'break-all' }}>
                                {highlightText(e.http_url, urlSearch.query || '')}
                              </Typography>
                              <Typography variant="caption" sx={{ color: 'text.disabled', display: 'flex', alignItems: 'center', gap: 1 }}>
                                STATUS: {e.http_status}
                                {e.page_title && ` | TITLE: ${e.page_title}`}
                              </Typography>
                            </Box>
                          </Stack>
                          <IconButton component={Link} href={getSafeUrl(e.http_url) ?? '#'} target="_blank" sx={{ color: 'text.disabled' }}>
                            <ExternalLink size={18} />
                          </IconButton>
                        </CardContent>
                      </Card>
                    ))
                  ) : (
                    <EmptyState message="NO_ENDPOINTS_FOUND" />
                  )}
                </Stack>
              )}

              {activeTab === 2 && (
                <Stack spacing={2}>
                  {searchResults.results.vulnerabilities.length > 0 ? (
                    searchResults.results.vulnerabilities.map((v, idx) => (
                      <Card key={idx} sx={{ bgcolor: 'action.hover', border: 1, borderColor: 'divider' }}>
                        <CardContent>
                          <Stack direction="row" spacing={3} sx={{ alignItems: "flex-start" }}>
                            <Box sx={{ color: SEVERITY_COLORS[v.severity] || '#fff', mt: 0.5 }}><ShieldAlert size={20} /></Box>
                            <Box sx={{ flexGrow: 1 }}>
                              <Typography variant="subtitle1" sx={{ color: 'text.primary', fontWeight: 600 }}>
                                {highlightText(v.name, urlSearch.query || '')}
                                <Chip 
                                  label={getSeverityName(v.severity)} 
                                  size="small" 
                                  sx={{ 
                                    ml: 2, height: 18, fontSize: '0.6rem', fontWeight: 900,
                                    bgcolor: SEVERITY_COLORS[v.severity] + '22',
                                    color: SEVERITY_COLORS[v.severity],
                                    border: `1px solid ${SEVERITY_COLORS[v.severity]}44`
                                  }} 
                                />
                              </Typography>
                              {v.http_url && (
                                <Typography variant="caption" sx={{ color: tokens.accent.primary, opacity: 0.7, display: 'block', mb: 1 }}>
                                  {v.http_url}
                                </Typography>
                              )}
                              {v.description && (
                                <Typography variant="body2" sx={{ color: 'text.disabled', mt: 1 }}>
                                  {highlightText(v.description, urlSearch.query || '')}
                                </Typography>
                              )}
                            </Box>
                          </Stack>
                        </CardContent>
                      </Card>
                    ))
                  ) : (
                    <EmptyState message="NO_VULNERABILITIES_FOUND" />
                  )}
                </Stack>
              )}

              {activeTab === 3 && (
                <EmptyState message="ADDITIONAL_SEARCH_OBJECTS_NOT_IMPLEMENTED" icon={<AlertTriangle size={40} />} />
              )}
            </Box>
          </>
        ) : (
          <Box sx={{ textAlign: 'center', py: 10, opacity: 0.3 }}>
            <Target size={60} style={{ marginBottom: 16 }} />
            <Typography variant="h6" sx={{ fontFamily: 'Orbitron', letterSpacing: 2 }}>
              AWAITING_INPUT
            </Typography>
          </Box>
        )}
      </Box>
    </Box>
  );
};

const EmptyState = ({ message, icon }: { message: string; icon?: React.ReactNode }) => (
  <Box sx={{ textAlign: 'center', py: 8, bgcolor: 'action.hover', borderRadius: 2, border: 1, borderColor: 'divider', borderStyle: 'dashed' }}>
    <Box sx={{ color: 'text.disabled', mb: 2 }}>{icon || <FileCode size={40} />}</Box>
    <Typography variant="body2" sx={{ color: 'text.disabled', letterSpacing: 2, fontFamily: 'Orbitron' }}>
      {message}
    </Typography>
  </Box>
);

const getSeverityName = (severity: number) => {
  const names: Record<number, string> = {
    4: 'CRITICAL',
    3: 'HIGH',
    2: 'MEDIUM',
    1: 'LOW',
    0: 'INFO',
    [-1]: 'UNKNOWN'
  };
  return names[severity] || 'UNKNOWN';
};
