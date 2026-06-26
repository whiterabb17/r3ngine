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
  Menu,
  MenuItem,
  Chip,
  Snackbar,
  Alert
} from '@mui/material';
import {
  Search,
  Copy,
  Download,
  Filter,
  LayoutGrid,
  ChevronDown,
  ChevronRight,
  Trash2,
  ExternalLink,
  Key,
  Play
} from 'lucide-react';

import { useEndpoints, useDeleteEndpoints } from '../../endpoints/api';
import { usePlugins } from '../../plugins/api/pluginsApi';
import { useDirectoryFileDispatch } from '../api';
import { BruteConfigDialog } from './BruteConfigDialog';
import { TacticalPanel } from '../../../components/TacticalPanel';
import { copyToClipboard } from '../../endpoints/utils/copy';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import { ConfirmDialog } from '../../../components/ConfirmDialog';
import { ExtractAuthModal } from './ExtractAuthModal';

interface EndpointsTabProps {
  projectSlug: string;
  scanId?: number;
  matchedGfCounts?: Array<{ matched_gf_patterns: string; count: number }>;
  targetId?: number;
  initialAlive?: boolean;
}

export const EndpointsTab: React.FC<EndpointsTabProps> = ({ projectSlug, scanId, matchedGfCounts, targetId, initialAlive }) => {
  const { tokens, isLight, theme } = useThemeTokens();
  const [page, setPage] = useState(1);
  const [searchQuery, setSearchQuery] = useState('');
  const [activeSearch, setActiveSearch] = useState('');
  const [selectedGfPattern, setSelectedGfPattern] = useState<string | undefined>(undefined);
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [isAliveFilter, setIsAliveFilter] = useState(initialAlive || false);

  // Actions state
  const { data: plugins } = usePlugins();
  const credPluginEnabled = plugins?.some(
    (p: { slug: string; is_enabled: boolean }) =>
      p.slug === 'credential_intelligence' && p.is_enabled
  );
  const dispatchMutation = useDirectoryFileDispatch();

  const [expandedRows, setExpandedRows] = useState<number[]>([]);
  const [bruteModalOpen, setBruteModalOpen] = useState(false);
  const [bruteEndpoint, setBruteEndpoint] = useState<{ id: number; url: string } | null>(null);
  const [pendingActionId, setPendingActionId] = useState<{ id: number; action: string } | null>(null);

  const [extractAuthModalOpen, setExtractAuthModalOpen] = useState(false);
  const [extractAuthUrl, setExtractAuthUrl] = useState('');
  const [extractAuthWorkflowId, setExtractAuthWorkflowId] = useState<string | null>(null);
  const [extractAuthStatus, setExtractAuthStatus] = useState<'idle' | 'extracting' | 'completed' | 'error'>('idle');

  const [selectedEndpoints, setSelectedEndpoints] = useState<number[]>([]);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [confirmConfig, setConfirmConfig] = useState({
    title: '',
    message: '',
    type: 'danger' as 'danger' | 'warning' | 'info',
    onConfirm: () => {}
  });
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: string; severity: 'success' | 'error' | 'info' | 'warning' }>({
    open: false,
    message: '',
    severity: 'success'
  });

  const showNotification = (message: string, severity: 'success' | 'error' | 'info' | 'warning' = 'success') => {
    setSnackbar({ open: true, message, severity });
  };

  const handleExtractAuth = async (id: number, url: string) => {
    if (!scanId) return;
    setPendingActionId({ id, action: 'extract_auth' });
    setExtractAuthUrl(url);
    setExtractAuthModalOpen(true);
    setExtractAuthStatus('extracting');
    setExtractAuthWorkflowId(null);
    try {
      const response = await dispatchMutation.mutateAsync({
        url,
        action: 'extract_auth',
        scan_id: scanId
      });
      if (response && response.workflow_id) {
        setExtractAuthWorkflowId(response.workflow_id);
      }
      // Wait for a few seconds before completing to allow logs to be viewed? 
      // Actually, since Temporal workflow might take longer, we should ideally poll Temporal status.
      // For now, we will mark as completed after 5 seconds of extracting if it succeeds, but wait, the endpoint returns instantly.
      // We will let the user close it, and maybe we don't know when it's done unless we poll workflow status.
      // But we can check if logs contain "[COMPLETE]"!
    } catch (error: any) {
      showNotification(error.message || 'Failed to dispatch auth extraction', 'error');
      setExtractAuthStatus('error');
    } finally {
      setPendingActionId(null);
    }
  };

  const handleBruteOpen = (id: number, url: string) => {
    setBruteEndpoint({ id, url });
    setBruteModalOpen(true);
  };

  const handleBruteSubmit = async (params: {
    tool: string;
    wordlist_user: string;
    wordlist_pass: string;
    threads: number;
    additional_flags: string;
  }) => {
    if (!bruteEndpoint || !scanId) return;
    setPendingActionId({ id: bruteEndpoint.id, action: 'brute_test' });
    try {
      await dispatchMutation.mutateAsync({
        url: bruteEndpoint.url,
        action: 'brute_test',
        scan_id: scanId,
        ...params
      });
      showNotification('Brute force test dispatched successfully', 'success');
      setBruteModalOpen(false);
      setBruteEndpoint(null);
    } catch (error: any) {
      showNotification(error.message || 'Failed to dispatch brute test', 'error');
    } finally {
      setPendingActionId(null);
    }
  };

  const toggleRowExpand = (id: number) => {
    setExpandedRows(prev =>
      prev.includes(id) ? prev.filter(i => i !== id) : [...prev, id]
    );
  };

  const deleteMutation = useDeleteEndpoints(projectSlug);

  const { data, isLoading } = useEndpoints(
    projectSlug,
    page,
    activeSearch,
    scanId,
    selectedGfPattern,
    targetId,
    isAliveFilter ? '200' : undefined
  );

  // Reset selection on query/page changes
  React.useEffect(() => {
    setSelectedEndpoints([]);
  }, [page, activeSearch, selectedGfPattern, isAliveFilter]);

  const handleSearch = () => {
    setPage(1);
    setActiveSearch(searchQuery);
  };

  const handleMenuOpen = (event: React.MouseEvent<HTMLButtonElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleMenuClose = () => {
    setAnchorEl(null);
  };

  const handleSelectPattern = (pattern: string | undefined) => {
    setPage(1);
    setSelectedGfPattern(pattern);
    handleMenuClose();
  };

  const toggleSelectAll = () => {
    if (selectedEndpoints.length === data?.results.length) {
      setSelectedEndpoints([]);
    } else {
      setSelectedEndpoints(data?.results.map(e => e.id) || []);
    }
  };

  const toggleSelectEndpoint = (id: number) => {
    setSelectedEndpoints(prev =>
      prev.includes(id) ? prev.filter(i => i !== id) : [...prev, id]
    );
  };

  const handleBulkCopy = () => {
    if (selectedEndpoints.length === 0) return;
    const selectedUrls = data?.results
      .filter(e => selectedEndpoints.includes(e.id))
      .map(e => e.http_url)
      .join('\n');
    if (selectedUrls) {
      copyToClipboard(selectedUrls);
      showNotification(`${selectedEndpoints.length} URL(s) copied to clipboard`);
    }
  };

  const handleBulkDelete = () => {
    if (selectedEndpoints.length === 0) return;
    setConfirmConfig({
      title: 'BULK DELETE ENDPOINTS',
      message: `Are you sure you want to delete ${selectedEndpoints.length} endpoints? This operation is permanent.`,
      type: 'danger',
      onConfirm: async () => {
        try {
          await deleteMutation.mutateAsync(selectedEndpoints);
          showNotification(`${selectedEndpoints.length} endpoint(s) deleted successfully`);
          setSelectedEndpoints([]);
        } catch (error: any) {
          showNotification(error.message || 'Failed to delete endpoints', 'error');
        }
      }
    });
    setConfirmOpen(true);
  };

  const handleSingleDelete = (id: number) => {
    setConfirmConfig({
      title: 'DELETE ENDPOINT',
      message: 'Are you sure you want to delete this endpoint? This operation is permanent.',
      type: 'danger',
      onConfirm: async () => {
        try {
          await deleteMutation.mutateAsync([id]);
          showNotification('Endpoint deleted successfully');
          setSelectedEndpoints(prev => prev.filter(i => i !== id));
        } catch (error: any) {
          showNotification(error.message || 'Failed to delete endpoint', 'error');
        }
      }
    });
    setConfirmOpen(true);
  };

  const handleExportVisible = () => {
    if (!data?.results || data.results.length === 0) {
      showNotification('No endpoints to export', 'warning');
      return;
    }
    const urls = data.results.map(e => e.http_url).join('\n');
    const blob = new Blob([urls], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `endpoints_${projectSlug}_page_${page}.txt`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    showNotification('Endpoints exported successfully');
  };

  const getStatusColor = (status: number) => {
    if (status >= 200 && status < 300) return isLight ? tokens.accent.success : '#00ff62';
    if (status >= 300 && status < 400) return tokens.accent.primary;
    if (status >= 400 && status < 500) return isLight ? tokens.accent.warning : '#ffae00';
    if (status >= 500) return isLight ? tokens.accent.error : '#ff003c';
    return isLight ? tokens.text.secondary : 'rgba(255,255,255,0.4)';
  };

  return (
    <Box>
      {/* High-Fidelity Search Bar and Pattern Dropdown */}
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
            placeholder={selectedGfPattern ? `Search within ${selectedGfPattern.toUpperCase()} endpoints...` : "Filter Endpoints..."}
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
          <Button
            onClick={() => {
              setIsAliveFilter(prev => !prev);
              setPage(1);
            }}
            disabled={isLoading}
            sx={{
              bgcolor: isAliveFilter ? `${tokens.accent.primary}33` : 'transparent',
              color: isAliveFilter ? tokens.accent.primary : 'text.primary',
              opacity: isLoading ? 0.6 : 1,
              px: 3,
              borderRadius: 0,
              fontWeight: 800,
              fontSize: '11px',
              letterSpacing: 2,
              fontFamily: 'Orbitron',
              borderLeft: `1px solid ${isLight ? 'rgba(0,0,0,0.1)' : `${tokens.accent.primary}33`}`,
              '&:hover': { bgcolor: `${tokens.accent.primary}26` }
            }}
          >
            {isLoading ? 'LOADING...' : isAliveFilter ? 'ALIVE [ON]' : 'ALIVE'}
          </Button>
        </Box>

        {/* Pattern Dropdown */}
        {matchedGfCounts && matchedGfCounts.length > 0 && (
          <Box>
            <Button
              variant="outlined"
              onClick={handleMenuOpen}
              endIcon={<ChevronDown size={14} />}
              sx={{
                height: '100%',
                px: 2,
                borderColor: isLight ? 'divider' : `${tokens.accent.primary}33`,
                color: selectedGfPattern ? 'error.main' : 'text.primary',
                bgcolor: selectedGfPattern ? (isLight ? 'rgba(239, 68, 68, 0.05)' : 'rgba(255, 0, 60, 0.05)') : (isLight ? 'rgba(0,0,0,0.02)' : 'rgba(255,255,255,0.03)'),
                fontWeight: 800,
                fontSize: '0.75rem',
                letterSpacing: 1,
                '&:hover': { borderColor: tokens.accent.primary, bgcolor: `${tokens.accent.primary}0D` }
              }}
            >
              {selectedGfPattern ? `PATTERN: ${selectedGfPattern.toUpperCase()}` : 'QUERY SPECIFIC ENDPOINTS'}
            </Button>
            <Menu
              anchorEl={anchorEl}
              open={Boolean(anchorEl)}
              onClose={handleMenuClose}
              slotProps={{
                paper: {
                  sx: {
                    bgcolor: 'background.paper',
                    border: `1px solid ${isLight ? 'rgba(0,0,0,0.08)' : `${tokens.accent.primary}33`}`,
                    boxShadow: isLight ? '0 4px 20px rgba(0,0,0,0.05)' : '0 0 30px rgba(0,0,0,0.5)',
                    mt: 1,
                    '& .MuiMenuItem-root': {
                      fontSize: '0.75rem',
                      fontWeight: 700,
                      color: 'text.primary',
                      px: 3,
                      py: 1,
                      '&:hover': { bgcolor: `${tokens.accent.primary}15`, color: tokens.accent.primary }
                    }
                  }
                }
              }}
            >
              <MenuItem onClick={() => handleSelectPattern(undefined)}>ALL ENDPOINTS</MenuItem>
              {matchedGfCounts.map((pattern) => (
                <MenuItem key={pattern.matched_gf_patterns} onClick={() => handleSelectPattern(pattern.matched_gf_patterns)}>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', width: '100%', gap: 4 }}>
                    <span>{pattern.matched_gf_patterns.toUpperCase()}</span>
                    <Box component="span" sx={{ color: 'error.main', opacity: 0.8 }}>{pattern.count}</Box>
                  </Box>
                </MenuItem>
              ))}
            </Menu>
          </Box>
        )}
      </Box>

      {/* Main Tactical Panel */}
      <TacticalPanel title={selectedGfPattern ? `ENDPOINTS: ${selectedGfPattern.toUpperCase()}` : "ALL ENDPOINTS"} icon={<LayoutGrid size={14} />}>
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
          <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
            {selectedEndpoints.length > 0 && (
              <Stack direction="row" spacing={1} sx={{ mr: 1 }}>
                <Button
                  size="small"
                  variant="contained"
                  onClick={handleBulkCopy}
                  startIcon={<Copy size={12} />}
                  sx={{
                    bgcolor: `${tokens.accent.primary}15`,
                    color: tokens.accent.primary,
                    fontSize: '10px',
                    fontWeight: 800,
                    border: `1px solid ${tokens.accent.primary}33`,
                    '&:hover': { bgcolor: `${tokens.accent.primary}33` }
                  }}
                >
                  COPY SELECTED ({selectedEndpoints.length})
                </Button>
                <Button
                  size="small"
                  variant="contained"
                  onClick={handleBulkDelete}
                  startIcon={<Trash2 size={12} />}
                  disabled={deleteMutation.isPending}
                  sx={{
                    bgcolor: isLight ? 'rgba(239, 68, 68, 0.08)' : 'rgba(255, 0, 60, 0.1)',
                    color: tokens.accent.error,
                    fontSize: '10px',
                    fontWeight: 800,
                    border: '1px solid',
                    borderColor: 'error.main',
                    '&:hover': { bgcolor: isLight ? 'rgba(239, 68, 68, 0.16)' : 'rgba(255, 0, 60, 0.2)' }
                  }}
                >
                  {deleteMutation.isPending ? 'DELETING...' : `DELETE SELECTED (${selectedEndpoints.length})`}
                </Button>
              </Stack>
            )}
            <Tooltip title="Refresh">
              <IconButton size="small" sx={{ color: 'text.secondary', border: '1px solid', borderColor: 'divider', borderRadius: 1 }}><Filter size={16} /></IconButton>
            </Tooltip>
            <Tooltip title="Export URLs">
              <IconButton
                size="small"
                onClick={handleExportVisible}
                sx={{ color: tokens.accent.primary, bgcolor: `${tokens.accent.primary}15`, border: `1px solid ${tokens.accent.primary}33`, borderRadius: 1 }}
              >
                <Download size={16} />
              </IconButton>
            </Tooltip>
          </Box>
        </Box>

        {/* Responsive Endpoints Table */}
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
                <th style={{ width: '40px', padding: '12px 16px', textAlign: 'center' }}>
                  <input
                    type="checkbox"
                    checked={selectedEndpoints.length === data?.results.length && data?.results.length > 0}
                    onChange={toggleSelectAll}
                    style={{ width: '14px', height: '14px', accentColor: tokens.accent.primary, cursor: 'pointer', opacity: 0.6 }}
                  />
                </th>
                <th style={{ padding: '12px 16px', color: tokens.accent.primary, fontSize: '10px', fontWeight: 900, letterSpacing: 1.5, fontFamily: 'Orbitron' }}>HTTP URL</th>
                <th style={{ padding: '12px 16px', color: tokens.accent.primary, fontSize: '10px', fontWeight: 900, letterSpacing: 1.5, fontFamily: 'Orbitron' }}>STATUS</th>
                <Box component="th" sx={{ display: { xs: 'none', md: 'table-cell' }, padding: '12px 16px', color: tokens.accent.primary, fontSize: '10px', fontWeight: 900, letterSpacing: 1.5, fontFamily: 'Orbitron' }}>PAGE TITLE</Box>
                <Box component="th" sx={{ display: { xs: 'none', sm: 'table-cell' }, padding: '12px 16px', color: tokens.accent.primary, fontSize: '10px', fontWeight: 900, letterSpacing: 1.5, fontFamily: 'Orbitron' }}>TAGS</Box>
                <Box component="th" sx={{ display: { xs: 'none', lg: 'table-cell' }, padding: '12px 16px', color: tokens.accent.primary, fontSize: '10px', fontWeight: 900, letterSpacing: 1.5, fontFamily: 'Orbitron' }}>INFO</Box>
                <th style={{ padding: '12px 16px', color: tokens.accent.primary, fontSize: '10px', fontWeight: 900, letterSpacing: 1.5, fontFamily: 'Orbitron', textAlign: 'right' }}>ACTIONS</th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr>
                  <td colSpan={7} style={{ padding: '40px', textAlign: 'center' }}>
                    <CircularProgress size={24} sx={{ color: tokens.accent.primary }} />
                  </td>
                </tr>
              ) : data?.results.map((endpoint) => {
                const hasAuthForm = endpoint.auth_candidates && endpoint.auth_candidates.length > 0;
                const isExpanded = expandedRows.includes(endpoint.id);
                const isExtractPending = pendingActionId?.id === endpoint.id && pendingActionId?.action === 'extract_auth';
                const isBrutePending = pendingActionId?.id === endpoint.id && pendingActionId?.action === 'brute_test';

                return (
                  <React.Fragment key={endpoint.id}>
                    <tr style={{
                      borderBottom: '1px solid',
                      borderColor: theme.palette.divider,
                      backgroundColor: selectedEndpoints.includes(endpoint.id)
                        ? (isLight ? 'rgba(14, 165, 233, 0.04)' : 'rgba(0, 243, 255, 0.02)')
                        : 'transparent',
                      transition: 'background 0.2s'
                    }}>
                      <td style={{ padding: '16px', verticalAlign: 'top', textAlign: 'center' }}>
                        <input
                          type="checkbox"
                          checked={selectedEndpoints.includes(endpoint.id)}
                          onChange={() => toggleSelectEndpoint(endpoint.id)}
                          style={{
                            width: '14px',
                            height: '14px',
                            accentColor: tokens.accent.primary,
                            cursor: 'pointer',
                            opacity: 0.6
                          }}
                        />
                      </td>
                      <td style={{ padding: '16px', verticalAlign: 'top' }}>
                        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            {hasAuthForm && (
                              <IconButton
                                size="small"
                                onClick={() => toggleRowExpand(endpoint.id)}
                                sx={{ p: 0.2, color: tokens.accent.primary }}
                              >
                                {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                              </IconButton>
                            )}
                            <Typography sx={{
                              fontSize: '12px',
                              fontWeight: 500,
                              color: 'text.primary',
                              textDecoration: 'none',
                              wordBreak: 'break-all',
                              '&:hover': { color: tokens.accent.primary }
                            }} component="a" href={endpoint.http_url} target="_blank">
                              {endpoint.http_url}
                            </Typography>
                          </Box>

                          {/* Tech Badges */}
                          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                            {endpoint.webserver && (
                              <Box sx={{ px: 0.8, py: 0.2, bgcolor: isLight ? 'rgba(112, 0, 255, 0.08)' : 'rgba(112, 0, 255, 0.1)', border: `1px solid ${isLight ? 'rgba(112, 0, 255, 0.2)' : 'rgba(112, 0, 255, 0.3)'}`, borderRadius: 0.5 }}>
                                <Typography sx={{ fontSize: '9px', fontWeight: 800, color: isLight ? '#7c3aed' : '#7000ff' }}>{endpoint.webserver}</Typography>
                              </Box>
                            )}
                            {endpoint.techs?.map(tech => (
                              <Box key={tech.id} sx={{ px: 0.8, py: 0.2, bgcolor: `${tokens.accent.primary}15`, border: `1px solid ${tokens.accent.primary}4D`, borderRadius: 0.5 }}>
                                <Typography sx={{ fontSize: '9px', fontWeight: 800, color: tokens.accent.primary }}>{tech.name}</Typography>
                              </Box>
                            ))}
                            {hasAuthForm && (
                              <Box sx={{ px: 0.8, py: 0.2, bgcolor: 'rgba(249, 115, 22, 0.1)', border: '1px solid rgba(249, 115, 22, 0.3)', borderRadius: 0.5 }}>
                                <Typography sx={{ fontSize: '9px', fontWeight: 800, color: '#f97316' }}>🔑 AUTH FORM</Typography>
                              </Box>
                            )}
                          </Box>
                        </Box>
                      </td>
                      <td style={{ padding: '16px', verticalAlign: 'top' }}>
                        <Box sx={{
                          display: 'inline-flex',
                          px: 1.2,
                          py: 0.4,
                          borderRadius: 0.5,
                          bgcolor: `${getStatusColor(endpoint.http_status)}15`,
                          border: `1px solid ${getStatusColor(endpoint.http_status)}44`
                        }}>
                          <Typography sx={{ fontSize: '10px', fontWeight: 900, color: getStatusColor(endpoint.http_status), fontFamily: 'monospace' }}>
                            {endpoint.http_status}
                          </Typography>
                        </Box>
                      </td>
                      <Box component="td" sx={{ display: { xs: 'none', md: 'table-cell' }, padding: '16px', verticalAlign: 'top' }}>
                        <Typography sx={{ fontSize: '11px', color: 'text.secondary', fontWeight: 500, fontStyle: endpoint.page_title ? 'normal' : 'italic' }}>
                          {endpoint.page_title || 'No Title Available'}
                        </Typography>
                      </Box>
                      <Box component="td" sx={{ display: { xs: 'none', sm: 'table-cell' }, padding: '16px', verticalAlign: 'top' }}>
                        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                          {endpoint.matched_gf_patterns && endpoint.matched_gf_patterns.split(',').map((tag) => (
                            <Chip
                              key={tag}
                              label={tag.toUpperCase()}
                              size="small"
                              sx={{
                                height: 16,
                                fontSize: '8px',
                                fontWeight: 900,
                                bgcolor: `${tokens.accent.primary}15`,
                                color: tokens.accent.primary,
                                border: `1px solid ${tokens.accent.primary}33`,
                                borderRadius: 0.5
                              }}
                            />
                          ))}
                        </Box>
                      </Box>
                      <Box component="td" sx={{ display: { xs: 'none', lg: 'table-cell' }, padding: '16px', verticalAlign: 'top' }}>
                        <Stack spacing={0.5}>
                          <Typography sx={{ fontSize: '10px', color: 'text.secondary', fontFamily: 'monospace' }}>
                            TIME: {endpoint.response_time ? `${endpoint.response_time.toFixed(3)}s` : 'N/A'}
                          </Typography>
                        </Stack>
                      </Box>
                      <td style={{ padding: '16px', verticalAlign: 'top', textAlign: 'right' }}>
                        <Box sx={{ display: 'flex', justifyContent: 'flex-end', gap: 1 }}>
                          <Tooltip title="Extract Auth Forms">
                            <span>
                              <IconButton
                                size="small"
                                onClick={() => handleExtractAuth(endpoint.id, endpoint.http_url)}
                                disabled={isExtractPending}
                                sx={{ color: 'text.secondary', '&:hover': { color: tokens.accent.primary } }}
                              >
                                {isExtractPending ? <CircularProgress size={14} color="inherit" /> : <Key size={14} />}
                              </IconButton>
                            </span>
                          </Tooltip>
                          {credPluginEnabled && (
                            <Tooltip title="Brute Force Test">
                              <span>
                                <IconButton
                                  size="small"
                                  onClick={() => handleBruteOpen(endpoint.id, endpoint.http_url)}
                                  disabled={isBrutePending}
                                  sx={{ color: 'text.secondary', '&:hover': { color: tokens.accent.primary } }}
                                >
                                  {isBrutePending ? <CircularProgress size={14} color="inherit" /> : <Play size={14} />}
                                </IconButton>
                              </span>
                            </Tooltip>
                          )}
                          <Tooltip title="Copy URL">
                            <IconButton
                              size="small"
                              onClick={() => {
                                copyToClipboard(endpoint.http_url);
                                showNotification('Copied URL to clipboard');
                              }}
                              sx={{ color: 'text.secondary', '&:hover': { color: tokens.accent.primary } }}
                            >
                              <Copy size={14} />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Open in browser">
                            <IconButton
                              size="small"
                              component="a"
                              href={endpoint.http_url}
                              target="_blank"
                              sx={{ color: 'text.secondary', '&:hover': { color: tokens.accent.primary } }}
                            >
                              <ExternalLink size={14} />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Delete Endpoint">
                            <IconButton
                              size="small"
                              onClick={() => handleSingleDelete(endpoint.id)}
                              sx={{ color: 'text.secondary', '&:hover': { color: tokens.accent.error } }}
                            >
                              <Trash2 size={14} />
                            </IconButton>
                          </Tooltip>
                        </Box>
                      </td>
                    </tr>

                    {/* Collapsible Auth Candidates section */}
                    {isExpanded && endpoint.auth_candidates && endpoint.auth_candidates.map((candidate: any, idx: number) => (
                      <tr key={`expanded-${endpoint.id}-${idx}`} style={{ backgroundColor: isLight ? 'rgba(0,0,0,0.01)' : 'rgba(255,255,255,0.01)' }}>
                        <td colSpan={7} style={{ padding: '8px 16px 16px 56px' }}>
                          <Box sx={{
                            p: 2,
                            border: `1px solid ${isLight ? 'rgba(0,0,0,0.08)' : `${tokens.accent.primary}22`}`,
                            borderRadius: 1,
                            bgcolor: isLight ? '#fcfcfc' : 'rgba(255,255,255,0.02)',
                            boxShadow: `0 2px 8px ${tokens.accent.primary}08`
                          }}>
                            <Typography sx={{ fontSize: '10px', fontWeight: 800, color: tokens.accent.primary, mb: 1.5, letterSpacing: 1.5, fontFamily: 'Orbitron' }}>
                              EXTRACTED AUTH FORM DETAILS (CANDIDATE #{idx + 1})
                            </Typography>
                            <Stack spacing={1}>
                              <Box sx={{ display: 'flex', gap: 2 }}>
                                <Box sx={{ flex: 1 }}>
                                  <Typography sx={{ fontSize: '10px', color: 'text.secondary', fontWeight: 600 }}>ACTION (TARGET URL)</Typography>
                                  <Typography sx={{ fontSize: '11px', fontFamily: 'monospace', color: 'text.primary', wordBreak: 'break-all' }}>{candidate.target}</Typography>
                                </Box>
                                <Box sx={{ width: '120px' }}>
                                  <Typography sx={{ fontSize: '10px', color: 'text.secondary', fontWeight: 600 }}>METHOD</Typography>
                                  <Chip label={(candidate.metadata?.method || 'POST').toUpperCase()} size="small" sx={{ fontSize: '9px', fontWeight: 800, bgcolor: 'rgba(14, 165, 233, 0.1)', color: '#0ea5e9' }} />
                                </Box>
                              </Box>
                              <Box sx={{ display: 'flex', gap: 2, pt: 1, borderTop: '1px solid', borderColor: 'divider' }}>
                                <Box sx={{ flex: 1 }}>
                                  <Typography sx={{ fontSize: '10px', color: 'text.secondary', fontWeight: 600 }}>USERNAME FIELD</Typography>
                                  <Typography sx={{ fontSize: '11px', fontFamily: 'monospace', color: 'text.primary' }}>{candidate.metadata?.user_field || 'N/A'}</Typography>
                                </Box>
                                <Box sx={{ flex: 1 }}>
                                  <Typography sx={{ fontSize: '10px', color: 'text.secondary', fontWeight: 600 }}>PASSWORD FIELD</Typography>
                                  <Typography sx={{ fontSize: '11px', fontFamily: 'monospace', color: 'text.primary' }}>{candidate.metadata?.pass_field || 'N/A'}</Typography>
                                </Box>
                                {candidate.metadata?.all_fields && (
                                  <Box sx={{ flex: 2 }}>
                                    <Typography sx={{ fontSize: '10px', color: 'text.secondary', fontWeight: 600 }}>ALL FIELDS</Typography>
                                    <Typography sx={{ fontSize: '11px', fontFamily: 'monospace', color: 'text.primary' }}>{candidate.metadata.all_fields.join(', ')}</Typography>
                                  </Box>
                                )}
                              </Box>
                            </Stack>
                          </Box>
                        </td>
                      </tr>
                    ))}
                  </React.Fragment>
                );
              })}
              {(!isLoading && data?.results.length === 0) && (
                <tr>
                  <td colSpan={7} style={{ padding: '60px', textAlign: 'center' }}>
                    <Typography sx={{ color: 'text.disabled', fontFamily: 'Orbitron', fontSize: '0.8rem' }}>ZERO ENDPOINTS DETECTED</Typography>
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

      {bruteEndpoint && (
        <BruteConfigDialog
          open={bruteModalOpen}
          onClose={() => {
            setBruteModalOpen(false);
            setBruteEndpoint(null);
          }}
          onSubmit={handleBruteSubmit}
          targetUrl={bruteEndpoint.url}
          isPending={pendingActionId?.id === bruteEndpoint.id && pendingActionId?.action === 'brute_test'}
        />
      )}

      {/* Confirmation Dialog */}
      <ConfirmDialog
        open={confirmOpen}
        onClose={() => setConfirmOpen(false)}
        onConfirm={confirmConfig.onConfirm}
        type={confirmConfig.type}
        title={confirmConfig.title}
        message={confirmConfig.message}
        confirmText="Confirm"
        cancelText="Cancel"
      />

      <ExtractAuthModal
        open={extractAuthModalOpen}
        onClose={() => setExtractAuthModalOpen(false)}
        url={extractAuthUrl}
        workflowId={extractAuthWorkflowId}
        status={extractAuthStatus}
      />

      <Snackbar
        open={snackbar.open}
        autoHideDuration={4000}
        onClose={() => setSnackbar(prev => ({ ...prev, open: false }))}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        <Alert
          onClose={() => setSnackbar(prev => ({ ...prev, open: false }))}
          severity={snackbar.severity}
          variant="filled"
          sx={{ width: '100%', fontWeight: 700, fontFamily: 'Orbitron', fontSize: '11px', letterSpacing: 0.5 }}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
};
