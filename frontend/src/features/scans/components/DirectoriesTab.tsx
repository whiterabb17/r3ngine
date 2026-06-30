import React, { useState } from 'react';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import {
  Box,
  Typography,
  IconButton,
  Tooltip,
  CircularProgress,
  Pagination,
  Stack,
  Collapse,
  Button,
  Chip,
  InputBase,
  Modal,
  Backdrop,
  Fade,
  Menu,
  MenuItem,
  ListItemIcon,
  ListItemText,
  Divider,
  Snackbar,
  Alert,
} from '@mui/material';
import {
  Search,
  ChevronRight,
  ChevronDown,
  Folder,
  FolderPlus,
  ExternalLink,
  Copy,
  Zap,
  Eye,
  FileText,
  MoreHorizontal,
  Download,
  X,
  Camera,
  KeyRound,
  ShieldAlert,
  Crosshair,
  ScanSearch,
  UserX,
  Trash2,
} from 'lucide-react';

import { useDirectories } from '../api';
import { TacticalPanel } from '../../../components/TacticalPanel';
import type { DirectoryFile } from '../../subdomains/types';
import { ConfirmDialog } from '../../../components/ConfirmDialog';
import { usePlugins } from '../../plugins/api/pluginsApi';
import { useDirectoryFileDispatch, useDirectoryFileDelete } from '../api';
import { BruteConfigDialog } from './BruteConfigDialog';
import { getMenuPaperSx } from '../../../theme/semanticColors';

interface DirectoriesTabProps {
  projectSlug: string;
  scanId?: number;
  subdomainId?: number;
  subdomainName?: string;
  targetId?: number;
}

export const DirectoriesTab: React.FC<DirectoriesTabProps> = ({ projectSlug, scanId, subdomainId, subdomainName, targetId }) => {
  const { theme, isLight, tokens } = useThemeTokens();
  const [page, setPage] = useState(1);
  const [searchQuery, setSearchQuery] = useState('');
  const [activeSearch, setActiveSearch] = useState('');
  const [expandedSubdomains, setExpandedSubdomains] = useState<Record<number | string, boolean>>({});
  const [expandedScans, setExpandedScans] = useState<Record<string, boolean>>({});
  const [lightboxSrc, setLightboxSrc] = useState<string | null>(null);
  const [lightboxLabel, setLightboxLabel] = useState<string>('');

  // Action menu state
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [selectedFile, setSelectedFile] = useState<DirectoryFile | null>(null);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [confirmConfig, setConfirmConfig] = useState<{
    title: string;
    message: string;
    onConfirm: () => void;
    type?: 'danger' | 'info' | 'warning';
  }>({ title: '', message: '', onConfirm: () => {} });
  const [snackbar, setSnackbar] = useState<{
    open: boolean;
    message: string;
    severity: 'success' | 'error' | 'info' | 'warning';
  }>({ open: false, message: '', severity: 'success' });

  const [bruteModalOpen, setBruteModalOpen] = useState(false);
  const [pendingActionId, setPendingActionId] = useState<{ id: number; action: string } | null>(null);

  const { data: plugins } = usePlugins();
  const credPluginEnabled = plugins?.some(
    (p: { slug: string; is_enabled: boolean }) =>
      p.slug === 'credential_intelligence' && p.is_enabled
  );

  const dispatchMutation = useDirectoryFileDispatch();
  const deleteMutation = useDirectoryFileDelete();

  const showNotification = (
    message: string,
    severity: 'success' | 'error' | 'info' | 'warning' = 'success'
  ) => setSnackbar({ open: true, message, severity });

  const handleActionClick = (
    event: React.MouseEvent<HTMLButtonElement>,
    file: DirectoryFile
  ) => {
    event.stopPropagation();
    setAnchorEl(event.currentTarget);
    setSelectedFile(file);
  };

  const handleActionClose = () => setAnchorEl(null);

  const handleDispatchAction = async (action: string, label: string, extraParams?: any) => {
    if (!selectedFile || !scanId) return;
    handleActionClose();
    setPendingActionId({ id: selectedFile.id, action });
    try {
      await dispatchMutation.mutateAsync({
        url: selectedFile.url,
        action,
        scan_id: scanId,
        ...extraParams
      });
      showNotification(`${label} DISPATCHED`, 'success');
      if (action === 'brute_test') {
        setBruteModalOpen(false);
      }
    } catch (error: any) {
      showNotification(error.message || `Failed to dispatch ${label.toLowerCase()} — check Temporal logs`, 'error');
    } finally {
      setPendingActionId(null);
    }
  };

  const handleCopyUrl = () => {
    if (selectedFile) {
      navigator.clipboard.writeText(selectedFile.url);
      showNotification('URL COPIED TO CLIPBOARD', 'info');
    }
    handleActionClose();
  };

  const handleOpenInBrowser = () => {
    if (selectedFile) window.open(selectedFile.url, '_blank', 'noopener,noreferrer');
    handleActionClose();
  };

  const handleDelete = () => {
    if (!selectedFile) return;
    handleActionClose();
    setConfirmConfig({
      title: 'DELETE ENDPOINT RECORD',
      message: `Delete the record for ${selectedFile.url}? This cannot be undone.`,
      type: 'danger',
      onConfirm: async () => {
        try {
          await deleteMutation.mutateAsync({ directory_file_ids: [selectedFile.id] });
          showNotification('ENDPOINT RECORD DELETED');
        } catch {
          showNotification('Failed to delete endpoint record', 'error');
        }
      },
    });
    setConfirmOpen(true);
  };

  const { data, isLoading, error } = useDirectories({
    scan_id: scanId,
    subdomain_id: subdomainId,
    page: page
  });

  const groupedSubdomains = React.useMemo(() => {
    if (!data?.results) return [];
    
    const groups: Record<string, any[]> = {};
    data.results.forEach((file: any) => {
      let hostname = 'Unknown Target';
      try {
        if (file.url) {
          hostname = new URL(file.url).hostname;
        }
      } catch (e) {}
      
      if (!groups[hostname]) {
        groups[hostname] = [];
      }
      groups[hostname].push(file);
    });
    
    return Object.keys(groups).map((hostname, index) => {
      const highestStatus = groups[hostname].length > 0 
          ? groups[hostname].sort((a, b) => (b.http_status || 0) - (a.http_status || 0))[0].http_status 
          : 200;
          
      return {
        id: `grouped-${index}`,
        name: hostname,
        http_url: `http://${hostname}`,
        http_status: highestStatus,
        page_title: 'Directory Scan Target',
        directories: [
          {
            id: `scan-${index}`,
            scanned_date: 'Directory Enumeration',
            directory_files: groups[hostname]
          }
        ]
      };
    });
  }, [data]);

  const handleSearch = () => {
    setPage(1);
    setActiveSearch(searchQuery);
  };

  const toggleSubdomain = (id: number | string) => {
    setExpandedSubdomains(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const toggleScan = (id: string) => {
    setExpandedScans(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const openLightbox = (path: string, label: string) => {
    setLightboxSrc(`/media/${path}`);
    setLightboxLabel(label);
  };

  const closeLightbox = () => {
    setLightboxSrc(null);
    setLightboxLabel('');
  };  const getStatusColor = (status: number) => {
    if (status >= 200 && status < 300) return isLight ? tokens.accent.success : '#00ffaa';
    if (status >= 300 && status < 400) return tokens.accent.primary;
    if (status >= 400 && status < 500) return isLight ? tokens.accent.warning : '#ffae00';
    if (status >= 500) return isLight ? tokens.accent.error : '#ff003c';
    return isLight ? tokens.text.secondary : 'rgba(255,255,255,0.4)';
  };

  const decodeBase64 = (str: string) => {
    try {
      return atob(str);
    } catch (e) {
      return str;
    }
  };

  const isSummaryMode = !subdomainId;

  return (
    <Box sx={{ width: '100%' }}>
      {/* Tactical Header */}
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 4, mt: 2 }}>
        <Box>
          <Typography variant="h5" sx={{
            fontWeight: 900,
            fontFamily: 'Orbitron',
            letterSpacing: 3,
            color: 'text.primary',
            textTransform: 'uppercase'
          }}>
            Directory Fuzzing Results
          </Typography>
          <Typography sx={{ fontSize: '12px', color: 'text.secondary', mt: 0.5, letterSpacing: 1 }}>
            V3.0 SCAN ASSETS DIRECTORY ENUM
          </Typography>
        </Box>
      </Box>

      {/* Enterprise-Grade Search Bar */}
      <Box sx={{
        display: 'flex',
        bgcolor: isLight ? 'rgba(0,0,0,0.02)' : 'rgba(255,255,255,0.03)',
        borderRadius: '4px',
        overflow: 'hidden',
        mb: 3,
        border: '1px solid',
        borderColor: 'divider',
        '&:focus-within': {
          borderColor: tokens.accent.primary,
          boxShadow: `0 0 15px ${tokens.accent.primary}15`
        },
        transition: 'all 0.2s'
      }}>
        <Box sx={{ display: 'flex', alignItems: 'center', pl: 2, color: 'text.disabled' }}>
          <Search size={18} />
        </Box>
        <InputBase
          placeholder="Filter Directories (e.g. name=admin, status=200)"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
          sx={{
            flex: 1,
            px: 2,
            py: 1,
            fontSize: '0.9rem',
            color: 'text.primary',
            '&::placeholder': { color: 'text.disabled', opacity: 1 }
          }}
        />
        <Button
          onClick={handleSearch}
          sx={{
            bgcolor: isLight ? 'rgba(0,0,0,0.05)' : `${tokens.accent.primary}15`,
            color: tokens.accent.primary,
            px: 4,
            borderRadius: 0,
            fontWeight: 700,
            fontSize: '11px',
            letterSpacing: 1,
            borderLeft: '1px solid',
            borderLeftColor: 'divider',
            '&:hover': { bgcolor: 'action.hover' }
          }}
        >
          SEARCH
        </Button>
      </Box>

      <TacticalPanel>
        <Box sx={{
          p: 2,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          borderBottom: 1, borderColor: 'divider',
          bgcolor: 'action.hover'
        }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Typography sx={{ fontSize: '11px', fontWeight: 600, color: 'text.secondary' }}>Results :</Typography>
              <Box sx={{ px: 1, py: 0.5, bgcolor: 'action.hover', border: '1px solid', borderColor: 'divider', borderRadius: 1 }}>
                <Typography sx={{ fontSize: '11px', color: 'text.primary', fontWeight: 700 }}>{data?.count || 0}</Typography>
              </Box>
            </Box>
            <Box sx={{ px: 3, py: 0.8, bgcolor: isLight ? 'rgba(0,0,0,0.02)' : 'rgba(255,255,255,0.03)', borderRadius: 1, border: '1px solid', borderColor: 'divider' }}>
              <Typography sx={{ fontSize: '11px', fontWeight: 700, color: 'text.secondary', letterSpacing: 0.5 }}>
                Showing page {page} of {Math.ceil((data?.count || 0) / 50) || 1}
              </Typography>
            </Box>
          </Box>
          <Box sx={{ display: 'flex', gap: 1 }}>
            <IconButton size="small" sx={{ color: tokens.accent.primary, bgcolor: `${tokens.accent.primary}0D`, border: `1px solid ${tokens.accent.primary}15`, borderRadius: 1 }}>
              <Download size={14} />
            </IconButton>
          </Box>
        </Box>

        <Box sx={{ overflowX: 'auto', width: '100%' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', tableLayout: 'auto' }}>
            <thead>
              <tr style={{
                textAlign: 'left',
                borderBottom: '1px solid',
                borderColor: 'divider',
                backgroundColor: isLight ? 'rgba(0,0,0,0.02)' : 'rgba(255,255,255,0.02)'
              }}>
                <th style={{ width: '40px', padding: '12px 16px' }}></th>
                <Box component="th" sx={{ display: { xs: 'none', sm: 'table-cell' }, width: '80px', padding: '12px 16px', color: tokens.accent.primary, fontSize: '10px', fontWeight: 900, letterSpacing: 1.5, fontFamily: 'Orbitron' }}>VISUAL</Box>
                <th style={{ padding: '12px 16px', color: tokens.accent.primary, fontSize: '10px', fontWeight: 900, letterSpacing: 1.5, fontFamily: 'Orbitron' }}>SUBDOMAIN</th>
                <Box component="th" sx={{ display: { xs: 'none', md: 'table-cell' }, padding: '12px 16px', color: tokens.accent.primary, fontSize: '10px', fontWeight: 900, letterSpacing: 1.5, fontFamily: 'Orbitron' }}>STATUS</Box>
                <Box component="th" sx={{ display: { xs: 'none', lg: 'table-cell' }, padding: '12px 16px', color: tokens.accent.primary, fontSize: '10px', fontWeight: 900, letterSpacing: 1.5, fontFamily: 'Orbitron' }}>PAGE TITLE</Box>
                <th style={{ padding: '12px 16px', color: tokens.accent.primary, fontSize: '10px', fontWeight: 900, letterSpacing: 1.5, fontFamily: 'Orbitron' }}>DIRECTORIES DISCOVERED</th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr>
                  <td colSpan={6} style={{ padding: '80px', textAlign: 'center' }}>
                    <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2 }}>
                      <CircularProgress size={32} sx={{ color: tokens.accent.primary, filter: isLight ? 'none' : `drop-shadow(0 0 8px ${tokens.accent.primary})` }} />
                      <Typography sx={{ fontSize: '10px', fontWeight: 900, color: tokens.text.secondary, fontFamily: 'Orbitron', letterSpacing: 2 }}>
                        FETCHING DIRECTORY DATA...
                      </Typography>
                    </Box>
                  </td>
                </tr>
              ) : isSummaryMode ? (
                (data?.results || []).map((sd: any) => (
                  <React.Fragment key={sd.id}>
                    <tr style={{
                      borderBottom: '1px solid', borderColor: theme.palette.divider,
                      backgroundColor: expandedSubdomains[sd.id] ? `${tokens.accent.primary}0D` : 'transparent',
                      cursor: 'pointer',
                      transition: 'background 0.2s'
                    }} onClick={() => toggleSubdomain(sd.id)}>
                      <td style={{ padding: '12px 16px', textAlign: 'center' }}>
                        <IconButton size="small" sx={{ color: tokens.accent.primary }}>
                          {expandedSubdomains[sd.id] ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                        </IconButton>
                      </td>
                      <Box component="td" sx={{ display: { xs: 'none', sm: 'table-cell' }, padding: '12px 16px', textAlign: 'center' }}>
                        <Folder size={18} style={{ color: tokens.accent.primary }} />
                      </Box>
                      <td style={{ padding: '12px 16px' }}>
                        <Typography sx={{ fontSize: '13px', fontWeight: 700, color: 'text.primary' }}>{sd.name}</Typography>
                      </td>
                      <Box component="td" sx={{ display: { xs: 'none', md: 'table-cell' }, padding: '12px 16px' }}>
                        <Typography sx={{ fontSize: '11px', color: 'text.secondary', fontWeight: 800 }}>RECON ACTIVE</Typography>
                      </Box>
                      <Box component="td" sx={{ display: { xs: 'none', lg: 'table-cell' }, padding: '12px 16px' }}>
                        <Typography sx={{ fontSize: '12px', color: 'text.secondary' }}>Click to expand findings</Typography>
                      </Box>
                      <td style={{ padding: '12px 16px' }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <Box sx={{ 
                            px: 1, 
                            py: 0.2, 
                            bgcolor: isLight ? 'rgba(0,0,0,0.04)' : `${tokens.accent.primary}15`, 
                            borderRadius: 0.5, 
                            color: tokens.accent.primary, 
                            fontSize: '11px', 
                            fontWeight: 900,
                            fontFamily: 'Orbitron',
                            border: `1px solid ${tokens.accent.primary}33`
                          }}>
                            {sd.directory_count}
                          </Box>
                          <Typography sx={{ fontSize: '10px', color: 'text.secondary', textTransform: 'uppercase', letterSpacing: 1 }}>Paths</Typography>
                        </Box>
                      </td>
                    </tr>
                    <tr>
                      <td colSpan={6} style={{ padding: 0 }}>
                        <Collapse in={expandedSubdomains[sd.id]} timeout="auto" unmountOnExit>
                          <Box sx={{ p: 3, bgcolor: isLight ? 'rgba(14, 165, 233, 0.04)' : 'rgba(0, 243, 255, 0.02)', borderLeft: `2px solid ${tokens.accent.primary}` }}>
                            <SubdomainFilesContent scanId={scanId!} subdomainId={sd.id} />
                          </Box>
                        </Collapse>
                      </td>
                    </tr>
                  </React.Fragment>
                ))
              ) : (
                groupedSubdomains.map((sub: any) => (
                  <tr key={sub.id} style={{
                    borderBottom: '1px solid', borderColor: theme.palette.divider,
                    backgroundColor: 'transparent'
                  }}>
                    <td style={{ padding: '12px 16px', verticalAlign: 'top', textAlign: 'center' }}>
                      <IconButton size="small" onClick={() => toggleSubdomain(sub.id)} sx={{ color: 'text.disabled' }}>
                        {expandedSubdomains[sub.id] ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                      </IconButton>
                    </td>
                    <Box component="td" sx={{ display: { xs: 'none', sm: 'table-cell' }, padding: '12px 16px', verticalAlign: 'top', textAlign: 'center' }}>
                      {sub.screenshot_path ? (
                        <IconButton
                          size="small"
                          onClick={() => openLightbox(sub.screenshot_path!, sub.name)}
                          sx={{
                            color: tokens.accent.primary,
                            bgcolor: `${tokens.accent.primary}0D`,
                            border: `1px solid ${tokens.accent.primary}33`,
                            '&:hover': { bgcolor: 'action.hover', borderColor: tokens.accent.primary }
                          }}
                        >
                          <Eye size={14} />
                        </IconButton>
                      ) : (
                        <Camera size={14} style={{ color: 'text.disabled' }} />
                      )}
                    </Box>
                    <td style={{ padding: '12px 16px', verticalAlign: 'top' }}>
                      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <Typography sx={{ fontSize: '13px', fontWeight: 700, color: 'text.primary' }}>{sub.name}</Typography>
                          {sub.http_url && (
                            <IconButton size="small" component="a" href={sub.http_url} target="_blank" sx={{ p: 0.2, color: tokens.accent.primary }}>
                              <ExternalLink size={12} />
                            </IconButton>
                          )}
                          <IconButton size="small" sx={{ p: 0.2, color: 'text.disabled' }}>
                            <Copy size={12} />
                          </IconButton>
                        </Box>
                        {sub.is_interesting && (
                          <Chip
                            label="INTERESTING"
                            size="small"
                            sx={{
                              height: 16,
                              fontSize: '8px',
                              fontWeight: 900,
                              bgcolor: isLight ? 'rgba(239, 68, 68, 0.08)' : 'rgba(255, 0, 60, 0.1)',
                              color: tokens.accent.error,
                              borderRadius: 0.5,
                              border: '1px solid',
                              borderColor: 'error.main'
                            }}
                          />
                        )}
                      </Box>
                    </td>
                    <Box component="td" sx={{ display: { xs: 'none', md: 'table-cell' }, padding: '12px 16px', verticalAlign: 'top' }}>
                      <Box sx={{
                        display: 'inline-flex',
                        px: 1.2,
                        py: 0.4,
                        borderRadius: 0.5,
                        bgcolor: `${getStatusColor(sub.http_status)}20`,
                        border: `1px solid ${getStatusColor(sub.http_status)}40`,
                      }}>
                        <Typography sx={{ fontSize: '11px', fontWeight: 900, color: getStatusColor(sub.http_status) }}>
                          {sub.http_status}
                        </Typography>
                      </Box>
                    </Box>
                    <Box component="td" sx={{ display: { xs: 'none', lg: 'table-cell' }, padding: '12px 16px', verticalAlign: 'top' }}>
                      <Typography sx={{ fontSize: '12px', color: 'text.secondary' }}>
                        {sub.page_title || '-'}
                      </Typography>
                    </Box>
                    <td style={{ padding: '12px 16px', verticalAlign: 'top' }}>
                      {sub.directories && sub.directories.length > 0 ? (
                        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                          {sub.directories.length > 1 && (
                            <Typography sx={{ fontSize: '11px', color: 'text.secondary', mb: 1 }}>
                              Directory Scan performed {sub.directories.length} times.
                            </Typography>
                          )}
                          <Stack spacing={1}>
                            {[...sub.directories].reverse().map((scan, idx) => (
                              <Box key={scan.id}>
                                <Box
                                  onClick={() => toggleScan(`${sub.id}-${scan.id}`)}
                                  sx={{
                                    display: 'flex',
                                    alignItems: 'center',
                                    gap: 1,
                                    cursor: 'pointer',
                                    '&:hover': { color: tokens.accent.primary },
                                    color: 'text.primary',
                                    transition: 'color 0.2s'
                                  }}
                                >
                                  {expandedScans[`${sub.id}-${scan.id}`] ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                                  <FolderPlus size={14} style={{ color: tokens.accent.primary }} />
                                  <Typography sx={{ fontSize: '12px', fontWeight: 600 }}>
                                    <Box component="span" sx={{ px: 1, py: 0.2, bgcolor: isLight ? 'rgba(0,0,0,0.04)' : `${tokens.accent.primary}15`, borderRadius: 0.5, mr: 1, color: tokens.accent.primary }}>
                                      {scan.directory_files.length}
                                    </Box>
                                    Directories found on {scan.scanned_date}
                                  </Typography>
                                </Box>

                                <Collapse in={expandedScans[`${sub.id}-${scan.id}`]}>
                                  <Box sx={{ ml: 4, mt: 1, borderLeft: '1px dashed', borderLeftColor: 'divider', pl: 2 }}>
                                    <Stack spacing={1}>
                                      {scan.directory_files.map((file: any, fIdx: number) => (
                                        <Box
                                          key={`${scan.id}-${fIdx}`}
                                          sx={{
                                            display: 'flex',
                                            alignItems: 'center',
                                            justifyContent: 'space-between',
                                            p: 1,
                                            bgcolor: 'action.hover',
                                            borderRadius: 0.5,
                                            '&:hover': { bgcolor: 'action.selected' }
                                          }}
                                        >
                                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, flex: 1 }}>
                                            <Typography sx={{
                                              fontSize: '12px',
                                              fontWeight: 700,
                                              color: 'text.primary',
                                              textDecoration: 'none',
                                              '&:hover': { color: tokens.accent.primary }
                                            }} component="a" href={file.url} target="_blank">
                                              {decodeBase64(file.name)}
                                            </Typography>
                                            <Box sx={{
                                              px: 0.8,
                                              py: 0.1,
                                              borderRadius: 0.5,
                                              bgcolor: `${getStatusColor(file.http_status)}20`,
                                              border: `1px solid ${getStatusColor(file.http_status)}40`,
                                            }}>
                                              <Typography sx={{ fontSize: '9px', fontWeight: 900, color: getStatusColor(file.http_status) }}>
                                                {file.http_status}
                                              </Typography>
                                            </Box>
                                            <Chip
                                              label={file.content_type}
                                              size="small"
                                              sx={{ height: 14, fontSize: '8px', bgcolor: 'action.hover', color: 'text.secondary', borderRadius: 0.5 }}
                                            />
                                          </Box>
                                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                                            <Typography sx={{ fontSize: '10px', color: 'text.secondary', fontFamily: 'monospace' }}>
                                              {(file.length / 1024).toFixed(1)} KB
                                            </Typography>
                                            {file.lines && (
                                              <Typography sx={{ fontSize: '10px', color: 'text.secondary', fontFamily: 'monospace' }}>
                                                {file.lines} L
                                              </Typography>
                                            )}
                                            <IconButton size="small" component="a" href={file.url} target="_blank" sx={{ color: 'text.disabled', p: 0.5 }}>
                                              <ExternalLink size={12} />
                                            </IconButton>
                                            <IconButton
                                              size="small"
                                              onClick={(e) => handleActionClick(e, file as DirectoryFile)}
                                              sx={{
                                                color: 'text.secondary',
                                                p: 0.5,
                                                '&:hover': {
                                                  color: tokens.accent.primary,
                                                },
                                              }}
                                            >
                                              <MoreHorizontal size={12} />
                                            </IconButton>
                                          </Box>
                                        </Box>
                                      ))}
                                    </Stack>
                                  </Box>
                                </Collapse>
                              </Box>
                            ))}
                          </Stack>
                        </Box>
                      ) : (
                        <Typography sx={{ fontSize: '11px', color: 'text.disabled', fontStyle: 'italic' }}>
                          No directory data available
                        </Typography>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </Box>

        <Box sx={{ p: 2, display: 'flex', justifyContent: 'center', borderTop: '1px solid', borderColor: 'divider' }}>
          <Stack spacing={2}>
            <Pagination
              count={Math.ceil((data?.count || 0) / 50)}
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
                  }
                }
              }}
            />
          </Stack>
        </Box>
      </TacticalPanel>

      <Modal
        open={!!lightboxSrc}
        onClose={closeLightbox}
        closeAfterTransition
        slots={{ backdrop: Backdrop }}
        slotProps={{
          backdrop: {
            sx: { bgcolor: 'rgba(0, 0, 0, 0.92)', backdropFilter: 'blur(6px)' },
            timeout: 200,
          },
        }}
      >
        <Fade in={!!lightboxSrc} timeout={200}>
          <Box
            onClick={closeLightbox}
            sx={{
              position: 'fixed',
              inset: 0,
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              p: 4,
              outline: 'none',
            }}
          >
            <Box
              onClick={(e) => e.stopPropagation()}
              sx={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                width: '100%',
                maxWidth: '90vw',
                mb: 1.5,
              }}
            >
              <Typography sx={{
                color: tokens.accent.primary,
                fontFamily: 'Orbitron',
                fontSize: '12px',
                fontWeight: 700,
                letterSpacing: 1,
                overflow: 'hidden',
                textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                maxWidth: 'calc(100% - 80px)'
              }}>
                {lightboxLabel}
              </Typography>
              <Box sx={{ display: 'flex', gap: 1 }}>
                <IconButton
                  component="a"
                  href={lightboxSrc ?? '#'}
                  target="_blank"
                  rel="noopener noreferrer"
                  onClick={(e) => e.stopPropagation()}
                  size="small"
                  sx={{
                    color: 'rgba(255,255,255,0.6)',
                    bgcolor: 'action.hover',
                    border: '1px solid rgba(255,255,255,0.1)',
                    '&:hover': { color: tokens.accent.primary, borderColor: `${tokens.accent.primary}66` },
                  }}
                >
                  <ExternalLink size={14} />
                </IconButton>
                <IconButton
                  onClick={closeLightbox}
                  size="small"
                  sx={{
                    color: 'rgba(255,255,255,0.6)',
                    bgcolor: 'action.hover',
                    border: '1px solid rgba(255,255,255,0.1)',
                    '&:hover': { color: '#ff003c', borderColor: 'rgba(255,0,60,0.4)' },
                  }}
                >
                  <X size={14} />
                </IconButton>
              </Box>
            </Box>

            <Box
              onClick={(e) => e.stopPropagation()}
              sx={{
                maxWidth: '90vw',
                maxHeight: '80vh',
                border: `1px solid ${isLight ? 'rgba(0,0,0,0.15)' : `${tokens.accent.primary}33`}`,
                borderRadius: 1,
                overflow: 'hidden',
                boxShadow: `0 0 60px ${tokens.accent.primary}15`,
              }}
            >
              {lightboxSrc && (
                <img
                  src={lightboxSrc}
                  alt={lightboxLabel}
                  style={{
                    display: 'block',
                    maxWidth: '90vw',
                    maxHeight: '80vh',
                    objectFit: 'contain',
                  }}
                />
              )}
            </Box>

            <Typography
              onClick={closeLightbox}
              sx={{
                mt: 2,
                fontSize: '10px',
                color: 'text.disabled',
                fontFamily: 'Orbitron',
                letterSpacing: 1,
                cursor: 'pointer',
                userSelect: 'none',
              }}
            >
              CLICK ANYWHERE TO CLOSE
            </Typography>
          </Box>
        </Fade>
      </Modal>

      {/* Directory File Action Menu */}
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleActionClose}
        slotProps={{
          paper: {
            sx: {
              ...getMenuPaperSx(isLight, theme, tokens),
              border: `1px solid ${isLight ? 'rgba(0,0,0,0.1)' : `${theme.palette.primary.main}33`}`,
              color: 'text.primary',
              minWidth: 220,
              '& .MuiMenuItem-root': {
                fontSize: '0.8rem',
                fontWeight: 600,
                fontFamily: 'Inter, sans-serif',
                py: 1,
                gap: 1.5,
                '&:hover': {
                  bgcolor: `${tokens.accent.primary}15`,
                },
              },
            },
          },
        }}
      >
        <MenuItem onClick={() => handleDispatchAction('extract_auth', 'AUTH EXTRACTION')}>
          <ListItemIcon><KeyRound size={15} color={theme.palette.warning.main} /></ListItemIcon>
          <ListItemText primary="EXTRACT AUTH" />
        </MenuItem>
        <MenuItem onClick={() => handleDispatchAction('scan_vuln', 'VULNERABILITY SCAN')}>
          <ListItemIcon><ShieldAlert size={15} color={theme.palette.error.main} /></ListItemIcon>
          <ListItemText primary="SCAN VULNERABILITIES" />
        </MenuItem>
        <MenuItem onClick={() => handleDispatchAction('deep_fuzz', 'DEEP FUZZ')}>
          <ListItemIcon><Crosshair size={15} color={theme.palette.info.main} /></ListItemIcon>
          <ListItemText primary="DEEP FUZZ" />
        </MenuItem>
        <MenuItem onClick={() => handleDispatchAction('secret_scan', 'SECRET SCAN')}>
          <ListItemIcon><ScanSearch size={15} color={theme.palette.success.main} /></ListItemIcon>
          <ListItemText primary="SCAN FOR SECRETS" />
        </MenuItem>
        <MenuItem onClick={() => handleDispatchAction('bypass_waf', 'WAF BYPASS')}>
          <ListItemIcon><Zap size={15} color={theme.palette.secondary.main} /></ListItemIcon>
          <ListItemText primary="BYPASS WAF" />
        </MenuItem>
        <Divider sx={{ my: 0.5, borderColor: theme.palette.divider }} />
        <Tooltip
          title={credPluginEnabled ? '' : 'Credential Intelligence plugin not installed'}
          placement="left"
        >
          <span>
            <MenuItem
              disabled={!credPluginEnabled}
              onClick={() => {
                setBruteModalOpen(true);
                handleActionClose();
              }}
            >
              <ListItemIcon>
                <UserX
                  size={15}
                  color={credPluginEnabled ? theme.palette.warning.main : theme.palette.text.disabled}
                />
              </ListItemIcon>
              <ListItemText primary="SEND TO BRUTE TEST" />
            </MenuItem>
          </span>
        </Tooltip>
        <Divider sx={{ my: 0.5, borderColor: theme.palette.divider }} />
        <MenuItem onClick={handleCopyUrl}>
          <ListItemIcon><Copy size={15} color={theme.palette.text.secondary} /></ListItemIcon>
          <ListItemText primary="COPY URL" />
        </MenuItem>
        <MenuItem onClick={handleOpenInBrowser}>
          <ListItemIcon><ExternalLink size={15} color={theme.palette.text.secondary} /></ListItemIcon>
          <ListItemText primary="OPEN IN BROWSER" />
        </MenuItem>
        <Divider sx={{ my: 0.5, borderColor: theme.palette.divider }} />
        <MenuItem onClick={handleDelete} sx={{ color: theme.palette.error.main }}>
          <ListItemIcon><Trash2 size={15} color={theme.palette.error.main} /></ListItemIcon>
          <ListItemText primary="DELETE RECORD" />
        </MenuItem>
      </Menu>

      {/* Confirm Dialog */}
      <ConfirmDialog
        open={confirmOpen}
        onClose={() => { setConfirmOpen(false); setSelectedFile(null); }}
        onConfirm={() => { confirmConfig.onConfirm(); setConfirmOpen(false); }}
        title={confirmConfig.title}
        message={confirmConfig.message}
        type={confirmConfig.type}
      />

      {/* Loading Backdrop */}
      <Backdrop
        sx={{
          color: theme.palette.primary.main,
          zIndex: (t) => t.zIndex.drawer + 1,
          bgcolor: 'rgba(0,0,0,0.8)',
        }}
        open={dispatchMutation.isPending || deleteMutation.isPending}
      >
        <Stack spacing={2} sx={{ alignItems: 'center' }}>
          <CircularProgress color="inherit" size={60} thickness={2} />
          <Typography sx={{ fontFamily: isLight ? 'var(--r3-heading-font)' : 'Orbitron', letterSpacing: 2, fontSize: '0.9rem' }}>
            {deleteMutation.isPending ? 'DELETING RECORD...' : 'DISPATCHING ACTION...'}
          </Typography>
        </Stack>
      </Backdrop>

      {/* Snackbar */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={4000}
        onClose={() => setSnackbar((s) => ({ ...s, open: false }))}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        <Alert
          onClose={() => setSnackbar((s) => ({ ...s, open: false }))}
          severity={snackbar.severity}
          variant="filled"
        >
          {snackbar.message}
        </Alert>
      </Snackbar>

      {selectedFile && (
        <BruteConfigDialog
          open={bruteModalOpen}
          onClose={() => {
            setBruteModalOpen(false);
            setSelectedFile(null);
          }}
          onSubmit={(params) => handleDispatchAction('brute_test', 'BRUTE TEST', params)}
          targetUrl={selectedFile.url}
          isPending={pendingActionId?.id === selectedFile.id && pendingActionId?.action === 'brute_test'}
        />
      )}
    </Box>
  );
};

const SubdomainFilesContent: React.FC<{ scanId: number; subdomainId: number }> = ({ scanId, subdomainId }) => {
  const { theme, isLight, tokens } = useThemeTokens();
  const { data, isLoading } = useDirectories({ scan_id: scanId, subdomain_id: subdomainId });

  const getStatusColor = (status: number) => {
    if (status >= 200 && status < 300) return isLight ? tokens.accent.success : '#00ffaa';
    if (status >= 300 && status < 400) return tokens.accent.primary;
    if (status >= 400 && status < 500) return isLight ? tokens.accent.warning : '#ffae00';
    if (status >= 500) return isLight ? tokens.accent.error : '#ff003c';
    return isLight ? tokens.text.secondary : 'rgba(255,255,255,0.4)';
  };

  const decodeBase64 = (str: string) => {
    try {
      return atob(str);
    } catch (e) {
      return str;
    }
  };

  if (isLoading) {
    return (
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, py: 2 }}>
        <CircularProgress size={16} sx={{ color: tokens.accent.primary }} />
        <Typography sx={{ fontSize: '10px', color: tokens.text.secondary, fontWeight: 800, fontFamily: 'Orbitron' }}>
          DECRYPTING FILE SYSTEM...
        </Typography>
      </Box>
    );
  }

  if (!data?.results || data.results.length === 0) {
    return (
      <Typography sx={{ fontSize: '11px', color: 'text.disabled', fontStyle: 'italic' }}>
        No directory findings associated with this subdomain.
      </Typography>
    );
  }

  return (
    <Stack spacing={1.5}>
      {data.results.map((file: any, idx: number) => (
        <Box
          key={idx}
          sx={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            p: 1.5,
            bgcolor: isLight ? 'rgba(0,0,0,0.02)' : 'rgba(255,255,255,0.03)',
            borderRadius: 1,
            border: 1, borderColor: 'divider',
            '&:hover': { 
              bgcolor: 'action.hover',
              borderColor: tokens.accent.primary,
              boxShadow: `0 0 10px ${tokens.accent.primary}0D`
            },
            transition: 'all 0.2s'
          }}
        >
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, flex: 1 }}>
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }}>
              <Typography sx={{
                fontSize: '12px',
                fontWeight: 700,
                color: 'text.primary',
                textDecoration: 'none',
                '&:hover': { color: tokens.accent.primary }
              }} component="a" href={file.url} target="_blank">
                {decodeBase64(file.name)}
              </Typography>
              <Typography sx={{ fontSize: '10px', color: 'text.disabled', fontFamily: 'monospace' }}>
                {file.url}
              </Typography>
            </Box>
            
            <Box sx={{
              px: 1,
              py: 0.2,
              borderRadius: 0.5,
              bgcolor: `${getStatusColor(file.http_status)}20`,
              border: `1px solid ${getStatusColor(file.http_status)}40`,
            }}>
              <Typography sx={{ fontSize: '10px', fontWeight: 900, color: getStatusColor(file.http_status) }}>
                {file.http_status}
              </Typography>
            </Box>
            
            <Chip
              label={file.content_type || 'unknown'}
              size="small"
              sx={{ height: 16, fontSize: '9px', bgcolor: 'action.hover', color: 'text.secondary', borderRadius: 0.5 }}
            />
          </Box>
          
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 3 }}>
            <Stack direction="row" spacing={2}>
              <Box sx={{ textAlign: 'right' }}>
                <Typography sx={{ fontSize: '9px', color: 'text.disabled', fontWeight: 800 }}>SIZE</Typography>
                <Typography sx={{ fontSize: '11px', color: 'text.secondary', fontFamily: 'monospace' }}>
                  {(file.length / 1024).toFixed(1)} KB
                </Typography>
              </Box>
              {file.lines && (
                <Box sx={{ textAlign: 'right' }}>
                  <Typography sx={{ fontSize: '9px', color: 'text.disabled', fontWeight: 800 }}>LINES</Typography>
                  <Typography sx={{ fontSize: '11px', color: 'text.secondary', fontFamily: 'monospace' }}>
                    {file.lines}
                  </Typography>
                </Box>
              )}
            </Stack>
            <IconButton size="small" component="a" href={file.url} target="_blank" sx={{ color: tokens.accent.primary, bgcolor: `${tokens.accent.primary}0D`, p: 1 }}>
              <ExternalLink size={14} />
            </IconButton>
          </Box>
        </Box>
      ))}
    </Stack>
  );
};
