import React from 'react';
import {
  Box,
  Card,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  IconButton,
  LinearProgress,
  Tooltip,
  TextField,
  InputAdornment,
  Button,
  Menu,
  MenuItem,
  Checkbox,
  TablePagination,
  Paper,
  CircularProgress,
  Snackbar,
  Alert
} from '@mui/material';
import {
  Search,
  Activity,
  Clock,
  CheckCircle2,
  XCircle,
  Play,
  StopCircle,
  MoreVertical,
  RefreshCw,
  Eye,
  Settings,
  Share2,
  Trash2,
  FileText,
  AlertTriangle,
  Download,
  Terminal,
  Shield,
  Bug,
  Layers,
  ChevronRight,
  Globe,
  AlertCircle,
  Pause,
  PauseCircle
} from 'lucide-react';
import {
  useScansHistory,
  useStopScan,
  useResumeScan,
  useDeleteScan,
  useBulkScanAction,
  useDomains,
  usePauseScan,
  useUnpauseScan
} from '../api';
import { useParams, Link as RouterLink, useNavigate } from '@tanstack/react-router';
import { ScanReportModal } from './ScanReportModal';
import { StartScanModal } from './StartScanModal';
import { ConfirmDialog } from '../../../components/ConfirmDialog';

import { timeout } from 'd3';
import type { ScanHistory } from '../types';
import { useThemeTokens } from '../../../theme/useThemeTokens';

export const ScanHistoryPage: React.FC = () => {
  const { tokens, isLight, theme } = useThemeTokens();
  const { projectSlug = 'default' } = useParams({ strict: false }) as any;
  const navigate = useNavigate();
  const { data: scans, isLoading } = useScansHistory(projectSlug);
  const stopScanMutation = useStopScan(projectSlug);
  const resumeScanMutation = useResumeScan(projectSlug);
  const deleteScanMutation = useDeleteScan(projectSlug);
  const bulkActionMutation = useBulkScanAction(projectSlug);
  const pauseScanMutation = usePauseScan(projectSlug);
  const unpauseScanMutation = useUnpauseScan(projectSlug);
  const { data: domains } = useDomains(projectSlug);

  const [searchQuery, setSearchQuery] = React.useState('');
  const [page, setPage] = React.useState(0);
  const [rowsPerPage, setRowsPerPage] = React.useState(10);
  const [selected, setSelected] = React.useState<number[]>([]);
  const [anchorEl, setAnchorEl] = React.useState<null | HTMLElement>(null);
  const [activeScanId, setActiveScanId] = React.useState<number | null>(null);
  const [reportScanId, setReportScanId] = React.useState<number | null>(null);
  const [reportModalOpen, setReportModalOpen] = React.useState(false);
  //const [rescanModalOpen, setRescanModalOpen] = React.useState(false);
  //const [rescanTarget, setRescanTarget] = React.useState<{ ids: number[]; names: string[] } | null>(null);
  const [snackbar, setSnackbar] = React.useState<{ open: boolean; message: string; severity: 'success' | 'error' | 'info' }>({
    open: false,
    message: '',
    severity: 'success'
  });

  const [activeTarget, setActiveTarget] = React.useState<{ id: number; name: string } | null>(null);
  const [startScanTargets, setStartScanTargets] = React.useState<{ ids: number[]; names: string[] } | null>(null);

  // Confirmation state
  const [confirmOpen, setConfirmOpen] = React.useState(false);
  const [confirmConfig, setConfirmConfig] = React.useState<{
    title: string;
    message: string;
    onConfirm: () => void;
    type?: 'danger' | 'info' | 'warning';
  }>({
    title: '',
    message: '',
    onConfirm: () => { },
  });

  const handleCloseSnackbar = () => setSnackbar(prev => ({ ...prev, open: false }));

  const handleMenuOpen = (event: React.MouseEvent<HTMLElement>, _id: number, domainName: string) => {
    setAnchorEl(event.currentTarget);
    setActiveScanId(_id);
    setActiveTarget({ id: _id, name: domainName });
  };

  const handleMenuClose = () => {
    setAnchorEl(null);
    setActiveScanId(null);
  };

  const handleSelectAllClick = (event: React.ChangeEvent<HTMLInputElement>) => {
    if (event.target.checked && scans) {
      const newSelecteds = scans.map((n) => n.id!);
      setSelected(newSelecteds);
      return;
    }
    setSelected([]);
  };

  const handleClick = (id: number) => {
    const selectedIndex = selected.indexOf(id);
    let newSelected: number[] = [];

    if (selectedIndex === -1) {
      newSelected = newSelected.concat(selected, id);
    } else if (selectedIndex === 0) {
      newSelected = newSelected.concat(selected.slice(1));
    } else if (selectedIndex === selected.length - 1) {
      newSelected = newSelected.concat(selected.slice(0, -1));
    } else if (selectedIndex > 0) {
      newSelected = newSelected.concat(
        selected.slice(0, selectedIndex),
        selected.slice(selectedIndex + 1)
      );
    }
    setSelected(newSelected);
  };

  const isSelected = (id: number) => selected.indexOf(id) !== -1;

  const sortedScans = React.useMemo(() => {
    if (!scans) return [];
    return [...scans].sort((a, b) => (b.id || 0) - (a.id || 0));
  }, [scans]);

  const filteredScans = React.useMemo(() => {
    return sortedScans.filter(scan =>
      scan.domain?.name?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      scan.engine_name?.toLowerCase().includes(searchQuery.toLowerCase())
    );
  }, [sortedScans, searchQuery]);

  const paginatedScans = React.useMemo(() => {
    return filteredScans.slice(page * rowsPerPage, page * rowsPerPage + rowsPerPage);
  }, [filteredScans, page, rowsPerPage]);

  const getStatusChip = (scan: ScanHistory) => {
    const status = scan.scan_status;
    if (scan.is_spiderfoot_running) {
      return (
        <Tooltip title="SpiderFoot OSINT Scan is running in the background">
          <Chip
            label="SPIDERFOOT ACTIVE"
            size="small"
            sx={{
              bgcolor: 'rgba(255, 0, 255, 0.1)',
              color: tokens.accent.secondary,
              border: '1px solid rgba(255, 0, 255, 0.4)',
              fontSize: '0.65rem',
              fontWeight: 900,
              fontFamily: 'Orbitron',
              animation: 'pulse-spider 2s infinite ease-in-out',
              '@keyframes pulse-spider': {
                '0%': { transform: 'scale(1)', filter: `drop-shadow(0 0 0px ${tokens.accent.secondary})` },
                '50%': { transform: 'scale(1.05)', filter: `drop-shadow(0 0 8px ${tokens.accent.secondary})` },
                '100%': { transform: 'scale(1)', filter: `drop-shadow(0 0 0px ${tokens.accent.secondary})` },
              }
            }}
            icon={<Bug size={12} color={tokens.accent.secondary} />}
          />
        </Tooltip>
      );
    }
    switch (status) {
      case 2: { // Complete
        const total = scan.total_task_count ?? 0;
        const ok    = scan.successful_task_count ?? 0;
        const completeLabel = total > 0 ? `COMPLETE ${ok}/${total}` : 'COMPLETE';
        const color = isLight ? tokens.accent.success : '#00ff62';
        return <Chip label={completeLabel} size="small" sx={{ bgcolor: isLight ? `${tokens.accent.success}1A` : 'rgba(0, 255, 98, 0.1)', color: color, border: `1px solid ${color}33`, fontSize: '0.65rem', fontWeight: 900, fontFamily: 'Orbitron' }} icon={<CheckCircle2 size={12} />} />;
      }
      case 1: // Running
        return <Chip label="RUNNING" size="small" sx={{ bgcolor: `${tokens.accent.primary}15`, color: tokens.accent.primary, border: `1px solid ${tokens.accent.primary}33`, fontSize: '0.65rem', fontWeight: 900, fontFamily: 'Orbitron' }} icon={<RefreshCw size={12} className="spin" />} />;
      case 5: { // Paused
        const color = isLight ? '#d97706' : '#ffab00';
        return (
          <Chip
            label="PAUSED"
            size="small"
            sx={{
              bgcolor: isLight ? '#d977061A' : 'rgba(255, 171, 0, 0.1)',
              color: color,
              border: `1px solid ${color}33`,
              fontSize: '0.65rem',
              fontWeight: 900,
              fontFamily: 'Orbitron',
              animation: 'pulse-paused 2s infinite ease-in-out',
              '@keyframes pulse-paused': {
                '0%': { transform: 'scale(1)', filter: `drop-shadow(0 0 0px ${color})` },
                '50%': { transform: 'scale(1.02)', filter: `drop-shadow(0 0 4px ${color})` },
                '100%': { transform: 'scale(1)', filter: `drop-shadow(0 0 0px ${color})` },
              }
            }}
            icon={<PauseCircle size={12} color={color} />}
          />
        );
      }
      case 3: { // Aborted
        const color = isLight ? tokens.accent.error : '#ff003c';
        return <Chip label="ABORTED" size="small" sx={{ bgcolor: isLight ? `${tokens.accent.error}1A` : 'rgba(255, 0, 60, 0.1)', color: color, border: `1px solid ${color}33`, fontSize: '0.65rem', fontWeight: 900, fontFamily: 'Orbitron' }} icon={<AlertTriangle size={12} />} />;
      }
      case 0: { // Failed
        const total = scan.total_task_count ?? 0;
        const ok    = scan.successful_task_count ?? 0;
        const failedLabel = total > 0 ? `FAILED ${ok}/${total}` : 'FAILED';
        const color = isLight ? tokens.accent.error : '#ff003c';
        return <Chip label={failedLabel} size="small" sx={{ bgcolor: isLight ? `${tokens.accent.error}1A` : 'rgba(255, 0, 60, 0.1)', color: color, border: `1px solid ${color}33`, fontSize: '0.65rem', fontWeight: 900, fontFamily: 'Orbitron' }} icon={<XCircle size={12} />} />;
      }
      case 4: { // Partially Complete
        const warnColor = isLight ? '#d97706' : '#fffc00';
        return <Chip label="PARTIALLY COMPLETE" size="small" sx={{ bgcolor: isLight ? '#d977061A' : 'rgba(255, 252, 0, 0.1)', color: warnColor, border: `1px solid ${warnColor}33`, fontSize: '0.65rem', fontWeight: 900, fontFamily: 'Orbitron' }} icon={<AlertTriangle size={12} />} />;
      }
      default: {
        const color = isLight ? '#d97706' : '#ffab00';
        return <Chip label="PENDING" size="small" sx={{ bgcolor: isLight ? '#d977061A' : 'rgba(255, 171, 0, 0.1)', color: color, border: `1px solid ${color}33`, fontSize: '0.65rem', fontWeight: 900, fontFamily: 'Orbitron' }} icon={<Clock size={12} />} />;
      }
    }
  };

  if (isLoading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%', mt: 10 }}>
        <CircularProgress sx={{ color: tokens.accent.primary }} />
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      <Box sx={{ mb: 4, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Box>
          <Typography variant="h5" sx={{ fontWeight: 900, fontFamily: 'Orbitron', color: 'text.primary', letterSpacing: 2 }}>SCAN HISTORY</Typography>
          <Typography variant="body2" sx={{ color: 'text.secondary', fontFamily: 'Orbitron', fontSize: '0.7rem' }}>
            MANAGE AND AUDIT PAST SECURITY OPERATIONS
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', gap: 2 }}>
          {selected.length > 0 && (
            <>
              <Button
                variant="outlined"
                color="warning"
                startIcon={<Pause size={18} />}
                onClick={() => {
                  pauseScanMutation.mutate({ scan_ids: selected });
                  setSelected([]);
                }}
                sx={{ fontFamily: 'Orbitron', fontSize: '0.7rem', fontWeight: 800, borderColor: '#ffab00', color: '#ffab00' }}
              >
                PAUSE SELECTED
              </Button>
              <Button
                variant="outlined"
                color="success"
                startIcon={<Play size={18} />}
                onClick={() => {
                  unpauseScanMutation.mutate({ scan_ids: selected });
                  setSelected([]);
                }}
                sx={{ fontFamily: 'Orbitron', fontSize: '0.7rem', fontWeight: 800, borderColor: '#00ff62', color: '#00ff62' }}
              >
                UNPAUSE SELECTED
              </Button>
              <Button
                variant="outlined"
                color="error"
                startIcon={<StopCircle size={18} />}
                onClick={() => bulkActionMutation.mutate({ action: 'bulk_stop', ids: selected })}
                sx={{ fontFamily: 'Orbitron', fontSize: '0.7rem', fontWeight: 800, borderColor: '#ff003c', color: '#ff003c' }}
              >
                STOP SELECTED
              </Button>
              <Button
                variant="outlined"
                color="error"
                startIcon={<Trash2 size={18} />}
                onClick={() => {
                  setConfirmConfig({
                    title: 'BULK DELETE SCANS',
                    message: `Are you sure you want to delete ${selected.length} scan records? This will permanently remove all associated data.`,
                    type: 'danger',
                    onConfirm: () => {
                      bulkActionMutation.mutate({ action: 'bulk_delete', ids: selected });
                      setSelected([]);
                    }
                  });
                  setConfirmOpen(true);
                }}
                sx={{ fontFamily: 'Orbitron', fontSize: '0.7rem', fontWeight: 800, borderColor: '#ff003c', color: '#ff003c' }}
              >
                DELETE SELECTED
              </Button>
            </>
          )}
        </Box>
      </Box>

      <Card sx={{ bgcolor: isLight ? tokens.surface.secondary : 'rgba(13, 12, 20, 0.95)', border: `1px solid ${tokens.accent.primary}15`, borderRadius: '12px', position: 'relative', overflow: 'hidden' }}>
        <Box sx={{ p: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: `1px solid ${tokens.accent.primary}15` }}>
          <TextField
            placeholder="FILTER SCAN RECORDS..."
            size="small"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            sx={{
              width: 350,
              '& .MuiOutlinedInput-root': {
                color: 'text.primary',
                fontFamily: 'Orbitron',
                fontSize: '0.75rem',
                bgcolor: 'rgba(0, 243, 255, 0.03)',
                '& fieldset': { borderColor: `${tokens.accent.primary}33` },
                '&:hover fieldset': { borderColor: tokens.accent.primary },
                '&.Mui-focused fieldset': { borderColor: tokens.accent.primary },
              }
            }}
            slotProps={{
              input: {
                startAdornment: (
                  <InputAdornment position="start">
                    <Search size={16} style={{ color: tokens.accent.primary }} />
                  </InputAdornment>
                ),
              }
            }}
          />
        </Box>
        <TableContainer>
          <Table>
            <TableHead sx={{ bgcolor: isLight ? 'rgba(0,0,0,0.02)' : 'rgba(0, 243, 255, 0.03)', borderBottom: `1px solid ${theme.palette.divider}` }}>
              <TableRow>
                <TableCell padding="checkbox" sx={{ borderBottom: `1px solid ${tokens.accent.primary}15` }}>
                  <Checkbox
                    indeterminate={selected.length > 0 && selected.length < (scans?.length || 0)}
                    checked={selected.length > 0 && selected.length === (scans?.length || 0)}
                    onChange={handleSelectAllClick}
                    sx={{ color: isLight ? 'rgba(0,0,0,0.2)' : 'rgba(255,255,255,0.2)', '&.Mui-checked': { color: tokens.accent.primary } }}
                  />
                </TableCell>
                <TableCell sx={{ color: tokens.accent.primary, fontWeight: 800, fontFamily: 'Orbitron', fontSize: '0.7rem', borderBottom: `1px solid ${tokens.accent.primary}15` }}>DOMAIN / TARGET</TableCell>
                <TableCell sx={{ color: tokens.accent.primary, fontWeight: 800, fontFamily: 'Orbitron', fontSize: '0.7rem', borderBottom: `1px solid ${tokens.accent.primary}15` }}>SUMMARY</TableCell>
                <TableCell sx={{ color: tokens.accent.primary, fontWeight: 800, fontFamily: 'Orbitron', fontSize: '0.7rem', borderBottom: `1px solid ${tokens.accent.primary}15` }}>ENGINE</TableCell>
                <TableCell sx={{ color: tokens.accent.primary, fontWeight: 800, fontFamily: 'Orbitron', fontSize: '0.7rem', borderBottom: `1px solid ${tokens.accent.primary}15` }}>STATUS</TableCell>
                <TableCell sx={{ color: tokens.accent.primary, fontWeight: 800, fontFamily: 'Orbitron', fontSize: '0.7rem', borderBottom: `1px solid ${tokens.accent.primary}15` }}>PROGRESS</TableCell>
                <TableCell sx={{ color: tokens.accent.primary, fontWeight: 800, fontFamily: 'Orbitron', fontSize: '0.7rem', borderBottom: `1px solid ${tokens.accent.primary}15` }}>TIMELINE</TableCell>
                <TableCell sx={{ color: tokens.accent.primary, fontWeight: 800, fontFamily: 'Orbitron', fontSize: '0.7rem', borderBottom: `1px solid ${tokens.accent.primary}15`, textAlign: 'left', width: 140 }}>ACTION</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {paginatedScans.map((scan) => {
                const isItemSelected = isSelected(scan.id!);
                const displayProgress = (scan.scan_status === 2 || scan.scan_status === 0 || scan.scan_status === 3) ? 100 : Number(scan.current_progress || 0);
                return (
                  <TableRow
                    key={scan.id!}
                    hover
                    onClick={() => handleClick(scan.id!)}
                    role="checkbox"
                    aria-checked={isItemSelected}
                    selected={isItemSelected}
                    sx={{
                      '&:hover': { bgcolor: 'rgba(0, 243, 255, 0.02) !important' },
                      '&.Mui-selected': { bgcolor: `${tokens.accent.primary}0D !important` },
                      transition: 'all 0.2s',
                      cursor: 'pointer'
                    }}
                  >
                    <TableCell padding="checkbox" sx={{ borderBottom: 1, borderColor: 'divider' }}>
                      <Checkbox
                        checked={isItemSelected}
                        sx={{ color: 'rgba(255,255,255,0.2)', '&.Mui-checked': { color: tokens.accent.primary } }}
                      />
                    </TableCell>
                    <TableCell
                      sx={{ borderBottom: 1, borderColor: 'divider', cursor: 'pointer' }}
                      onClick={(e) => {
                        e.stopPropagation();
                        navigate({ to: `/${projectSlug}/scan/detail/${scan.id}` as any });
                      }}
                    >
                      <Typography
                        variant="body2"
                        sx={{
                          fontWeight: 800,
                          color: 'text.primary',
                          fontFamily: 'Orbitron',
                          fontSize: '0.8rem',
                          display: 'inline-block',
                          cursor: 'pointer',
                          '&:hover': {
                            color: tokens.accent.primary,
                            textDecoration: 'underline'
                          }
                        }}
                      >
                        {scan.domain?.name}
                      </Typography>
                      {scan.cfg_starting_point_path && (
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mt: 0.5 }}>
                          <Terminal size={10} style={{ color: theme.palette.text.disabled }} />
                          <Typography variant="caption" sx={{ color: 'text.secondary', fontSize: '0.6rem' }}>{scan.cfg_starting_point_path}</Typography>
                        </Box>
                      )}
                    </TableCell>
                    <TableCell sx={{ borderBottom: 1, borderColor: 'divider' }}>
                      <Box sx={{ display: 'flex', gap: 1 }}>
                        <Tooltip title="Subdomains Found">
                          <Box sx={{ bgcolor: `${tokens.accent.primary}15`, color: tokens.accent.primary, px: 1, py: 0.5, borderRadius: '2px', display: 'flex', alignItems: 'center', gap: 0.5 }}>
                            <Globe size={12} />
                            <Typography variant="caption" sx={{ fontWeight: 900, fontFamily: 'Orbitron' }}>{scan.subdomain_count || 0}</Typography>
                          </Box>
                        </Tooltip>
                        <Tooltip title="Endpoints Discovered">
                          <Box sx={{ bgcolor: 'rgba(255, 171, 0, 0.1)', color: '#ffab00', px: 1, py: 0.5, borderRadius: '2px', display: 'flex', alignItems: 'center', gap: 0.5 }}>
                            <Layers size={12} />
                            <Typography variant="caption" sx={{ fontWeight: 900, fontFamily: 'Orbitron' }}>{scan.endpoint_count || 0}</Typography>
                          </Box>
                        </Tooltip>
                        <Tooltip title="Vulnerabilities Detected">
                          <Box sx={{ bgcolor: 'rgba(255, 0, 60, 0.1)', color: '#ff003c', px: 1, py: 0.5, borderRadius: '2px', display: 'flex', alignItems: 'center', gap: 0.5 }}>
                            <Bug size={12} />
                            <Typography variant="caption" sx={{ fontWeight: 900, fontFamily: 'Orbitron' }}>{scan.vulnerability_count || 0}</Typography>
                          </Box>
                        </Tooltip>
                      </Box>
                    </TableCell>
                    <TableCell sx={{ borderBottom: 1, borderColor: 'divider' }}>
                      <Chip
                        label={scan.scan_type?.engine_name || 'Standard'}
                        size="small"
                        sx={{ bgcolor: 'action.hover', color: 'text.secondary', border: `1px solid ${theme.palette.divider}`, fontSize: '0.6rem', fontWeight: 800, fontFamily: 'Orbitron' }}
                      />
                    </TableCell>
                    <TableCell sx={{ borderBottom: 1, borderColor: 'divider' }}>
                      {getStatusChip(scan)}
                    </TableCell>
                    <TableCell sx={{ borderBottom: 1, borderColor: 'divider', minWidth: 160 }}>
                      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <Typography variant="caption" sx={{ fontSize: '0.55rem', color: 'text.secondary', fontFamily: 'Orbitron', fontWeight: 700 }}>
                            {scan.scan_status === 2 ? 'ALL TIERS COMPLETE' : `TIER ${scan.current_tier || 0}/${scan.total_tiers || 0}`}
                          </Typography>
                          <Typography variant="caption" sx={{ fontWeight: 900, color: 'text.primary', fontSize: '0.6rem', fontFamily: 'Orbitron' }}>
                            {Math.round(Number(displayProgress))}%
                          </Typography>
                        </Box>
                        <LinearProgress
                          variant="determinate"
                          value={displayProgress}
                          sx={{
                            width: '100%',
                            height: 4,
                            borderRadius: 0,
                            bgcolor: 'action.hover',
                            '& .MuiLinearProgress-bar': {
                              bgcolor: (scan.scan_status === 0 || scan.scan_status === 3) ? '#ff003c' : scan.scan_status === 5 ? '#ffab00' : tokens.accent.primary,
                              boxShadow: `0 0 10px ${(scan.scan_status === 0 || scan.scan_status === 3) ? 'rgba(255, 0, 60, 0.5)' : scan.scan_status === 5 ? 'rgba(255, 171, 0, 0.5)' : `${tokens.accent.primary}80`}`,
                              ...((scan.scan_status === 1 || scan.scan_status === -1) && {
                                background: `linear-gradient(90deg, #00f3ff 0%, #00a8ff 50%, ${tokens.accent.primary} 100%)`,
                                backgroundSize: '200% 100%',
                                animation: 'progress-flow 2s linear infinite'
                              })
                            }
                          }}
                        />

                        {(scan.scan_status === 1 || scan.scan_status === 5) && scan.current_tier && scan.current_tier > 0 ? (
                          <Box sx={{ mt: 0.5, display: 'flex', flexDirection: 'column', gap: 0.5 }}>
                            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                              <Typography variant="caption" sx={{ fontSize: '0.5rem', color: `${tokens.accent.primary}99`, fontFamily: 'Orbitron', fontWeight: 600 }}>
                                TIER TASK PROGRESS
                              </Typography>
                              <Typography variant="caption" sx={{ color: `${tokens.accent.primary}CC`, fontSize: '0.55rem', fontFamily: 'Orbitron', fontWeight: 800 }}>
                                {Math.round(scan.current_tier_progress || 0)}%
                              </Typography>
                            </Box>
                            <LinearProgress
                              variant="determinate"
                              value={scan.current_tier_progress || 0}
                              sx={{
                                width: '100%',
                                height: 2,
                                borderRadius: 0,
                                bgcolor: 'action.hover',
                                '& .MuiLinearProgress-bar': {
                                  bgcolor: scan.scan_status === 5 ? 'rgba(255, 171, 0, 0.6)' : '#d500f9',
                                  boxShadow: `0 0 5px ${scan.scan_status === 5 ? 'rgba(255, 171, 0, 0.3)' : 'rgba(213, 0, 249, 0.3)'}`,
                                }
                              }}
                            />
                          </Box>
                        ) : null}
                      </Box>
                    </TableCell>
                    <TableCell sx={{ borderBottom: 1, borderColor: 'divider' }}>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Clock size={12} style={{ color: `${tokens.accent.primary}80` }} />
                        <Typography variant="caption" sx={{ color: 'text.secondary', fontWeight: 600, fontSize: '0.65rem' }}>
                          Time: {scan.elapsed_time || '0s'}
                        </Typography>
                      </Box>
                      <Typography variant="caption" sx={{ display: 'block', color: 'text.disabled', fontSize: '0.55rem', mt: 0.5 }}>
                        ELAPSED: {scan.elapsed_time || '0s'}
                      </Typography>
                    </TableCell>
                    <TableCell sx={{ borderBottom: 1, borderColor: 'divider', textAlign: 'left' }}>
                      <Box sx={{ display: 'flex', justifyContent: 'center', gap: 1 }}>
                        <Button
                          variant="contained"
                          size="small"
                          component={RouterLink}
                          to={`/${projectSlug}/scan/detail/${scan.id}`}
                          sx={{
                            bgcolor: `${tokens.accent.primary}15`,
                            color: tokens.accent.primary,
                            border: `1px solid ${tokens.accent.primary}4D`,
                            fontFamily: 'Orbitron',
                            fontSize: '0.6rem',
                            fontWeight: 900,
                            '&:hover': { bgcolor: `${tokens.accent.primary}33` }
                          }}
                        >
                          RESULTS
                        </Button>
                        <IconButton
                          size="small"
                          onClick={() => {
                            const match = domains?.find(d => d.id === scan.domain?.id);
                            if (!match) return;
                            setStartScanTargets({
                              ids: [match.id!],
                              names: [match.name!],
                            });
                          }}
                          sx={{ color: 'rgba(112, 206, 35, 0.63)', '&:hover': { color: tokens.accent.primary, bgcolor: `${tokens.accent.primary}15` } }}
                        >
                          <RefreshCw size={16} />
                        </IconButton>
                        <IconButton
                          size="small"
                          onClick={(e) => {
                            e.stopPropagation();
                            handleMenuOpen(e, scan.id!, scan.domain?.name || 'N/A');
                          }}
                          sx={{ color: 'text.disabled', '&:hover': { color: tokens.accent.primary, bgcolor: `${tokens.accent.primary}15` } }}
                        >
                          <MoreVertical size={16} />
                        </IconButton>
                      </Box>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </TableContainer>
        <TablePagination
          component="div"
          count={filteredScans.length}
          rowsPerPage={rowsPerPage}
          page={page}
          onPageChange={(_, newPage) => setPage(newPage)}
          onRowsPerPageChange={(e) => {
            setRowsPerPage(parseInt(e.target.value, 10));
            setPage(0);
          }}
          sx={{
            color: 'text.secondary',
            borderTop: `1px solid ${tokens.accent.primary}15`,
            '& .MuiTablePagination-selectIcon': { color: 'text.secondary' },
            '& .MuiTablePagination-actions': { color: tokens.accent.primary }
          }}
        />
      </Card>

      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleMenuClose}
        slotProps={{
          paper: {
            sx: {
              bgcolor: 'background.default',
              border: `1px solid ${tokens.accent.primary}33`,
              borderRadius: 0,
              boxShadow: '0 10px 30px rgba(0,0,0,0.5)',
              minWidth: 200,
              '& .MuiMenuItem-root': {
                fontFamily: 'Orbitron',
                fontSize: '0.7rem',
                fontWeight: 700,
                color: 'text.primary',
                gap: 1.5,
                py: 1.2,
                '&:hover': { bgcolor: `${tokens.accent.primary}0D`, color: tokens.accent.primary },
                '& svg': { color: `${tokens.accent.primary}80` }
              }
            }
          }
        }}
      >
        <MenuItem onClick={handleMenuClose}>
          <Settings size={14} /> SHOW CONFIGS
        </MenuItem>
        <MenuItem onClick={() => {
          navigate({ to: `/${projectSlug}/attack_surface/${activeScanId}` });
          handleMenuClose();
        }}>
          <Share2 size={14} /> ATTACK SURFACE
        </MenuItem>
        {activeScanId && scans?.find((s) => s.id === activeScanId)?.scan_status === 1 && (
          <MenuItem onClick={() => {
            if (activeScanId) {
              pauseScanMutation.mutate({ scan_ids: [activeScanId] });
              handleMenuClose();
            }
          }}>
            <Pause size={14} /> PAUSE SCAN
          </MenuItem>
        )}
        {activeScanId && scans?.find((s) => s.id === activeScanId)?.scan_status === 5 && (
          <MenuItem onClick={() => {
            if (activeScanId) {
              unpauseScanMutation.mutate({ scan_ids: [activeScanId] });
              handleMenuClose();
            }
          }}>
            <Play size={14} /> UNPAUSE SCAN
          </MenuItem>
        )}
        <MenuItem onClick={() => {
          if (activeScanId) {
            stopScanMutation.mutate(activeScanId);
            handleMenuClose();
          }
        }}>
          <StopCircle size={14} /> STOP SCAN
        </MenuItem>
        {activeScanId && (scans?.find((s) => s.id === activeScanId)?.scan_status === 0 || scans?.find((s) => s.id === activeScanId)?.scan_status === 3) && (
          <MenuItem onClick={() => {
            if (activeScanId) {
              resumeScanMutation.mutate(activeScanId);
              handleMenuClose();
            }
          }}>
            <Play size={14} /> RESUME SCAN
          </MenuItem>
        )}
        <MenuItem onClick={() => {
          if (activeScanId) {
            setConfirmConfig({
              title: 'DELETE SCAN RECORD',
              message: 'Are you sure you want to delete this scan? This action is irreversible.',
              type: 'danger',
              onConfirm: () => {
                deleteScanMutation.mutate(activeScanId);
                handleMenuClose();
              }
            });
            setConfirmOpen(true);
          }
        }} sx={{ color: '#ff003c !important', '& svg': { color: '#ff003c !important' } }}>
          <Trash2 size={14} /> DELETE SCAN
        </MenuItem>
        <MenuItem onClick={() => {
          if (activeScanId) {
            setReportScanId(activeScanId);
            setReportModalOpen(true);
          }
          handleMenuClose();
        }}>
          <FileText size={14} /> SCAN REPORT
        </MenuItem>
      </Menu>

      {reportScanId && (
        <ScanReportModal
          open={reportModalOpen}
          onClose={() => {
            setReportModalOpen(false);
            setReportScanId(null);
          }}
          scanId={reportScanId}
        />
      )}

      {startScanTargets && (
        <StartScanModal
          open={!!startScanTargets}
          onClose={() => setStartScanTargets(null)}
          domainIds={startScanTargets.ids}
          domainNames={startScanTargets.names}
          projectSlug={projectSlug}
        />
      )}

      {/* Confirmation Dialog */}
      <ConfirmDialog
        open={confirmOpen}
        onClose={() => setConfirmOpen(false)}
        onConfirm={() => {
          confirmConfig.onConfirm();
          setConfirmOpen(false);
        }}
        title={confirmConfig.title}
        message={confirmConfig.message}
        type={confirmConfig.type}
      />

      <Snackbar
        open={snackbar.open}
        autoHideDuration={5000}
        onClose={handleCloseSnackbar}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        <Alert
          onClose={handleCloseSnackbar}
          severity={snackbar.severity}
          variant="filled"
          sx={{
            fontFamily: 'Orbitron',
            fontSize: '0.8rem',
            fontWeight: 700,
            bgcolor: snackbar.severity === 'success' ? 'rgba(0, 255, 98, 0.9)' : 
              snackbar.severity === 'error' ? 'rgba(255, 0, 85, 0.9)' : `${tokens.accent.primary}80`,
            color: '#fff',
            border: `1px solid ${theme.palette.divider}`,
            backdropFilter: 'blur(10px)',
            borderRadius: 1
          }}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
};
