import React, { useState } from 'react';
import ReactMarkdown from 'react-markdown';
import {
  Box,
  Typography,
  Grid,
  InputBase,
  Button,
  IconButton,
  Tooltip,
  CircularProgress,
  Pagination,
  Stack,
  Menu,
  MenuItem,
  ListItemIcon,
  ListItemText,
  Chip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  FormControl,
  FormControlLabel,
  InputLabel,
  Select,
  Checkbox,
  TextField,
  List,
  ListItem,
  ListItemButton,
  FormGroup,
  Divider,
  Alert,
  Snackbar,
  Modal,
  Fade,
  Backdrop
} from '@mui/material';
import {
  Search,
  Zap,
  Eye,
  FilePlus,
  MoreHorizontal,
  Download,
  ChevronRight,
  ExternalLink,
  AlertTriangle,
  Trash2,
  Copy,
  FileText,
  Shield,
  Network,
  X,
  Folder,
  Crosshair,
} from 'lucide-react';
import { getCsrfToken } from '../../../api/axiosConfig';


import {
  useSubdomains,
  useDeleteSubdomain,
  useToggleSubdomainImportant,
  useInitiateSubscan,
  useGPTAttackSurface,
  useAddManualSubdomain,
} from '../../subdomains/api';
import type { SubdomainFilters } from '../../subdomains/api';
import { useEngines } from '../../engines/api';
import { usePlugins } from '../../plugins/api/pluginsApi';
import { useCreateTodo } from '../../todos/api';
import { TacticalPanel } from '../../../components/TacticalPanel';
import { ConfirmDialog } from '../../../components/ConfirmDialog';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import { getDialogPaperSx, getFieldSx, getMenuPaperSx } from '../../../theme/semanticColors';

interface SubdomainsTabProps {
  projectSlug: string;
  scanId?: number;
  targetId?: number;
  onTabChange?: (index: number) => void;
  initialAlive?: boolean;
}

const TASK_TIER_ORDER: string[] = [
  // Tier 1 — Discovery
  'subdomain_discovery', 'amass_intel_discovery', 'firewall_vpn_scan',
  'dns_security', 'osint', 'spiderfoot_scan', 'baddns',
  // Tier 2 — HTTP Crawl & Port Scan
  'http_crawl', 'port_scan', 'vigolium_discovery',
  // Tier 3 — Fetching & Screenshot
  'fetch_url', 'screenshot',
  // Tier 4 — Fuzzing
  'dir_file_fuzz',
  // Tier 5 — Analysis
  'web_api_discovery', 'waf_detection', 'secret_scanning', 'vigolium_analysis',
  // Tier 6 — Security Assessment
  'vulnerability_scan', 'waf_bypass', 'brute_force_scan', 'vigolium_scan',
];

export const SubdomainsTab: React.FC<SubdomainsTabProps> = ({ projectSlug, scanId, targetId, onTabChange, initialAlive }) => {
  const { tokens, isLight, theme } = useThemeTokens();
  const warningAccent = tokens.accent.warning;

  const [page, setPage] = useState(1);
  const [searchQuery, setSearchQuery] = useState('');
  const [activeSearch, setActiveSearch] = useState('');
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [selectedAssets, setSelectedAssets] = useState<number[]>([]);
  const [hasIpFilter, setHasIpFilter] = useState(false);
  const [isAliveFilter, setIsAliveFilter] = useState(initialAlive || false);
  const [sortCol, setSortCol] = useState<string | undefined>('1');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc');

  const handleSort = (colNum: string) => {
    if (sortCol === colNum) {
      setSortDir(prev => prev === 'asc' ? 'desc' : 'asc');
    } else {
      setSortCol(colNum);
      setSortDir('asc');
    }
    setPage(1);
  };

  const filters: SubdomainFilters = {
    has_ip: hasIpFilter ? 'true' : undefined,
    http_status: isAliveFilter ? '200' : undefined
  };

  const { data, isLoading } = useSubdomains(projectSlug, page, activeSearch, scanId, false, targetId, filters, 10, sortCol, sortDir);
  const [isReady, setIsReady] = useState(false);
  
  // Modals state
  const [subscanModalOpen, setSubscanModalOpen] = useState(false);
  const [attackSurfaceModalOpen, setAttackSurfaceModalOpen] = useState(false);
  const [todoModalOpen, setTodoModalOpen] = useState(false);
  const [addSubdomainModalOpen, setAddSubdomainModalOpen] = useState(false);
  const [manualSubdomainName, setManualSubdomainName] = useState('');

  const addSubdomainMutation = useAddManualSubdomain(projectSlug);
  
  // Selected subdomain for single actions
  const [targetSubdomain, setTargetSubdomain] = useState<any>(null);
  const [lightboxSrc, setLightboxSrc] = useState<string | null>(null);
  const [lightboxLabel, setLightboxLabel] = useState<string>('');
  
  const openLightbox = (src: string, label: string = '') => {
    setLightboxSrc(`/media/${src}`);
    setLightboxLabel(label);
  };
  const closeLightbox = () => {
    setLightboxSrc(null);
    setLightboxLabel('');
  };
  
  // Confirmation state
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [confirmConfig, setConfirmConfig] = useState<{
    title: string;
    message: string;
    onConfirm: () => void;
    type?: 'danger' | 'info' | 'warning';
  }>({
    title: '',
    message: '',
    onConfirm: () => {},
  });
  
  // Subscan state
  const [selectedEngineId, setSelectedEngineId] = useState<number | null>(null);
  const [selectedTasks, setSelectedTasks] = useState<string[]>([]);
  const [selectedPlugins, setSelectedPlugins] = useState<string[]>([]);
  
  // TODO state
  const [todoTitle, setTodoTitle] = useState('');
  const [todoDescription, setTodoDescription] = useState('');
  const [snackbar, setSnackbar] = useState<{
    open: boolean;
    message: string;
    severity: 'success' | 'error' | 'info' | 'warning';
  }>({
    open: false,
    message: '',
    severity: 'success',
  });

  // AD Assessment state
  const [adLaunchMsg, setAdLaunchMsg] = useState<{ text: string; severity: 'success' | 'error' } | null>(null);

  const handleCloseSnackbar = () => {
    setSnackbar({ ...snackbar, open: false });
  };

  const showNotification = (message: string, severity: 'success' | 'error' | 'info' | 'warning' = 'success') => {
    setSnackbar({
      open: true,
      message,
      severity,
    });
  };

  // Mutations
  const deleteMutation = useDeleteSubdomain(projectSlug);
  const importantMutation = useToggleSubdomainImportant(projectSlug);
  const subscanMutation = useInitiateSubscan();
  const probeMutation = useInitiateSubscan();
  const [probeTarget, setProbeTarget] = useState<any>(null);
  const attackSurfaceMutation = useGPTAttackSurface();
  const createTodoMutation = useCreateTodo();
  const { data: enginesData } = useEngines();
  const { data: allPlugins } = usePlugins();
  const enabledPlugins = (allPlugins ?? []).filter(p => p.is_enabled);

  React.useEffect(() => {
    if (!isLoading && data) {
      const timer = setTimeout(() => setIsReady(true), 100);
      return () => clearTimeout(timer);
    } else {
      setIsReady(false);
    }
  }, [isLoading, data]);

  const toggleSelectAll = () => {
    if (selectedAssets.length === data?.results.length) {
      setSelectedAssets([]);
    } else {
      setSelectedAssets(data?.results.map(s => s.id) || []);
    }
  };

  const toggleSelectAsset = (id: number) => {
    setSelectedAssets(prev =>
      prev.includes(id) ? prev.filter(i => i !== id) : [...prev, id]
    );
  };

  const handleSearch = () => {
    setPage(1);
    setActiveSearch(searchQuery);
  };

  const handleActionClick = (event: React.MouseEvent<HTMLButtonElement>, sub: any) => {
    setAnchorEl(event.currentTarget);
    setSelectedId(sub.id);
    setTargetSubdomain(sub);
  };

  const handleActionClose = () => {
    setAnchorEl(null);
    setSelectedId(null);
    // We keep targetSubdomain until a new one is selected or modal closes
  };

  const handleDelete = async (id: number) => {
    setConfirmConfig({
      title: 'DELETE ASSET',
      message: 'Are you sure you want to delete this subdomain? This action cannot be undone.',
      type: 'danger',
      onConfirm: async () => {
        try {
          await deleteMutation.mutateAsync([id]);
          showNotification('Subdomain deleted successfully');
        } catch (error: any) {
          showNotification(error.message || 'Failed to delete subdomain', 'error');
        }
        handleActionClose();
      }
    });
    setConfirmOpen(true);
  };

  const handleBulkDelete = async () => {
    if (selectedAssets.length === 0) return;
    setConfirmConfig({
      title: 'BULK DELETE ASSETS',
      message: `Are you sure you want to delete ${selectedAssets.length} subdomains? This operation is permanent.`,
      type: 'danger',
      onConfirm: async () => {
        try {
          await deleteMutation.mutateAsync(selectedAssets);
          showNotification(`${selectedAssets.length} subdomains deleted`);
          setSelectedAssets([]);
        } catch (error: any) {
          showNotification(error.message || 'Failed to delete subdomains', 'error');
        }
      }
    });
    setConfirmOpen(true);
  };

  const handleToggleImportant = async (id: number) => {
    try {
      await importantMutation.mutateAsync(id);
      showNotification('Status updated');
    } catch (error: any) {
      showNotification(error.message || 'Failed to update status', 'error');
    }
    handleActionClose();
  };

  const handleLaunchADAssessment = async () => {
    handleActionClose();
    if (!selectedId) return;
    try {
      const res = await fetch('/api/action/ad-assessment/from-subdomain/', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() ?? '' },
        body: JSON.stringify({ subdomain_id: selectedId }),
      });
      const json = await res.json();
      if (!res.ok) throw new Error(json.error ?? `HTTP ${res.status}`);
      setAdLaunchMsg({
        text: `AD Assessment created for ${json.target_domain}. Open the AD Intelligence plugin to start it.`,
        severity: 'success',
      });
    } catch (err: unknown) {
      setAdLaunchMsg({
        text: (err instanceof Error ? err.message : 'Failed to create AD assessment'),
        severity: 'error',
      });
    }
  };

  const handleInitiateSubscan = async () => {
    if (!selectedEngineId) {
      showNotification('Please select an engine', 'error');
      return;
    }
    if (selectedTasks.length === 0) {
      showNotification('Please select at least one task', 'error');
      return;
    }

    const subdomain_ids = selectedAssets.length > 0 
      ? selectedAssets 
      : targetSubdomain ? [targetSubdomain.id] : [];

    if (subdomain_ids.length === 0) {
      showNotification('No subdomains selected', 'error');
      return;
    }

    try {
      await subscanMutation.mutateAsync({
        engine_id: selectedEngineId,
        tasks: selectedTasks,
        subdomain_ids,
        selected_plugins: selectedPlugins,
      });
      showNotification('Subscan initiated successfully');
      setSubscanModalOpen(false);
      setSelectedEngineId(null);
      setSelectedTasks([]);
      setSelectedPlugins([]);
    } catch (error: any) {
      showNotification(error.message || 'Failed to initiate subscan', 'error');
    }
  };

  const handleSendToAWVS = async () => {
    if (selectedAssets.length === 0) return;
    try {
      await subscanMutation.mutateAsync({
        engine_id: null,
        tasks: ['run_acunetix'],
        subdomain_ids: selectedAssets
      });
      showNotification('Acunetix scan initiated successfully');
      setSelectedAssets([]);
    } catch (error: any) {
      showNotification(error.message || 'Failed to initiate Acunetix scan', 'error');
    }
  };

  const handleProbeConfirm = async () => {
    if (!probeTarget) return;
    const id = probeTarget.id;
    const name = probeTarget.name;
    setProbeTarget(null);
    try {
      await probeMutation.mutateAsync({
        engine_id: null,
        tasks: ['http_crawl', 'screenshot'],
        subdomain_ids: [id],
      });
      showNotification(`Probe initiated for ${name}`);
    } catch (error: any) {
      showNotification(error.message || 'Failed to initiate probe', 'error');
    }
  };

  const selectedEngine = enginesData?.find(e => e.id === selectedEngineId);

  const handleAddTodo = async () => {
    if (!todoDescription) {
      showNotification('Please enter a description', 'error');
      return;
    }
    try {
      await createTodoMutation.mutateAsync({
        title: todoTitle || `TODO: ${targetSubdomain.name}`,
        description: todoDescription,
        subdomain_id: targetSubdomain.id,
        project: projectSlug || ""
      });
      setTodoModalOpen(false);
      setTodoDescription('');
      showNotification('TODO note added successfully');
    } catch (error: any) {
      showNotification(error.message || 'Failed to add TODO note', 'error');
    }
  };

  const handleShowAttackSurface = async (sub: any) => {
    setTargetSubdomain(sub);
    setAttackSurfaceModalOpen(true);
    try {
      await attackSurfaceMutation.mutateAsync(sub.id);
    } catch (error: any) {
      showNotification(error.message || 'Failed to fetch attack surface', 'error');
    }
  };

  const getStatusColor = (status: number) => {
    if (status >= 200 && status < 300) return isLight ? tokens.accent.success : '#00ffaa';
    if (status >= 300 && status < 400) return tokens.accent.primary;
    if (status >= 400 && status < 500) return isLight ? tokens.accent.warning : '#ffae00';
    if (status >= 500) return isLight ? tokens.accent.error : '#ff003c';
    return isLight ? tokens.text.secondary : 'rgba(255,255,255,0.4)';
  };

  return (
    <Box sx={{ width: '100%' }}>
      {/* Tactical Header */}
      <Box sx={{ display: 'flex', alignItems: 'center', justifycontent: 'space-between', mb: 4, mt: 2 }}>
        <Box>
          <Typography variant="h5" sx={{
            fontWeight: 900,
            fontFamily: 'Orbitron',
            letterSpacing: 3,
            color: 'text.primary',
            textTransform: 'uppercase'
          }}>
            Subdomain Inventory
          </Typography>
          <Typography sx={{ fontSize: '12px', color: 'text.secondary', mt: 0.5, letterSpacing: 1 }}>
            V3.0 SCAN ASSETS RECON ACTIVE
          </Typography>
        </Box>

        {/* Manual Subdomain Addition Button */}
        {(targetId || scanId) && (
          <Button
            variant="contained"
            startIcon={<FilePlus size={16} />}
            onClick={() => setAddSubdomainModalOpen(true)}
            sx={{
              bgcolor: `${tokens.accent.primary}15`,
              color: tokens.accent.primary,
              border: `1px solid ${isLight ? 'rgba(0,0,0,0.1)' : `${tokens.accent.primary}33`}`,
              fontSize: '11px',
              fontWeight: 800,
              letterSpacing: 1,
              fontFamily: 'Orbitron',
              '&:hover': {
                bgcolor: `${tokens.accent.primary}33`,
                borderColor: tokens.accent.primary,
              }
            }}
          >
            ADD SUBDOMAIN
          </Button>
        )}
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
          placeholder="Filter Subdomains (e.g. name=google.com, http_status=200)"
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
            bgcolor: `${tokens.accent.primary}15`,
            color: tokens.accent.primary,
            px: 4,
            borderRadius: 0,
            fontWeight: 700,
            fontSize: '11px',
            letterSpacing: 1,
            borderLeft: '1px solid',
            borderLeftColor: 'divider',
            '&:hover': { bgcolor: `${tokens.accent.primary}33` }
          }}
        >
          SEARCH
        </Button>
        <Button
          onClick={() => {
            setHasIpFilter(prev => !prev);
            setPage(1);
            setSelectedAssets([]);
          }}
          disabled={isLoading}
          sx={{
            bgcolor: hasIpFilter ? `${tokens.accent.primary}33` : 'transparent',
            color: hasIpFilter ? tokens.accent.primary : 'text.primary',
            opacity: isLoading ? 0.6 : 1,
            px: 3,
            borderRadius: 0,
            fontWeight: 700,
            fontSize: '11px',
            letterSpacing: 1,
            borderLeft: '1px solid',
            borderLeftColor: 'divider',
            '&:hover': { bgcolor: `${tokens.accent.primary}26` }
          }}
        >
          {isLoading ? 'LOADING...' : hasIpFilter ? 'HAS IP [ON]' : 'HAS IP'}
        </Button>
        <Button
          onClick={() => {
            setIsAliveFilter(prev => !prev);
            setPage(1);
            setSelectedAssets([]);
          }}
          disabled={isLoading}
          sx={{
            bgcolor: isAliveFilter ? `${tokens.accent.primary}33` : 'transparent',
            color: isAliveFilter ? tokens.accent.primary : 'text.primary',
            opacity: isLoading ? 0.6 : 1,
            px: 3,
            borderRadius: 0,
            fontWeight: 700,
            fontSize: '11px',
            letterSpacing: 1,
            borderLeft: '1px solid',
            borderLeftColor: 'divider',
            '&:hover': { bgcolor: `${tokens.accent.primary}26` }
          }}
        >
          {isLoading ? 'LOADING...' : isAliveFilter ? 'ALIVE [ON]' : 'ALIVE'}
        </Button>
      </Box>

      {/* Tactical Panel */}
      <TacticalPanel>
        {/* Tactical Table Header (Legacy Parity) */}
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
            {selectedAssets.length > 0 && (
              <Stack direction="row" spacing={1}>
                <Button 
                  size="small" 
                  variant="contained" 
                  onClick={() => setSubscanModalOpen(true)}
                  sx={{ 
                    bgcolor: `${tokens.accent.primary}15`, 
                    color: tokens.accent.primary, 
                    fontSize: '10px', 
                    fontWeight: 800, 
                    border: `1px solid ${tokens.accent.primary}33`,
                    '&:hover': { bgcolor: `${tokens.accent.primary}33` } 
                  }}
                >
                  SUBSCAN SELECTED ({selectedAssets.length})
                </Button>
                <Button 
                  size="small" 
                  variant="contained" 
                  onClick={handleSendToAWVS}
                  disabled={subscanMutation.isPending}
                  sx={{ 
                    bgcolor: isLight ? 'rgba(217, 119, 6, 0.08)' : 'rgba(255, 170, 0, 0.1)', 
                    color: tokens.accent.warning, 
                    fontSize: '10px', 
                    fontWeight: 800, 
                    border: '1px solid',
                    borderColor: 'warning.main',
                    '&:hover': { bgcolor: isLight ? 'rgba(217, 119, 6, 0.16)' : 'rgba(255, 170, 0, 0.2)' } 
                  }}
                >
                  {subscanMutation.isPending ? 'SENDING...' : `SEND TO AWVS (${selectedAssets.length})`}
                </Button>
                <Button 
                  size="small" 
                  variant="contained" 
                  onClick={handleBulkDelete}
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
                  DELETE SELECTED ({selectedAssets.length})
                </Button>
              </Stack>
            )}
            <IconButton size="small" sx={{ color: tokens.accent.primary, bgcolor: `${tokens.accent.primary}0D`, border: `1px solid ${tokens.accent.primary}15`, borderRadius: 1 }}>
              <Download size={14} />
            </IconButton>
          </Box>
        </Box>

        {/* Responsive Subdomains Table */}
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
                borderBottom: '1px solid',
                borderColor: 'divider',
                backgroundColor: isLight ? 'rgba(0,0,0,0.02)' : 'rgba(255,255,255,0.02)'
              }}>
                <th style={{ width: '40px', padding: '12px 16px', textAlign: 'center' }}>
                  <input
                    type="checkbox"
                    checked={selectedAssets.length === data?.results.length && data?.results.length > 0}
                    onChange={toggleSelectAll}
                    style={{ width: '14px', height: '14px', accentColor: tokens.accent.primary, cursor: 'pointer', opacity: 0.6 }}
                  />
                </th>
                <th
                  onClick={() => handleSort('1')}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      handleSort('1');
                    }
                  }}
                  role="button"
                  tabIndex={0}
                  aria-label={`Sort by subdomain${sortCol === '1' ? (sortDir === 'asc' ? ', ascending' : ', descending') : ''}`}
                  style={{
                    padding: '12px 16px',
                    color: tokens.accent.primary,
                    fontSize: '10px',
                    fontWeight: 900,
                    letterSpacing: 1.5,
                    fontFamily: 'Orbitron',
                    cursor: 'pointer',
                    userSelect: 'none'
                  }}
                >
                  SUBDOMAIN {sortCol === '1' && (sortDir === 'asc' ? '▲' : '▼')}
                </th>
                <Box
                  component="th"
                  onClick={() => handleSort('4')}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      handleSort('4');
                    }
                  }}
                  role="button"
                  tabIndex={0}
                  aria-label={`Sort by status${sortCol === '4' ? (sortDir === 'asc' ? ', ascending' : ', descending') : ''}`}
                  sx={{
                    display: { xs: 'none', sm: 'table-cell' },
                    padding: '12px 16px',
                    color: tokens.accent.primary,
                    fontSize: '10px',
                    fontWeight: 900,
                    letterSpacing: 1.5,
                    fontFamily: 'Orbitron',
                    cursor: 'pointer',
                    userSelect: 'none'
                  }}
                >
                  STATUS {sortCol === '4' && (sortDir === 'asc' ? '▲' : '▼')}
                </Box>
                <Box component="th" sx={{ display: { xs: 'none', md: 'table-cell' }, padding: '12px 16px', color: tokens.accent.primary, fontSize: '10px', fontWeight: 900, letterSpacing: 1.5, fontFamily: 'Orbitron' }}>IP</Box>
                <Box component="th" sx={{ display: { xs: 'none', lg: 'table-cell' }, padding: '12px 16px', color: tokens.accent.primary, fontSize: '10px', fontWeight: 900, letterSpacing: 1.5, fontFamily: 'Orbitron' }}>PORTS</Box>
                <Box
                  component="th"
                  onClick={() => handleSort('8')}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      handleSort('8');
                    }
                  }}
                  role="button"
                  tabIndex={0}
                  aria-label={`Sort by content${sortCol === '8' ? (sortDir === 'asc' ? ', ascending' : ', descending') : ''}`}
                  sx={{
                    display: { xs: 'none', xl: 'table-cell' },
                    padding: '12px 16px',
                    color: tokens.accent.primary,
                    fontSize: '10px',
                    fontWeight: 900,
                    letterSpacing: 1.5,
                    fontFamily: 'Orbitron',
                    cursor: 'pointer',
                    userSelect: 'none'
                  }}
                >
                  CONTENT {sortCol === '8' && (sortDir === 'asc' ? '▲' : '▼')}
                </Box>
                <Box
                  component="th"
                  onClick={() => handleSort('10')}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      handleSort('10');
                    }
                  }}
                  role="button"
                  tabIndex={0}
                  aria-label={`Sort by time${sortCol === '10' ? (sortDir === 'asc' ? ', ascending' : ', descending') : ''}`}
                  sx={{
                    display: { xs: 'none', lg: 'table-cell' },
                    padding: '12px 16px',
                    color: tokens.accent.primary,
                    fontSize: '10px',
                    fontWeight: 900,
                    letterSpacing: 1.5,
                    fontFamily: 'Orbitron',
                    cursor: 'pointer',
                    userSelect: 'none'
                  }}
                >
                  TIME {sortCol === '10' && (sortDir === 'asc' ? '▲' : '▼')}
                </Box>
                <Box component="th" sx={{ display: { xs: 'none', md: 'table-cell' }, padding: '12px 16px', color: tokens.accent.primary, fontSize: '10px', fontWeight: 900, letterSpacing: 1.5, fontFamily: 'Orbitron' }}>SCREENSHOT</Box>
                <th style={{ padding: '12px 16px', color: tokens.accent.primary, fontSize: '10px', fontWeight: 900, letterSpacing: 1.5, fontFamily: 'Orbitron', textAlign: 'right' }}>ACTION</th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr>
                  <td colSpan={9} style={{ padding: '80px', textAlign: 'center' }}>
                    <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2 }}>
                      <CircularProgress size={32} sx={{ color: tokens.accent.primary, filter: isLight ? 'none' : `drop-shadow(0 0 8px ${tokens.accent.primary})` }} />
                      <Typography sx={{
                        fontSize: '10px',
                        fontWeight: 900,
                        color: tokens.text.secondary,
                        fontFamily: 'Orbitron',
                        letterSpacing: 2,
                        textTransform: 'uppercase'
                      }}>
                        System Fetching Subdomains...
                      </Typography>
                    </Box>
                  </td>
                </tr>
              ) : data?.results.map((sub) => (
                <tr key={sub.id} style={{
                  borderBottom: '1px solid', borderColor: theme.palette.divider,
                  backgroundColor: selectedAssets.includes(sub.id) 
                    ? (isLight ? 'rgba(14, 165, 233, 0.04)' : 'rgba(0, 243, 255, 0.02)') 
                    : (sub.is_important ? (isLight ? 'rgba(239, 68, 68, 0.04)' : 'rgba(255, 0, 60, 0.03)') : 'transparent'),
                  transition: 'background 0.2s'
                }}>
                  <td style={{ padding: '12px 16px', verticalAlign: 'middle', textAlign: 'center' }}>
                    <input
                      type="checkbox"
                      checked={selectedAssets.includes(sub.id)}
                      onChange={() => toggleSelectAsset(sub.id)}
                      style={{
                        width: '14px',
                        height: '14px',
                        accentColor: tokens.accent.primary,
                        cursor: 'pointer',
                        opacity: 0.6
                      }}
                    />
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }}>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Typography sx={{ fontSize: '13px', fontWeight: 700, color: 'text.primary', letterSpacing: 0.2 }}>{sub.name}</Typography>
                        {sub.is_important && <Shield size={12} color={tokens.accent.warning} style={{ filter: isLight ? 'none' : `drop-shadow(0 0 5px ${tokens.accent.warning})` }} />}
                        <IconButton 
                          size="small" 
                          onClick={() => {
                            navigator.clipboard.writeText(sub.name);
                            showNotification('Copied to clipboard');
                          }}
                          sx={{ p: 0.2, color: 'text.disabled', '&:hover': { color: tokens.accent.primary } }}
                        >
                          <Copy size={12} />
                        </IconButton>
                      </Box>

                      {/* Asset Intelligence Badges (Legacy Feature) */}
                      <Box sx={{ display: 'flex', gap: 1.5, mt: 0.5 }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                          <Tooltip title="Subscans">
                            <Typography sx={{ fontSize: '9px', fontWeight: 800, color: 'text.secondary', display: 'flex', alignItems: 'center', gap: 0.5, cursor: 'help' }}>
                              <Zap size={10} style={{ color: tokens.accent.primary }} /> {sub.subscan_count || 0}
                            </Typography>
                          </Tooltip>
                        </Box>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                          <Tooltip title="Endpoints">
                            <Typography sx={{ fontSize: '9px', fontWeight: 800, color: 'text.secondary', display: 'flex', alignItems: 'center', gap: 0.5, cursor: 'help' }}>
                              <ExternalLink size={10} style={{ color: tokens.accent.secondary }} /> {sub.endpoint_count || 0}
                            </Typography>
                          </Tooltip>
                        </Box>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                          <Tooltip title="Critical Vulnerabilities">
                            <Typography sx={{ fontSize: '9px', fontWeight: 800, color: 'text.secondary', display: 'flex', alignItems: 'center', gap: 0.5, cursor: 'help' }}>
                              <AlertTriangle size={10} style={{ color: tokens.accent.error }} /> {sub.critical_count || 0}
                            </Typography>
                          </Tooltip>
                        </Box>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                          <Tooltip title="Directories Discovered">
                            <Typography sx={{ fontSize: '9px', fontWeight: 800, color: 'text.secondary', display: 'flex', alignItems: 'center', gap: 0.5, cursor: 'help' }}>
                              <Folder size={10} style={{ color: tokens.accent.warning }} /> {sub.directories_count || 0}
                            </Typography>
                          </Tooltip>
                        </Box>

                        {sub.info_count > 0 && (
                          <Chip label={`${sub.info_count} Info`} size="small" sx={{ height: 14, fontSize: '7px', fontWeight: 900, bgcolor: `${tokens.accent.primary}15`, color: tokens.accent.primary, borderRadius: 0.5 }} />
                        )}
                      </Box>
                    </Box>
                  </td>
                  <Box component="td" sx={{ display: { xs: 'none', sm: 'table-cell' }, padding: '12px 16px' }}>
                    <Box sx={{
                      display: 'inline-flex',
                      px: 1.2,
                      py: 0.4,
                      borderRadius: 0.5,
                      bgcolor: `${getStatusColor(sub.http_status)}20`,
                      border: `1px solid ${getStatusColor(sub.http_status)}40`,
                    }}>
                      <Typography sx={{ fontSize: '11px', fontWeight: 900, color: getStatusColor(sub.http_status) }}>
                        {sub.http_status || '404'}
                      </Typography>
                    </Box>
                  </Box>
                  <Box component="td" sx={{ display: { xs: 'none', md: 'table-cell' }, padding: '12px 16px' }}>
                    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }}>
                      {sub.ip_addresses?.map(ip => (
                        <Typography
                          key={`ip-${sub.id}-${ip.id}`}
                          sx={{
                            fontSize: '11px',
                            color: ip.is_cdn ? tokens.accent.warning : 'text.primary',
                            fontFamily: 'monospace',
                            fontWeight: 600
                          }}
                        >
                          {ip.address}
                        </Typography>
                      ))}
                    </Box>
                  </Box>
                  <Box component="td" sx={{ display: { xs: 'none', lg: 'table-cell' }, padding: '12px 16px' }}>
                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                      {sub.ip_addresses?.flatMap(ip => ip.ports.map(port => ({ ...port, ipId: ip.id }))).map(port => (
                        <Box
                          key={`port-${sub.id}-${port.ipId}-${port.id}`}
                          sx={{
                            px: 1,
                            py: 0.2,
                            borderRadius: 0.5,
                            bgcolor: port.is_uncommon ? (isLight ? `${tokens.accent.error}15` : 'rgba(255, 0, 60, 0.1)') : (isLight ? 'action.hover' : 'rgba(255,255,255,0.05)'),
                            border: `1px solid ${port.is_uncommon ? (isLight ? `${tokens.accent.error}4D` : 'rgba(255, 0, 60, 0.2)') : (isLight ? 'rgba(0,0,0,0.08)' : 'rgba(255,255,255,0.1)')}`,
                          }}
                        >
                          <Typography sx={{ fontSize: '9px', fontWeight: 800, color: port.is_uncommon ? tokens.accent.error : (isLight ? 'text.secondary' : 'rgba(255,255,255,0.6)'), fontFamily: 'monospace' }}>
                            {port.number}
                          </Typography>
                        </Box>
                      ))}
                    </Box>
                  </Box>
                  <Box component="td" sx={{ display: { xs: 'none', xl: 'table-cell' }, padding: '12px 16px' }}>
                    <Typography sx={{ fontSize: '11px', color: 'text.secondary', fontFamily: 'monospace' }}>
                      {sub.content_length ? `${(sub.content_length / 1024).toFixed(1)} KB` : '0 KB'}
                    </Typography>
                  </Box>
                  <Box component="td" sx={{ display: { xs: 'none', lg: 'table-cell' }, padding: '12px 16px' }}>
                    <Typography sx={{ fontSize: '11px', color: 'text.secondary', fontFamily: 'monospace' }}>
                      {sub.response_time ? `${(sub.response_time * 1000).toFixed(0)}ms` : '-'}
                    </Typography>
                  </Box>
                  <Box component="td" sx={{ display: { xs: 'none', md: 'table-cell' }, padding: '12px 16px' }}>
                    {(() => {
                      const ssPath = sub.screenshot_path || sub.screenshots?.[0]?.screenshot_path || null;
                      return ssPath ? (
                        <Box
                          onClick={() => openLightbox(ssPath, sub.name)}
                          sx={{
                            width: 60,
                            height: 34,
                            borderRadius: 0.5,
                            overflow: 'hidden',
                            border: '1px solid',
                            borderColor: 'divider',
                            cursor: 'pointer',
                            transition: 'all 0.2s',
                            position: 'relative',
                            '&:hover': {
                              borderColor: tokens.accent.primary,
                              transform: 'scale(1.1)',
                              zIndex: 10,
                              boxShadow: `0 0 15px ${tokens.accent.primary}4D`
                            }
                          }}
                        >
                          <img
                            src={`/media/${ssPath}`}
                            alt="preview"
                            style={{ width: '100%', height: '100%', objectFit: 'cover' }}
                          />
                        </Box>
                      ) : (
                        <Typography sx={{ fontSize: '9px', color: 'text.disabled', fontWeight: 800 }}>NO DATA</Typography>
                      );
                    })()}
                  </Box>
                  <td style={{ padding: '12px 16px', textAlign: 'right' }}>
                    <Box sx={{ display: 'flex', gap: 0.5, justifyContent: 'flex-end' }}>
                      <Tooltip title="Show Attack Surface">
                        <IconButton 
                          size="small" 
                          onClick={() => handleShowAttackSurface(sub)}
                          sx={{ color: tokens.accent.primary, bgcolor: `${tokens.accent.primary}0D`, p: 0.5 }}
                        >
                          <Eye size={14} />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Further Scan Subdomain">
                        <IconButton 
                          size="small" 
                          onClick={() => {
                            setTargetSubdomain(sub);
                            setSubscanModalOpen(true);
                          }}
                          sx={{ color: tokens.accent.success, bgcolor: `${tokens.accent.success}0D`, p: 0.5 }}
                        >
                          <Zap size={14} />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Add Recon TODO/Note">
                        <IconButton
                          size="small"
                          onClick={() => {
                            setTargetSubdomain(sub);
                            setTodoModalOpen(true);
                          }}
                          sx={{ color: tokens.accent.warning, bgcolor: `${tokens.accent.warning}0D`, p: 0.5 }}
                        >
                          <FileText size={14} />
                        </IconButton>
                      </Tooltip>
                      {/* Probe button */}
                      <Tooltip title="Probe Subdomain">
                        <IconButton
                          size="small"
                          onClick={() => setProbeTarget(sub)}
                          disabled={probeMutation.isPending}
                          sx={{ color: tokens.accent.primary, bgcolor: `${tokens.accent.primary}0D`, p: 0.5 }}
                        >
                          <Crosshair size={14} />
                        </IconButton>
                      </Tooltip>
                      <IconButton size="small" onClick={(e) => handleActionClick(e, sub)} sx={{ color: 'text.disabled', p: 0.5 }}>
                        <MoreHorizontal size={14} />
                      </IconButton>
                    </Box>
                  </td>

                </tr>
              ))}
            </tbody>
          </table>
        </Box>

        {/* Tactical Pagination */}
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

      {/* Action Menu */}
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleActionClose}
        slotProps={{
          paper: {
            sx: {
              ...getMenuPaperSx(isLight, theme, tokens),
              border: `1px solid ${isLight ? 'rgba(0,0,0,0.1)' : `${tokens.accent.primary}33`}`,
              color: 'text.primary',
              '& .MuiMenuItem-root': {
                fontSize: '12px',
                fontWeight: 600,
                fontFamily: 'Inter',
                '&:hover': { bgcolor: `${tokens.accent.primary}15` }
              }
            }
          }
        }}
      >
        <MenuItem onClick={handleLaunchADAssessment} sx={{ color: tokens.accent.primary }}>
          <ListItemIcon><Network size={16} color={tokens.accent.primary} /></ListItemIcon>
          <ListItemText primary="ASSESS IDENTITY INFRASTRUCTURE" />
        </MenuItem>
        <Divider sx={{ my: 0.5, borderColor: 'divider' }} />
        <MenuItem onClick={() => handleToggleImportant(selectedId!)} sx={{ color: tokens.accent.warning }}>
          <ListItemIcon><Shield size={16} color={tokens.accent.warning} /></ListItemIcon>
          <ListItemText primary={targetSubdomain?.is_important ? "UNMARK IMPORTANT" : "MARK IMPORTANT"} />
        </MenuItem>
        <MenuItem onClick={() => handleDelete(selectedId!)} sx={{ color: tokens.accent.error }}>
          <ListItemIcon><Trash2 size={16} color={tokens.accent.error} /></ListItemIcon>
          <ListItemText primary="DELETE ASSET" />
        </MenuItem>
      </Menu>

      {/* Subscan Overlay */}
      <Dialog
        open={subscanModalOpen}
        onClose={() => setSubscanModalOpen(false)}
        maxWidth="xs"
        fullWidth
        slotProps={{
          paper: {
            sx: {
              ...getDialogPaperSx(isLight, theme, tokens),
              border: `1px solid ${isLight ? 'rgba(0,0,0,0.1)' : `${tokens.accent.primary}33`}`,
            }
          }
        }}
      >
        <DialogTitle sx={{ color: tokens.accent.primary, fontFamily: 'Orbitron', fontSize: '0.9rem', letterSpacing: 2 }}>
          CONFIGURE SUBSCAN: {selectedAssets.length > 0 ? `${selectedAssets.length} ASSETS` : targetSubdomain?.name}
        </DialogTitle>
        <DialogContent>
          <Typography sx={{ color: 'text.secondary', fontSize: '0.7rem', mb: 2, fontFamily: 'monospace' }}>
            SELECT ENGINE & ANALYTIC TASKS
          </Typography>
          
          <FormControl fullWidth size="small" sx={{ mb: 3 }}>
            <InputLabel id="engine-select-label" sx={{ color: 'text.secondary', fontSize: '0.8rem' }}>Scan Engine</InputLabel>
            <Select
              labelId="engine-select-label"
              value={selectedEngineId || ''}
              label="Scan Engine"
              onChange={(e) => {
                setSelectedEngineId(Number(e.target.value));
                setSelectedTasks([]);
              }}
              sx={{
                color: 'text.primary',
                '& .MuiOutlinedInput-notchedOutline': { borderColor: isLight ? tokens.border.subtle : 'rgba(255,255,255,0.1)' },
                '&:hover .MuiOutlinedInput-notchedOutline': { borderColor: `${tokens.accent.primary}4D` },
                '&.Mui-focused .MuiOutlinedInput-notchedOutline': { borderColor: tokens.accent.primary },
              }}
            >
              {enginesData?.map(engine => (
                <MenuItem key={engine.id} value={engine.id}>{engine.engine_name}</MenuItem>
              ))}
            </Select>
          </FormControl>

          {selectedEngine && (
            <Box>
              <Typography sx={{ color: tokens.accent.primary, fontSize: '0.65rem', mb: 1, fontWeight: 900, fontFamily: 'Orbitron' }}>
                AVAILABLE TASKS
              </Typography>
              <FormGroup>
                {[...selectedEngine.tasks]
                  .sort((a, b) => {
                    const ai = TASK_TIER_ORDER.indexOf(a);
                    const bi = TASK_TIER_ORDER.indexOf(b);
                    return (ai === -1 ? Infinity : ai) - (bi === -1 ? Infinity : bi);
                  })
                  .map((task: string) => (
                  <FormControlLabel
                    key={task}
                    control={
                      <Checkbox
                        size="small"
                        checked={selectedTasks.includes(task)}
                        onChange={(e) => {
                          if (e.target.checked) setSelectedTasks(prev => [...prev, task]);
                          else setSelectedTasks(prev => prev.filter(t => t !== task));
                        }}
                        sx={{ color: `${tokens.accent.primary}33`, '&.Mui-checked': { color: tokens.accent.primary } }}
                      />
                    }
                    label={<Typography sx={{ fontSize: '0.8rem', color: 'text.primary', fontWeight: 600 }}>{task.replace(/_/g, ' ').toUpperCase()}</Typography>}
                  />
                ))}
              </FormGroup>

              {enabledPlugins.length > 0 && (
                <>
                  <Divider sx={{ borderColor: 'divider', my: 1.5 }} />
                  <Typography sx={{ color: tokens.accent.primary, fontSize: '0.65rem', mb: 1, fontWeight: 900, fontFamily: 'Orbitron' }}>
                    PLUGINS
                  </Typography>
                  <FormGroup>
                    {enabledPlugins.map(plugin => (
                      <FormControlLabel
                        key={plugin.slug}
                        control={
                          <Checkbox
                            size="small"
                            checked={selectedPlugins.includes(plugin.slug)}
                            onChange={(e) => {
                              setSelectedPlugins(prev =>
                                e.target.checked
                                  ? [...prev, plugin.slug]
                                  : prev.filter(s => s !== plugin.slug)
                                );
                            }}
                            sx={{ color: `${tokens.accent.primary}33`, '&.Mui-checked': { color: tokens.accent.primary } }}
                          />
                        }
                        label={
                          <Typography sx={{ fontSize: '0.8rem', color: 'text.primary', fontWeight: 600 }}>
                            {plugin.name}
                          </Typography>
                        }
                      />
                    ))}
                  </FormGroup>
                </>
              )}
            </Box>
          )}
        </DialogContent>
        <DialogActions sx={{ p: 2, borderTop: '1px solid', borderColor: 'divider' }}>
          <Button onClick={() => setSubscanModalOpen(false)} sx={{ color: 'text.secondary', fontSize: '0.7rem' }}>CANCEL</Button>
          <Button
            variant="contained"
            onClick={handleInitiateSubscan}
            disabled={subscanMutation.isPending || !selectedEngineId || selectedTasks.length === 0}
            sx={{
              bgcolor: `${tokens.accent.primary}15`,
              color: tokens.accent.primary,
              border: `1px solid ${isLight ? 'rgba(0,0,0,0.1)' : `${tokens.accent.primary}33`}`,
              fontSize: '0.7rem',
              fontWeight: 900,
              '&:hover': { bgcolor: `${tokens.accent.primary}33` }
            }}
          >
            {subscanMutation.isPending ? 'INITIATING...' : 'RUN SUBSCAN'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Attack Surface Modal */}
      <Dialog
        open={attackSurfaceModalOpen}
        onClose={() => setAttackSurfaceModalOpen(false)}
        maxWidth="md"
        fullWidth
        slotProps={{
          paper: {
            sx: {
              ...getDialogPaperSx(isLight, theme, tokens),
              border: `1px solid ${isLight ? 'rgba(0,0,0,0.1)' : `${tokens.accent.primary}33`}`,
            }
          }
        }}
      >
        <DialogTitle sx={{ color: tokens.accent.primary, fontFamily: 'Orbitron', fontSize: '0.9rem', letterSpacing: 2, display: 'flex', justifycontent: 'space-between', alignItems: 'center' }}>
          ATTACK SURFACE ANALYSIS: {targetSubdomain?.name}
          <IconButton onClick={() => setAttackSurfaceModalOpen(false)} size="small" sx={{ color: 'text.disabled' }}><X size={18} /></IconButton>
        </DialogTitle>
        <DialogContent>
          {attackSurfaceMutation.isPending ? (
            <Box sx={{ py: 8, textAlign: 'center' }}>
              <CircularProgress size={32} sx={{ color: tokens.accent.primary }} />
              <Typography sx={{ color: tokens.text.secondary, fontSize: '0.7rem', mt: 2, fontFamily: 'Orbitron', letterSpacing: 1 }}>
                AI ENGINE ANALYZING TARGET VECTOR...
              </Typography>
            </Box>
          ) : attackSurfaceMutation.isError ? (
            <Alert severity="error" sx={{ bgcolor: isLight ? 'rgba(239, 68, 68, 0.08)' : 'rgba(255, 0, 60, 0.05)', color: 'error.main', border: '1px solid', borderColor: 'error.main' }}>
              {((attackSurfaceMutation.error as any)?.response?.data?.error) || (attackSurfaceMutation.error as any)?.message || "Failed to generate attack surface. Ensure LLM is configured in settings."}
            </Alert>
          ) : attackSurfaceMutation.data?.status === false ? (
            <Alert severity="error" sx={{ bgcolor: isLight ? 'rgba(239, 68, 68, 0.08)' : 'rgba(255, 0, 60, 0.05)', color: 'error.main', border: '1px solid', borderColor: 'error.main' }}>
              {attackSurfaceMutation.data?.error || "Failed to generate attack surface. Ensure LLM is configured in settings."}
            </Alert>
          ) : (
            <Box sx={{
              p: 3,
              bgcolor: 'action.hover',
              border: 1, borderColor: 'divider',
              borderRadius: 1,
              maxHeight: '70vh',
              overflow: 'auto',
              color: 'text.primary',
              '& .markdown-content': {
                fontFamily: 'Inter, sans-serif',
                fontSize: '0.9rem',
                lineHeight: 1.6,
                '& h1, h2, h3': { color: tokens.accent.primary, fontFamily: 'Orbitron', mt: 3, mb: 1.5, letterSpacing: 1 },
                '& p': { mb: 2 },
                '& ul, ol': { mb: 2, pl: 3 },
                '& li': { mb: 1 },
                '& strong': { color: tokens.accent.primary, fontWeight: 800 },
                '& code': { bgcolor: `${tokens.accent.primary}15`, px: 0.5, borderRadius: 0.5, color: tokens.accent.primary, fontFamily: 'monospace' },
                '& pre': { bgcolor: isLight ? 'rgba(0,0,0,0.05)' : 'rgba(0,0,0,0.3)', p: 2, borderRadius: 1, border: 1, borderColor: 'divider', overflow: 'auto', mb: 2 },
              }
            }}>
              <div className="markdown-content">
                <ReactMarkdown>
                  {attackSurfaceMutation.data?.description || "No analysis provided by LLM."}
                </ReactMarkdown>
              </div>
            </Box>
          )}
        </DialogContent>
      </Dialog>

      {/* Add TODO Modal */}
      <Dialog
        open={todoModalOpen}
        onClose={() => setTodoModalOpen(false)}
        maxWidth="xs"
        fullWidth
        slotProps={{
          paper: {
            sx: {
              ...getDialogPaperSx(isLight, theme, tokens),
              border: `1px solid ${isLight ? 'rgba(0,0,0,0.1)' : `${warningAccent}33`}`,
            }
          }
        }}
      >
        <DialogTitle sx={{ color: warningAccent, fontFamily: 'Orbitron', fontSize: '0.9rem', letterSpacing: 2 }}>
          ADD RECON NOTE: {targetSubdomain?.name}
        </DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField
              label="Title"
              fullWidth
              size="small"
              value={todoTitle}
              onChange={(e) => setTodoTitle(e.target.value)}
              variant="outlined"
              sx={getFieldSx(isLight, tokens, warningAccent)}
            />
            <TextField
              label="Description"
              fullWidth
              multiline
              rows={3}
              value={todoDescription}
              onChange={(e) => setTodoDescription(e.target.value)}
              variant="outlined"
              sx={getFieldSx(isLight, tokens, warningAccent)}
            />
          </Stack>
        </DialogContent>
        <DialogActions sx={{ p: 2, borderTop: '1px solid', borderColor: 'divider' }}>
          <Button onClick={() => setTodoModalOpen(false)} sx={{ color: 'text.secondary', fontSize: '0.7rem' }}>CANCEL</Button>
          <Button
            variant="contained"
            onClick={handleAddTodo}
            disabled={createTodoMutation.isPending}
            sx={{
              bgcolor: isLight ? 'rgba(245, 158, 11, 0.08)' : 'rgba(255, 174, 0, 0.1)',
              color: warningAccent,
              border: '1px solid',
              borderColor: 'warning.main',
              fontSize: '0.7rem',
              fontWeight: 900,
              '&:hover': { bgcolor: isLight ? 'rgba(245, 158, 11, 0.16)' : 'rgba(255, 174, 0, 0.2)' }
            }}
          >
            {createTodoMutation.isPending ? 'SAVING...' : 'SAVE NOTE'}
          </Button>
        </DialogActions>
      </Dialog>
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

      {/* Probe confirmation */}
      <ConfirmDialog
        open={Boolean(probeTarget)}
        onClose={() => setProbeTarget(null)}
        onConfirm={handleProbeConfirm}
        title="Probe Subdomain"
        message={`Run HTTP crawl and screenshot against ${probeTarget?.name}? This will refresh its status, content length, IP, and screenshot.`}
        confirmText="PROBE"
        cancelText="CANCEL"
        isDestructive={false}
        type="info"
        isLoading={probeMutation.isPending}
      />

      <Snackbar
        open={snackbar.open}
        autoHideDuration={4000}
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
            bgcolor: snackbar.severity === 'success' ? tokens.accent.success : tokens.accent.error,
            color: '#fff',
            '& .MuiAlert-icon': { color: '#fff' }
          }}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>

      <Snackbar
        open={adLaunchMsg !== null}
        autoHideDuration={6000}
        onClose={() => setAdLaunchMsg(null)}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert
          severity={adLaunchMsg?.severity ?? 'info'}
          onClose={() => setAdLaunchMsg(null)}
          sx={{ width: '100%' }}
        >
          {adLaunchMsg?.text}
        </Alert>
      </Snackbar>

      {/* Lightbox Modal */}
      <Modal
        open={!!lightboxSrc}
        onClose={closeLightbox}
        closeAfterTransition
        sx={{ 
          display: 'flex', 
          alignItems: 'center', 
          justifyContent: 'center',
          zIndex: 999999 // Extremely high to be sure
        }}
      >
        <Fade in={!!lightboxSrc} timeout={200}>
          <Box
            sx={{
              position: 'relative',
              width: '100vw',
              height: '100vh',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              outline: 'none',
            }}
          >
            {/* Custom Backdrop - guaranteed to be behind since it's the first child */}
            <Box 
              onClick={closeLightbox}
              sx={{ 
                position: 'absolute', 
                inset: 0, 
                bgcolor: 'rgba(0, 0, 0, 0.92)', 
                backdropFilter: 'blur(8px)',
                zIndex: 1,
                cursor: 'zoom-out'
              }} 
            />
            
            {/* Content - guaranteed to be on top since it's after the backdrop and has higher zIndex */}
            <Box
              sx={{
                position: 'relative',
                zIndex: 2,
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center',
                p: 4,
                maxWidth: '95vw',
                maxHeight: '95vh',
              }}
            >
              <IconButton
                onClick={closeLightbox}
                sx={{
                  position: 'absolute',
                  top: -20,
                  right: -20,
                  color: 'rgba(255,255,255,0.8)',
                  bgcolor: 'rgba(0,0,0,0.5)',
                  zIndex: 3,
                  '&:hover': { color: 'text.primary', bgcolor: `${tokens.accent.primary}33` }
                }}
              >
                <X size={20} />
              </IconButton>
            
            <Box
              component="img"
              src={lightboxSrc || ''}
              alt="Screenshot Full View"
              onClick={(e) => e.stopPropagation()}
              sx={{
                maxWidth: '95vw',
                maxHeight: '85vh',
                objectFit: 'contain',
                borderRadius: 1,
                border: `1px solid ${isLight ? 'rgba(0,0,0,0.15)' : `${tokens.accent.primary}33`}`,
                boxShadow: `0 0 50px ${tokens.accent.primary}26`,
                cursor: 'default'
              }}
            />
              </Box>
            </Box>
          </Fade>
      </Modal>

      {/* Add Subdomain Dialog */}
      <Dialog
        open={addSubdomainModalOpen}
        onClose={() => {
          if (!addSubdomainMutation.isPending) {
            setAddSubdomainModalOpen(false);
            setManualSubdomainName('');
          }
        }}
        maxWidth="xs"
        fullWidth
        slotProps={{
          paper: {
            sx: {
              ...getDialogPaperSx(isLight, theme, tokens),
              border: `1px solid ${isLight ? 'rgba(0,0,0,0.1)' : `${tokens.accent.primary}33`}`,
            }
          }
        }}
      >
        <DialogTitle sx={{ color: tokens.accent.primary, fontFamily: 'Orbitron', fontSize: '0.9rem', letterSpacing: 2 }}>
          ADD SUBDOMAINS MANUALLY
        </DialogTitle>
        <DialogContent>
          <Typography sx={{ color: 'text.secondary', fontSize: '0.7rem', mb: 2, fontFamily: 'monospace' }}>
            ENTER SUBDOMAINS (SEPARATED BY NEWLINES, COMMAS, OR SPACES)
          </Typography>
          <TextField
            autoFocus
            fullWidth
            multiline
            rows={5}
            size="small"
            label="Subdomain List"
            value={manualSubdomainName}
            onChange={(e) => setManualSubdomainName(e.target.value)}
            placeholder="sub1.domain.com&#10;sub2.domain.com&#10;sub3.domain.com"
            disabled={addSubdomainMutation.isPending}
            sx={{
              mt: 1,
              ...getFieldSx(isLight, tokens, tokens.accent.primary),
              '& .MuiInputLabel-root': { color: 'text.secondary', fontSize: '0.8rem' },
            }}
          />
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 3 }}>
          <Button
            size="small"
            onClick={() => {
              setAddSubdomainModalOpen(false);
              setManualSubdomainName('');
            }}
            disabled={addSubdomainMutation.isPending}
            sx={{ color: 'text.secondary', fontSize: '10px', fontWeight: 700 }}
          >
            CANCEL
          </Button>
          <Button
            size="small"
            variant="contained"
            disabled={addSubdomainMutation.isPending || !manualSubdomainName.trim()}
            onClick={async () => {
              try {
                const res = await addSubdomainMutation.mutateAsync({
                  target_id: targetId,
                  scan_id: scanId,
                  subdomain_name: manualSubdomainName.trim(),
                });
                if (res.status) {
                  showNotification(res.message || 'Subdomain added successfully');
                  setAddSubdomainModalOpen(false);
                  setManualSubdomainName('');
                } else {
                  showNotification(res.message || 'Failed to add subdomain', 'error');
                }
              } catch (err: any) {
                showNotification(err.response?.data?.message || err.message || 'Error adding subdomain', 'error');
              }
            }}
            sx={{
              bgcolor: tokens.accent.primary,
              color: isLight ? '#fff' : '#000',
              fontWeight: 800,
              fontSize: '10px',
              '&:hover': { bgcolor: `${tokens.accent.primary}CC` }
            }}
          >
            {addSubdomainMutation.isPending ? 'ADDING...' : 'ADD SUBDOMAIN'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};
