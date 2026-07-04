import React, { useState, useMemo } from 'react';
import { getSeverityColor as getSemanticSeverityColor, getSeverityLabel } from '../../../theme/semanticColors';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import { useParams, Link as RouterLink } from '@tanstack/react-router';
import {
  Box,
  Grid,
  Typography,
  Card,
  CardContent,
  Button,
  IconButton,
  Stack,
  Chip,
  Tab,
  Tabs,
  Paper,
  Divider,
  CircularProgress,
  Tooltip as MuiTooltip,
  List,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Avatar,
  ListItem,
  ListItemText,
  ListItemIcon,
  LinearProgress,
  FormControlLabel,
  Checkbox,
  Dialog,
  DialogTitle,
  DialogContent,
  Slide,
  Backdrop,
  DialogActions,
  Link,
  Alert
} from '@mui/material';
import {
  Activity,
  Globe,
  Shield,
  Server,
  Zap,
  Terminal,
  AlertTriangle,
  Target,
  Map as MapIcon,
  ChevronRight,
  Clock,
  ExternalLink,
  Info,
  Layers,
  Search,
  Database,
  Cpu,
  MoreHorizontal,
  Plus,
  Link as LinkIcon,
  FileText,
  BarChart2,
  ShieldAlert,
  Bug,
  ChevronUp,
  ChevronDown,
  History,
  Timer,
  Settings,
  Camera,
  Folder,
  Eye,
  Mail,
  Users,
  Key,
  X,
  Copy,
  RefreshCw,
  GitBranch,
  Brain
} from 'lucide-react';
import { useScanSummary, useActivityLogs, useScanLogs, useFetchWhois, useStopScan, useRetryScanTask } from '../api';
import type { Command, SubScan, Vulnerability, ScanActivity, Subdomain, ScanSummaryResponse, TodoNote } from '../types';
import Chart from 'react-apexcharts';
import { GeoMap } from '../../dashboard/components/GeoMap';
import { KpiCard } from '../../../components/KpiCard';
import { SubdomainsTab } from './SubdomainsTab';
import { DirectoriesTab } from './DirectoriesTab';
import { EndpointsTab } from './EndpointsTab';
import { ParametersTab } from './ParametersTab';
import { TacticalPanel } from '../../../components/TacticalPanel';
import { VulnerabilityTable } from '../../vulnerabilities/components/VulnerabilityTable';
import { useGptVulnerabilityDetails } from '../../vulnerabilities/api';
import { SecretLeaksTab } from './SecretLeaksTab';
import { AttackSurfaceTab } from './AttackSurfaceTab';
import VisualizationTab from './VisualizationTab';
import { ScreenshotsTab } from './ScreenshotsTab';
import { ScanReportModal } from './ScanReportModal';
import { StartScanModal } from './StartScanModal';
import { OsintTab } from './OsintTab';
import { AttackPathsTab } from './AttackPathsTab';
import { AiExportModal } from './AiExportModal';
import { ExposureList } from '../../exposures/components/ExposureList';
import { usePlugins } from '../../plugins/api/pluginsApi';
import PluginComponent from '../../plugins/components/PluginComponent';
import PluginComponentLoader from '../../plugins/components/PluginComponentLoader';
import PluginCardSlot from '../../plugins/components/PluginCardSlot';

const SeverityBadge: React.FC<{ severity: number }> = ({ severity }) => {
  const { tokens } = useThemeTokens();
  const color = getSemanticSeverityColor(severity, tokens);
  const label = getSeverityLabel(severity);
  return (
    <Box sx={{
      display: 'inline-flex',
      px: 1,
      py: 0.2,
      borderRadius: 0.5,
      bgcolor: `${color}20`,
      border: `1px solid ${color}50`,
      color: color,
      fontSize: '0.6rem',
      fontWeight: 900
    }}>
      {label}
    </Box>
  );
};

const VulnerabilityInfoModal: React.FC<{
  open: boolean;
  onClose: () => void;
  vulnerability: any;
}> = ({ open, onClose, vulnerability }) => {
  const { tokens, isLight } = useThemeTokens();
  const gptMutation = useGptVulnerabilityDetails();
  const [localVuln, setLocalVuln] = useState<any>(null);
  const [error, setError] = React.useState<string | null>(null);

  React.useEffect(() => {
    setLocalVuln(vulnerability);
    setError(null);
  }, [vulnerability]);

  if (!localVuln) return null;

  const severityColor = getSemanticSeverityColor(String(localVuln.severity ?? 'info'), tokens);

  const handleFetchGpt = async () => {
    if (!localVuln) return;
    setError(null);
    try {
      const result = await gptMutation.mutateAsync({ id: localVuln.id!, name: localVuln.name });
      if (result.status) {
        setLocalVuln((prev: any) => ({
          ...prev,
          description: result.description,
          impact: result.impact,
          remediation: result.remediation,
          references: result.references?.join('\n') || prev.references || ''
        }));
      } else {
        setError(result.error || 'Failed to generate GPT description');
      }
    } catch (err: any) {
      console.error(err);
      setError(err?.response?.data?.error || err?.message || 'Something went wrong while generating GPT description');
    }
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      maxWidth="md"
      fullWidth
      slotProps={{
        paper: {
          sx: {
            bgcolor: 'background.paper',
            backgroundImage: isLight
              ? 'none'
              : 'linear-gradient(rgba(255, 255, 255, 0.02) 1px, transparent 1px), linear-gradient(90deg, rgba(255, 255, 255, 0.02) 1px, transparent 1px)',
            backgroundSize: '20px 20px',
            border: `1px solid ${severityColor}40`,
            borderRadius: 2,
            boxShadow: `0 0 30px ${severityColor}15`
          }
        }
      }}
    >
      <DialogTitle sx={{ p: 3, borderBottom: 1, borderColor: 'divider', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <Stack direction="row" sx={{ spacing: '2', alignItems: "center" }}>
          <Bug size={24} color={severityColor} />
          <Box>
            <Typography sx={{ color: 'text.primary', fontWeight: 900, fontSize: '1.1rem', letterSpacing: 1, fontFamily: 'Orbitron' }}>
              {localVuln.name}
            </Typography>
            <SeverityBadge severity={Number(localVuln.severity)} />
          </Box>
        </Stack>
        <IconButton onClick={onClose} sx={{ color: 'text.secondary', '&:hover': { color: 'text.primary', bgcolor: 'action.hover' } }}>
          <X size={20} />
        </IconButton>
      </DialogTitle>
      <DialogContent sx={{ p: 3 }}>
        <Stack spacing={4}>
          {error && (
            <Alert severity="error" sx={{ bgcolor: isLight ? `${tokens.accent.error}15` : 'rgba(255, 0, 60, 0.05)', color: isLight ? tokens.accent.error : '#ff003c', border: `1px solid ${isLight ? `${tokens.accent.error}33` : 'rgba(255, 0, 60, 0.2)'}` }}>
              {error}
            </Alert>
          )}
          {/* Classification Section */}
          <Box sx={{ p: 2, bgcolor: 'action.hover', border: 1, borderColor: 'divider', borderRadius: 1 }}>
            <Typography sx={{ color: severityColor, fontSize: '0.7rem', fontWeight: 900, mb: 2, letterSpacing: 1, textTransform: 'uppercase' }}>
              Vulnerability Classification
            </Typography>
            <Grid container spacing={2}>
              <Grid size={{ xs: 6, md: 3 }}>
                <Typography sx={{ color: 'text.secondary', fontSize: '0.7rem', fontWeight: 700, mb: 0.5 }}>CVSS SCORE</Typography>
                <Typography sx={{ color: 'text.primary', fontSize: '0.9rem', fontWeight: 900 }}>{localVuln.cvss_score || 'N/A'}</Typography>
              </Grid>
              <Grid size={{ xs: 6, md: 3 }}>
                <Typography sx={{ color: 'text.secondary', fontSize: '0.7rem', fontWeight: 700, mb: 0.5 }}>CVSS METRICS</Typography>
                <Typography sx={{ color: 'text.primary', fontSize: '0.8rem', fontWeight: 600, fontFamily: 'monospace' }}>{localVuln.cvss_metrics || 'N/A'}</Typography>
              </Grid>
              <Grid size={{ xs: 6, md: 3 }}>
                <Typography sx={{ color: 'text.secondary', fontSize: '0.7rem', fontWeight: 700, mb: 0.5 }}>SOURCE</Typography>
                <Typography sx={{ color: 'text.primary', fontSize: '0.9rem', fontWeight: 700 }}>{localVuln.source || 'N/A'}</Typography>
              </Grid>
              <Grid size={{ xs: 6, md: 3 }}>
                <Typography sx={{ color: 'text.secondary', fontSize: '0.7rem', fontWeight: 700, mb: 0.5 }}>TAGS</Typography>
                <Stack direction="row" sx={{ spacing: 0.5, flexWrap: "wrap" }}>
                  {localVuln.tags?.map((tag: any, i: number) => (
                    <Chip
                      key={i}
                      label={tag.name}
                      size="small"
                      sx={{
                        height: 16,
                        fontSize: '0.6rem',
                        bgcolor: 'action.hover',
                        color: 'text.secondary',
                        border: `1px solid ${tokens.border.subtle}`
                      }}
                    />
                  )) || <Typography sx={{ color: 'text.disabled', fontSize: '0.8rem' }}>N/A</Typography>}
                </Stack>
              </Grid>
            </Grid>
          </Box>

          {/* Description Section */}
          <Box>
            <Typography sx={{ color: severityColor, fontSize: '0.7rem', fontWeight: 900, mb: 1.5, letterSpacing: 1, textTransform: 'uppercase' }}>
              Description
            </Typography>
            <Typography sx={{ color: 'text.primary', fontSize: '0.9rem', lineHeight: 1.6, whiteSpace: 'pre-wrap' }}>
              {localVuln.description || 'No description provided.'}
            </Typography>
          </Box>

          {/* Impact Section */}
          {localVuln.impact && (
            <Box>
              <Typography sx={{ color: isLight ? tokens.accent.error : '#ff003c', fontSize: '0.7rem', fontWeight: 900, mb: 1.5, letterSpacing: 1, textTransform: 'uppercase' }}>
                Impact
              </Typography>
              <Typography sx={{ color: 'text.primary', fontSize: '0.9rem', lineHeight: 1.6, whiteSpace: 'pre-wrap' }}>
                {localVuln.impact}
              </Typography>
            </Box>
          )}

          {/* Remediation Section */}
          {localVuln.remediation && (
            <Box>
              <Typography sx={{ color: isLight ? tokens.accent.success : '#00ff62', fontSize: '0.7rem', fontWeight: 900, mb: 1.5, letterSpacing: 1, textTransform: 'uppercase' }}>
                Remediation
              </Typography>
              <Typography sx={{ color: 'text.primary', fontSize: '0.9rem', lineHeight: 1.6, whiteSpace: 'pre-wrap' }}>
                {localVuln.remediation}
              </Typography>
            </Box>
          )}

          {/* References Section */}
          {localVuln.references && (
            <Box>
              <Typography sx={{ color: tokens.accent.primary, fontSize: '0.7rem', fontWeight: 900, mb: 1.5, letterSpacing: 1, textTransform: 'uppercase' }}>
                References
              </Typography>
              <Stack spacing={1}>
                {localVuln.references.split('\n').filter(Boolean).map((ref: string, i: number) => (
                  <Link
                    key={i}
                    href={ref}
                    target="_blank"
                    sx={{
                      color: 'text.secondary',
                      fontSize: '0.8rem',
                      display: 'flex',
                      alignItems: 'center',
                      gap: 1,
                      textDecoration: 'none',
                      '&:hover': { color: tokens.accent.primary, textDecoration: 'underline' }
                    }}
                  >
                    <ExternalLink size={12} />
                    {ref}
                  </Link>
                ))}
              </Stack>
            </Box>
          )}
        </Stack>
      </DialogContent>
      <DialogActions sx={{ p: 3, borderTop: 1, borderColor: 'divider', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Button
          onClick={handleFetchGpt}
          disabled={gptMutation.isPending}
          startIcon={gptMutation.isPending ? <CircularProgress size={14} sx={{ color: isLight ? tokens.accent.warning : '#fffc00' }} /> : <Brain size={14} />}
          sx={{
            bgcolor: isLight ? `${tokens.accent.warning}1A` : 'rgba(255, 252, 0, 0.1)',
            color: isLight ? '#9a6700' : '#fffc00',
            border: isLight ? `1px solid ${tokens.accent.warning}4D` : '1px solid rgba(255, 252, 0, 0.3)',
            fontFamily: 'Orbitron',
            fontSize: '0.75rem',
            fontWeight: 900,
            px: 2.5,
            py: 1,
            borderRadius: '4px',
            textShadow: isLight ? 'none' : '0 0 10px rgba(255, 252, 0, 0.3)',
            boxShadow: isLight ? 'none' : '0 0 15px rgba(255, 252, 0, 0.05)',
            '&:hover': {
              bgcolor: isLight ? `${tokens.accent.warning}33` : 'rgba(255, 252, 0, 0.2)',
              borderColor: isLight ? '#9a6700' : '#fffc00',
              boxShadow: isLight ? 'none' : '0 0 20px rgba(255, 252, 0, 0.15)'
            },
            '&.Mui-disabled': {
              color: isLight ? 'rgba(154, 103, 0, 0.5)' : 'rgba(255, 252, 0, 0.5)',
              borderColor: isLight ? 'rgba(154, 103, 0, 0.1)' : 'rgba(255, 252, 0, 0.1)',
              bgcolor: isLight ? 'rgba(154, 103, 0, 0.05)' : 'rgba(255, 252, 0, 0.05)'
            }
          }}
        >
          {gptMutation.isPending ? 'THINKING...' : 'AI ANALYSIS'}
        </Button>
        <Button
          onClick={onClose}
          sx={{
            color: 'text.secondary',
            '&:hover': { color: 'text.primary', bgcolor: 'action.hover' },
            fontFamily: 'Orbitron',
            fontSize: '0.75rem',
            fontWeight: 900
          }}
        >
          CLOSE
        </Button>
      </DialogActions>
    </Dialog>
  );
};

const getFrontendEngineColor = (
  activityTitle: string,
  tokens: ReturnType<typeof useThemeTokens>['tokens']
) => {
  if (!activityTitle) return tokens.text.primary;
  const lowerTitle = activityTitle.toLowerCase();
  if (lowerTitle.includes('vulnerability')) return tokens.accent.error;
  if (lowerTitle.includes('osint') || lowerTitle.includes('intelligence')) return tokens.accent.secondary;
  if (lowerTitle.includes('fetch') || lowerTitle.includes('http')) return tokens.accent.info;
  if (lowerTitle.includes('waf')) return tokens.accent.secondary;
  if (lowerTitle.includes('port') || lowerTitle.includes('firewall') || lowerTitle.includes('vpn')) return tokens.accent.success;
  if (lowerTitle.includes('attack path')) return tokens.accent.warning;
  if (lowerTitle.includes('directories') || lowerTitle.includes('web api')) return tokens.accent.warning;
  if (lowerTitle.includes('subdomain') || lowerTitle.includes('screenshot')) return tokens.accent.primary;
  return tokens.text.primary;
};

const StatusBadge: React.FC<{ status: number, compact?: boolean, isSpiderFootRunning?: boolean }> = ({ status, compact = false, isSpiderFootRunning = false }) => {
  const { tokens, isLight } = useThemeTokens();
  if (isSpiderFootRunning) {
    return (
      <MuiTooltip title="SpiderFoot OSINT Scan is running in the background">
        <Box sx={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: 1,
          px: compact ? 2 : 3,
          py: compact ? 0.4 : 1,
          borderRadius: '20px',
          border: `1px solid ${tokens.accent.secondary}40`,
          color: tokens.accent.secondary,
          fontSize: '0.9rem',
          fontWeight: 900,
          fontFamily: 'Orbitron',
          animation: 'pulse-spider 2s infinite ease-in-out',
          textShadow: isLight ? 'none' : `0 0 10px ${tokens.accent.secondary}40`,
          boxShadow: `inset 0 0 10px ${tokens.accent.secondary}10`,
          '@keyframes pulse-spider': {
            '0%': { transform: 'scale(1)', filter: `drop-shadow(0 0 0px ${tokens.accent.secondary})` },
            '50%': { transform: 'scale(1.05)', filter: `drop-shadow(0 0 8px ${tokens.accent.secondary})` },
            '100%': { transform: 'scale(1)', filter: `drop-shadow(0 0 0px ${tokens.accent.secondary})` },
          }
        }}>
          <Bug size={compact ? 12 : 18} />
          {compact ? 'SF ACTIVE' : 'SPIDERFOOT ACTIVE'}
        </Box>
      </MuiTooltip>
    );
  }
  const configs: any = {
    [-1]: { label: 'PENDING', color: tokens.accent.warning, icon: Clock },
    [0]: { label: 'FAILED', color: tokens.accent.error, icon: AlertTriangle },
    [1]: { label: 'RUNNING', color: tokens.accent.primary, icon: Activity },
    [2]: { label: 'SUCCESS', color: tokens.accent.success, icon: Shield },
    [3]: { label: 'ABORTED', color: tokens.accent.error, icon: AlertTriangle },
    [4]: { label: 'PARTIALLY COMPLETE', color: tokens.accent.warning, icon: AlertTriangle },
    [5]: { label: 'PAUSED', color: tokens.accent.warning, icon: Clock },
  };
  const config = configs[status] || { label: 'UNKNOWN', color: 'text.primary', icon: Info };
  const Icon = config.icon;

  return (
    <Box sx={{
      display: 'inline-flex',
      alignItems: 'center',
      gap: 1,
      px: compact ? 2 : 3,
      py: compact ? 0.4 : 1,
      borderRadius: '20px',
      bgcolor: 'transparent',
      border: `1px solid ${config.color}40`,
      color: config.color,
      fontSize: '0.9rem',
      fontWeight: 900,
      fontFamily: 'Orbitron',
      textShadow: isLight ? 'none' : `0 0 10px ${config.color}40`,
      boxShadow: isLight ? 'none' : `inset 0 0 10px ${config.color}10`
    }}>
      <Icon size={compact ? 12 : 18} />
      {config.label}
    </Box>
  );
};

const formatTimeAgo = (date: string) => {
  if (!date) return 'N/A';
  const now = new Date();
  const past = new Date(date);
  const diffMs = now.getTime() - past.getTime();
  const diffHrs = Math.floor(diffMs / (1000 * 60 * 60));
  const days = Math.floor(diffHrs / 24);
  const hrs = diffHrs % 24;

  if (days > 0) return `${days} days, ${hrs} hours ago`;
  return `${hrs} hours ago`;
};

const getCommandBinary = (cmd: string) => {
  if (!cmd) return 'Command';
  const cleanCmd = cmd.trim();
  const parts = cleanCmd.split(/\s+/);
  if (parts.length === 0) return 'Command';
  let binary = parts[0].split('/').pop() || parts[0];
  if ((binary === 'python' || binary === 'python3' || binary === 'python2') && parts.length > 1) {
    const script = parts[1].split('/').pop() || parts[1];
    binary = `${binary} ${script}`;
  }
  return binary;
};

const getToolColor = (binary: string, tokens: any, isLight?: boolean) => {
  const b = binary.toLowerCase();
  if (b.includes('httpx')) return tokens.accent.primary;
  if (b.includes('nuclei')) return tokens.accent.error;
  if (b.includes('semgrep')) return tokens.accent.success;
  if (b.includes('gau') || b.includes('hakrawler') || b.includes('katana') || b.includes('gospider') || b.includes('waybackurls')) return tokens.accent.warning;
  if (b.includes('cat') || b.includes('sort') || b.includes('grep') || b.includes('mv') || b.includes('rm')) return 'text.secondary';
  return tokens.accent.secondary;
};

const TaskOverlay: React.FC<{
  open: boolean;
  onClose: () => void;
  activityId: number | null;
  scanId?: number | null;
  activityTitle: string;
}> = ({ open, onClose, activityId, scanId, activityTitle }) => {
  const { tokens, isLight, theme } = useThemeTokens();
  const { data: logs, isLoading } = useScanLogs(activityId, scanId ?? null);

  const [selectedLog, setSelectedLog] = useState<Command | null>(null);

  // Set first log as selected when logs load
  React.useEffect(() => {
    if (logs && logs.length > 0) {
      if (!selectedLog || !logs.find((l: Command) => l.id === selectedLog.id)) {
        setSelectedLog(logs[0]);
      }
    }
  }, [logs]);

  return (
    <Dialog
      open={open}
      onClose={onClose}
      fullWidth
      maxWidth="lg"
      slotProps={{
        paper: {
          sx: {
            bgcolor: 'background.paper',
            backgroundImage: isLight
              ? 'linear-gradient(rgba(0, 0, 0, 0.02) 1px, transparent 1px), linear-gradient(90deg, rgba(0, 0, 0, 0.02) 1px, transparent 1px)'
              : 'linear-gradient(rgba(255, 255, 255, 0.02) 1px, transparent 1px), linear-gradient(90deg, rgba(255, 255, 255, 0.02) 1px, transparent 1px)',
            backgroundSize: '20px 20px',
            border: `1px solid ${tokens.border.subtle}`,
            borderRadius: 2,
            minHeight: '70vh'
          }
        }
      }}
    >
      <DialogTitle sx={{ p: 2, display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: 1, borderColor: 'divider' }}>
        <Stack direction="row" sx={{ alignItems: "center" }}>
          <Terminal size={20} color={tokens.accent.primary} />
          <Typography sx={{ color: 'text.primary', fontWeight: 900, fontSize: '1rem', letterSpacing: 1, ml: 2 }}>
            {activityTitle} Execution Logs
          </Typography>
        </Stack>
        <IconButton onClick={onClose} size="small" sx={{ color: 'text.secondary', '&:hover': { color: 'text.primary', bgcolor: 'action.hover' } }}>
          <X size={20} />
        </IconButton>
      </DialogTitle>
      <DialogContent sx={{ p: 0, overflow: 'hidden' }}>
        <Grid container sx={{ height: '60vh' }}>
          {/* Command List */}
          <Grid size={{ xs: 4 }} sx={{ borderRight: 1, borderColor: 'divider', height: '100%', overflowY: 'auto' }}>
            {isLoading ? (
              <Box sx={{ p: 4, textAlign: 'center' }}>
                <CircularProgress size={24} sx={{ color: tokens.accent.primary }} />
              </Box>
            ) : logs && logs.length > 0 ? (
              <List sx={{ p: 0 }}>
                {logs.map((log: Command) => {
                  const cmdStr = log.command || '';
                  const binaryName = getCommandBinary(cmdStr);
                  const toolColor = getToolColor(binaryName, tokens, isLight);
                  const parts = cmdStr.trim().split(/\s+/);
                  const displayArgs = parts.length > 0 ? cmdStr.replace(parts[0], '').trim() : '';

                  return (
                    <ListItem
                      key={log.id}
                      component="div"
                      onClick={() => setSelectedLog(log)}
                      sx={{
                        cursor: 'pointer',
                        borderBottom: 1,
                        borderColor: 'divider',
                        py: 1.5,
                        px: 2,
                        bgcolor: selectedLog?.id === log.id ? `${tokens.accent.primary}0D` : 'transparent',
                        borderLeft: selectedLog?.id === log.id ? `3px solid ${toolColor}` : '3px solid transparent',
                        '&:hover': { bgcolor: 'action.hover' }
                      }}
                    >
                      <ListItemText
                        primary={
                          <Stack direction="row" spacing={1} sx={{ alignItems: 'center', mb: 0.5, overflow: 'hidden' }}>
                            <Box sx={{
                              px: 0.8,
                              py: 0.2,
                              fontSize: '0.6rem',
                              fontFamily: 'monospace',
                              fontWeight: 900,
                              borderRadius: 0.5,
                              bgcolor: `${toolColor}15`,
                              color: toolColor,
                              border: `1px solid ${toolColor}30`,
                              textTransform: 'uppercase',
                              letterSpacing: 0.5,
                              flexShrink: 0
                            }}>
                              {binaryName}
                            </Box>
                            <Typography sx={{
                              fontSize: '0.75rem',
                              color: selectedLog?.id === log.id ? 'text.primary' : 'text.secondary',
                              fontWeight: 700,
                              fontFamily: 'monospace',
                              whiteSpace: 'nowrap',
                              textOverflow: 'ellipsis',
                              overflow: 'hidden',
                              flexGrow: 1
                            }}>
                              {displayArgs || '(no arguments)'}
                            </Typography>
                          </Stack>
                        }
                        secondary={
                          <Stack direction="row" sx={{ justifyContent: 'space-between', alignItems: 'center', mt: 0.5 }}>
                            <Typography sx={{ fontSize: '0.6rem', color: 'text.disabled', fontFamily: 'monospace' }}>
                              ID: #{log.id}
                            </Typography>
                            <Typography sx={{ fontSize: '0.6rem', color: 'text.disabled', fontFamily: 'monospace' }}>
                              {new Date(log.time).toLocaleTimeString()}
                            </Typography>
                          </Stack>
                        }
                      />
                    </ListItem>
                  );
                })}
              </List>
            ) : (
              <Box sx={{ p: 4, textAlign: 'center' }}>
                <Typography sx={{ color: 'text.disabled', fontSize: '0.8rem' }}>
                  No commands found.
                </Typography>
              </Box>
            )}
          </Grid>
          {/* Command Output */}
          <Grid size={{ xs: 8 }} sx={{ height: '100%', overflowY: 'auto', bgcolor: isLight ? 'rgba(0,0,0,0.01)' : 'background.default' }}>
            {selectedLog ? (
              <Box sx={{ p: 2 }}>
                {/* Clean Command Box Header */}
                <Box sx={{
                  p: 2,
                  mb: 3,
                  bgcolor: 'background.paper',
                  border: 1, borderColor: 'divider',
                  borderRadius: 1,
                  boxShadow: theme.shadows[2]
                }}>
                  <Stack direction="row" sx={{ justifyContent: 'space-between', alignItems: 'center', mb: 1.5 }}>
                    <Stack direction="row" spacing={1.5} sx={{ alignItems: 'center' }}>
                      <Box sx={{
                        width: 8,
                        height: 8,
                        borderRadius: '50%',
                        bgcolor: selectedLog.return_code === 0 ? tokens.accent.success : selectedLog.return_code === null ? tokens.accent.warning : tokens.accent.error,
                        boxShadow: isLight ? 'none' : `0 0 10px ${selectedLog.return_code === 0 ? tokens.accent.success : selectedLog.return_code === null ? tokens.accent.warning : tokens.accent.error}`
                      }} />
                      <Typography sx={{
                        fontSize: '0.65rem',
                        color: 'text.secondary',
                        fontWeight: 900,
                        letterSpacing: 1,
                        textTransform: 'uppercase'
                      }}>
                        Command Execution Detail
                      </Typography>
                    </Stack>
                    <Box sx={{
                      px: 1,
                      py: 0.3,
                      fontSize: '0.55rem',
                      fontFamily: 'monospace',
                      fontWeight: 900,
                      borderRadius: 0.5,
                      bgcolor: selectedLog.return_code === 0 ? `${tokens.accent.success}1A` : selectedLog.return_code === null ? `${tokens.accent.warning}1A` : `${tokens.accent.error}1A`,
                      color: selectedLog.return_code === 0 ? tokens.accent.success : selectedLog.return_code === null ? tokens.accent.warning : tokens.accent.error,
                      border: `1px solid ${selectedLog.return_code === 0 ? `${tokens.accent.success}33` : selectedLog.return_code === null ? `${tokens.accent.warning}33` : `${tokens.accent.error}33`}`
                    }}>
                      STATUS: {selectedLog.return_code === 0 ? 'SUCCESS' : selectedLog.return_code === null ? 'RUNNING' : `EXIT CODE: ${selectedLog.return_code}`}
                    </Box>
                  </Stack>

                  {/* The Executed Command */}
                  <Box sx={{
                    p: 1.5,
                    bgcolor: 'action.hover',
                    borderLeft: `3px solid ${getToolColor(getCommandBinary(selectedLog.command || ''), tokens, isLight)}`,
                    fontFamily: 'monospace',
                    fontSize: '0.75rem',
                    color: 'text.primary',
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-all',
                    position: 'relative'
                  }}>
                    <Box component="span" sx={{ color: 'text.disabled', mr: 1, userSelect: 'none' }}>$</Box>
                    {selectedLog.command || ''}
                  </Box>
                </Box>

                {/* Output Header */}
                <Stack direction="row" sx={{ justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                  <Typography sx={{
                    fontSize: '0.7rem',
                    color: getFrontendEngineColor(selectedLog.activity?.title || activityTitle, tokens),
                    fontWeight: 900,
                    textTransform: 'uppercase',
                    letterSpacing: 1
                  }}>
                    {selectedLog.activity?.title || activityTitle} Output
                  </Typography>
                  <Button
                    size="small"
                    startIcon={<Copy size={12} />}
                    onClick={() => navigator.clipboard.writeText(selectedLog.output || '')}
                    sx={{ color: 'text.secondary', fontSize: '0.6rem', border: 1, borderColor: 'divider', '&:hover': { color: 'text.primary', border: `1px solid ${tokens.accent.primary}` } }}
                  >
                    Copy Output
                  </Button>
                </Stack>
                <Box sx={{
                  p: 2,
                  bgcolor: isLight ? 'rgba(0,0,0,0.03)' : 'rgba(0,0,0,0.5)',
                  border: 1, borderColor: 'divider',
                  borderRadius: 1,
                  fontFamily: 'monospace',
                  fontSize: '0.75rem',
                  color: 'text.primary',
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-all',
                  minHeight: '30vh'
                }}>
                  {selectedLog.output || "No output captured yet..."}
                </Box>
              </Box>
            ) : (
              <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', gap: 2, opacity: 0.3 }}>
                <Terminal size={48} />
                <Typography sx={{ fontSize: '0.8rem', fontWeight: 700 }}>Select a command to view output</Typography>
              </Box>
            )}
          </Grid>
        </Grid>
      </DialogContent>
    </Dialog>
  );
};

const TIER_LABELS: Record<number, string> = {
  0: 'Initialization',
  1: 'Discovery',
  2: 'Enumeration',
  3: 'URL & Screenshots',
  4: 'Fuzzing',
  5: 'Analysis',
  6: 'Security Assessment',
  7: 'Post-Processing',
};

const TimelineItem: React.FC<{ activity: ScanActivity, onClick?: () => void, onRetry?: (activity: ScanActivity) => void, isTerminal?: boolean }> = ({ activity, onClick, onRetry, isTerminal }) => {
  const { theme, isLight, tokens } = useThemeTokens();
  const statusConfig: Record<string, { color: string, label: string }> = {
    'SUCCESS': { color: tokens.accent.success, label: 'Completed' },
    'RUNNING': { color: tokens.accent.primary, label: 'In Progress' },
    'FAILED': { color: tokens.accent.error, label: 'Failed' },
    'ABORTED': { color: tokens.accent.error, label: 'Aborted' },
    'PENDING': { color: tokens.accent.warning, label: 'Pending' }
  };
  const config = statusConfig[activity.status] || { color: theme.palette.text.primary, label: activity.status };

  return (
    <Box
      onClick={onClick}
      sx={{
        position: 'relative',
        pl: 5,
        pb: 4,
        '&:last-child': { pb: 0 },
        cursor: 'pointer',
        '&:hover': {
          '& .timeline-content': { bgcolor: isLight ? 'rgba(0,0,0,0.03)' : 'rgba(255,255,255,0.03)' }
        }
      }}
    >
      {/* Vertical Line */}
      <Box sx={{
        position: 'absolute',
        left: 6,
        top: 10,
        bottom: -4,
        width: 2,
        bgcolor: isLight ? 'rgba(0,0,0,0.1)' : 'rgba(255,255,255,0.05)',
        zIndex: 1
      }} />

      {/* Dot - Ring Style */}
      <Box sx={{
        position: 'absolute',
        left: 0,
        top: 4,
        width: 14,
        height: 14,
        borderRadius: '50%',
        border: `2px solid ${config.color}`,
        bgcolor: 'transparent',
        boxShadow: activity.status === 'RUNNING' ? `0 0 10px ${config.color}` : 'none',
        zIndex: 2,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center'
      }}>
        {activity.status === 'RUNNING' && (
          <Box sx={{
            width: 4,
            height: 4,
            borderRadius: '50%',
            bgcolor: config.color,
            opacity: 0.8
          }} />
        )}
      </Box>

      <Stack spacing={0.5} className="timeline-content" sx={{ p: 1, borderRadius: 1, transition: 'background-color 0.2s' }}>
        <Stack direction="row" spacing={1} sx={{ alignItems: 'center', justifyContent: 'space-between' }}>
          <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }}>
            <Typography sx={{ fontSize: '0.85rem', fontWeight: 800, color: theme.palette.text.primary }}>
              {activity.title}
            </Typography>
            <Box sx={{
              px: 1,
              py: 0.1,
              borderRadius: 1,
              bgcolor: `${config.color}20`,
              border: `1px solid ${config.color}40`,
              color: config.color,
              fontSize: '0.6rem',
              fontWeight: 800
            }}>
              {config.label}
            </Box>
            <Typography sx={{ fontSize: '0.6rem', color: isLight ? 'rgba(0,0,0,0.4)' : 'rgba(255,255,255,0.3)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 0.5 }}>
              • Click to view details <ChevronRight size={10} />
            </Typography>
          </Stack>
          {isTerminal && activity.status === 'FAILED' && activity.name !== 'raw_scan_history' && onRetry && (
            <MuiTooltip title="Retry Task" placement="top">
              <IconButton 
                size="small" 
                onClick={(e) => { e.stopPropagation(); onRetry(activity); }}
                sx={{ color: tokens.accent.primary, '&:hover': { bgcolor: `${tokens.accent.primary}20` } }}
              >
                <RefreshCw size={14} />
              </IconButton>
            </MuiTooltip>
          )}
        </Stack>
        <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }}>
          <Typography sx={{ fontSize: '0.7rem', color: isLight ? 'rgba(0,0,0,0.6)' : 'rgba(255,255,255,0.3)', fontWeight: 600 }}>
            {activity.status === 'PENDING'
              ? 'Queued'
              : activity.time_started
                ? new Date(activity.time_started).toLocaleString()
                : new Date(activity.time).toLocaleString()}
          </Typography>
          {activity.time_started && activity.time_ended && (
            <Typography sx={{ fontSize: '0.65rem', color: 'text.disabled', fontWeight: 600 }}>
              ({Math.round((new Date(activity.time_ended).getTime() - new Date(activity.time_started).getTime()) / 1000)}s)
            </Typography>
          )}
        </Stack>
        {activity.error_message && (
          <Typography sx={{ fontSize: '0.65rem', color: isLight ? tokens.accent.error : '#ff003c', bgcolor: isLight ? `${tokens.accent.error}15` : 'rgba(255,0,60,0.1)', p: 1, borderRadius: 0.5, border: `1px solid ${isLight ? `${tokens.accent.error}33` : 'rgba(255,0,60,0.2)'}`, mt: 1 }}>
            ERROR: {activity.error_message}
          </Typography>
        )}
      </Stack>
    </Box>
  );
};

const SubScanWidget: React.FC<{ subscans: SubScan[], targetName: string }> = ({ subscans, targetName }) => {
  const { tokens, isLight } = useThemeTokens();
  return (
    <Stack spacing={1.5}>
      <Box sx={{ mb: 1 }}>
        <Typography sx={{ fontSize: '0.75rem', fontWeight: 900, color: tokens.accent.secondary, mb: 1, textTransform: 'uppercase', letterSpacing: 1.5 }}>
          SUB SCAN HISTORY FOR
        </Typography>
        <Box component="span" sx={{ display: 'inline-block', px: 2, py: 0.4, border: `1px solid ${tokens.accent.secondary}`, borderRadius: '20px', color: tokens.accent.secondary, fontSize: '0.7rem', bgcolor: isLight ? `${tokens.accent.secondary}15` : 'rgba(255,0,255,0.05)' }}>
          {targetName}
        </Box>
      </Box>
      {subscans?.map((sub: SubScan) => (
        <Box key={sub.id} sx={{ p: 2, borderRadius: 2, bgcolor: 'action.hover', border: 1, borderColor: 'divider', position: 'relative', overflow: 'hidden' }}>
          <Box sx={{ position: 'absolute', left: 0, top: 0, bottom: 0, width: 4, bgcolor: sub.status === 2 ? (isLight ? tokens.accent.success : '#00ff62') : (isLight ? tokens.accent.warning : '#ffc107'), borderRadius: '4px 0 0 4px' }} />
          <Stack spacing={1.5}>
            <Typography sx={{ fontSize: '0.85rem', fontWeight: 900, color: tokens.accent.primary, textTransform: 'uppercase', letterSpacing: 1 }}>
              {sub.engine} ON {sub.subdomain_name}
            </Typography>
            <Stack direction="row" sx={{ justifyContent: 'space-between', alignItems: 'center' }}>
              <Typography sx={{ fontSize: '0.75rem', color: 'text.secondary', fontWeight: 600, maxWidth: '60%', lineHeight: 1.4 }}>
                {sub.completed_ago} Took {sub.time_taken}
              </Typography>
              <StatusBadge status={sub.status} compact />
            </Stack>
          </Stack>
        </Box>
      ))}
      {(!subscans || subscans.length === 0) && (
        <Typography sx={{ fontSize: '0.7rem', color: 'text.disabled', textAlign: 'center', py: 2 }}>NO SUB SCANS FOUND</Typography>
      )}
    </Stack>
  );
};

const VulnerabilityBreakdown: React.FC<{ counts: Record<string, number>, exploitable: number }> = ({ counts, exploitable }) => {
  const { tokens, isLight } = useThemeTokens();
  const series = [counts.critical, counts.high, counts.medium, counts.low, counts.info, counts.unknown, exploitable];
  const labels = ['Critical', 'High', 'Medium', 'Low', 'Info', 'Unknown', 'Exploitable'];
  const colors = [
    isLight ? tokens.accent.error : '#ff003c',
    isLight ? '#d97706' : '#ff5722',
    isLight ? '#b45309' : '#ff9800',
    isLight ? '#9a6700' : '#ffeb3b',
    isLight ? tokens.accent.info : '#2196f3',
    tokens.text.disabled,
    isLight ? tokens.accent.success : '#00ff62'
  ];

  return (
    <TacticalPanel title="Vulnerability Breakdown" icon={<Bug size={14} color={isLight ? tokens.accent.error : '#ff003c'} />} sx={{ height: '100%', '& .MuiCardContent-root': { pb: '10px !important' } }}>
      <Box sx={{ p: 1, display: 'flex', flexDirection: 'column', height: '100%' }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 3, textAlign: 'center', width: '100%', px: 1 }}>
          {labels.map((l, i) => (
            <Box key={l} sx={{ flex: 1 }}>
              <Typography sx={{ fontSize: '0.6rem', color: colors[i], fontWeight: 800, textTransform: 'uppercase', letterSpacing: 1 }}>{l.substring(0, 4)}</Typography>
              <Typography sx={{ fontSize: '0.85rem', fontWeight: 900, color: colors[i] }}>{series[i] || 0}</Typography>
            </Box>
          ))}
        </Box>
        <Box sx={{ flexGrow: 1, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <Chart
            options={{
              chart: { type: 'donut', background: 'transparent' },
              theme: { mode: isLight ? 'light' : 'dark' as any },
              stroke: { show: false },
              labels: labels,
              dataLabels: { enabled: false },
              legend: { show: true, position: 'bottom', fontSize: '10px', labels: { colors: isLight ? tokens.text.secondary : 'rgba(255,255,255,0.7)' } },
              colors: colors,
              plotOptions: {
                pie: {
                  donut: {
                    size: '65%',
                    labels: {
                      show: true,
                      total: {
                        show: true,
                        label: 'Total',
                        color: 'text.secondary',
                        fontSize: '12px',
                        formatter: () => counts.total.toString()
                      },
                      value: { color: 'text.primary', fontSize: '20px', fontWeight: 900 }
                    }
                  }
                }
              }
            }}
            series={series}
            type="donut"
            width="100%"
            height={260}
          />
        </Box>
      </Box>
    </TacticalPanel>
  );
};

const VulnHighlights: React.FC<{ highlights: Vulnerability[], onVulnClick: (v: any) => void }> = ({ highlights, onVulnClick }) => {
  const { tokens, isLight } = useThemeTokens();
  return (
    <TacticalPanel title="Vulnerability Highlights" icon={<Bug size={14} color={tokens.accent.error} />} sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <TableContainer sx={{ flex: 1, overflow: 'auto', maxHeight: 380 }}>
        <Table size="small" stickyHeader>
          <TableHead>
            <TableRow sx={{ '& th': { borderBottom: `2px solid ${tokens.accent.primary}`, bgcolor: 'background.paper', color: tokens.accent.primary, fontSize: '0.7rem', fontWeight: 900, py: 1.5 } }}>
              <TableCell>TYPE</TableCell>
              <TableCell>VULNERABILITY</TableCell>
              <TableCell>SEVERITY</TableCell>
              <TableCell>VULNERABLE URL</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {(highlights || []).map((v: Vulnerability, idx: number) => (
              <TableRow
                key={idx}
                onClick={() => onVulnClick(v)}
                sx={{
                  '& td': { borderBottom: 1, borderColor: 'divider', py: 2 },
                  cursor: 'pointer',
                  transition: 'background-color 0.2s',
                  '&:hover': {
                    bgcolor: isLight ? 'action.hover' : 'rgba(255,255,255,0.03)',
                    '& td:nth-of-type(2) p:first-of-type': { color: tokens.accent.primary }
                  }
                }}
              >
                <TableCell>
                  <Box sx={{
                    bgcolor: isLight ? `${tokens.accent.info}1A` : 'rgba(33,150,243,0.1)',
                    color: isLight ? tokens.accent.info : '#2196f3',
                    fontSize: '0.6rem',
                    fontWeight: 900,
                    px: 1,
                    py: 0.5,
                    borderRadius: 0.5,
                    display: 'inline-block',
                    textTransform: 'lowercase'
                  }}>
                    {Number(v.severity) === 0 ? 'info' : 'vuln'}
                  </Box>
                </TableCell>
                <TableCell>
                  <Typography sx={{ fontSize: '0.75rem', fontWeight: 800, color: 'text.primary', mb: 0.5 }}>{v.name}</Typography>
                  <Typography sx={{ fontSize: '0.65rem', color: 'text.secondary' }}>
                    Discovered: {formatTimeAgo(v.discovered_date || '')}
                  </Typography>
                </TableCell>
                <TableCell>
                  <SeverityBadge severity={Number(v.severity)} />
                </TableCell>
                <TableCell>
                  <Typography sx={{
                    fontSize: '0.7rem',
                    color: isLight ? tokens.accent.error : '#ff003c',
                    fontWeight: 600,
                    wordBreak: 'break-all'
                  }}>
                    {v.http_url}
                  </Typography>
                </TableCell>
              </TableRow>
            ))}
            {(!highlights || highlights.length === 0) && (
              <TableRow>
                <TableCell colSpan={4} align="center" sx={{ py: 4, color: isLight ? 'text.disabled' : 'rgba(255,255,255,0.2)' }}>NO VULNERABILITY HIGHLIGHTS</TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>
    </TacticalPanel>
  );
};

interface SubdomainVulnCounts {
  host: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}

const MostVulnerableSubdomain: React.FC<{ vulnerabilities: Vulnerability[], sx?: any }> = ({ vulnerabilities = [], sx = {} }) => {
  const { tokens, isLight } = useThemeTokens();
  const [ignoreInfo, setIgnoreInfo] = useState(false);

  const filteredVulns = ignoreInfo ? vulnerabilities.filter(v => Number(v.severity) > 0) : vulnerabilities;

  const subdomainMap = filteredVulns.reduce(
    (acc: Record<string, SubdomainVulnCounts>, v: Vulnerability) => {
      try {
        if (!v.http_url) return acc;
        const normalizedUrl = v.http_url.match(/^https?:\/\//) ? v.http_url : `http://${v.http_url}`;
        const host = new URL(normalizedUrl).hostname;
        if (!host) return acc;
        if (!acc[host]) acc[host] = { host, critical: 0, high: 0, medium: 0, low: 0, total: 0 };
        const sev = Number(v.severity);
        if (sev === 4) acc[host].critical += 1;
        else if (sev === 3) acc[host].high += 1;
        else if (sev === 2) acc[host].medium += 1;
        else if (sev === 1) acc[host].low += 1;
        acc[host].total += 1;
      } catch {
        // ignore invalid URLs
      }
      return acc;
    },
    {}
  );

  const rows = Object.values(subdomainMap).sort((a, b) => b.total - a.total);

  const cellStyle = { borderBottom: 1, borderColor: 'divider', py: 0.75 };

  return (
    <TacticalPanel
      title="MOST VULNERABLE SUBDOMAINS"
      icon={<ShieldAlert size={14} color={isLight ? tokens.accent.error : '#ff003c'} />}
      sx={{ height: '100%', ...sx }}
      headerAction={
        <FormControlLabel
          control={<Checkbox size="small" checked={ignoreInfo} onChange={(e) => setIgnoreInfo(e.target.checked)} sx={{ color: 'text.secondary', '&.Mui-checked': { color: tokens.accent.primary } }} />}
          label={<Typography sx={{ fontSize: '0.65rem', color: 'text.secondary', fontWeight: 800 }}>Ignore Info</Typography>}
        />
      }
    >
      {rows.length > 0 ? (
        <TableContainer sx={{ maxHeight: 320 }}>
          <Table size="small" stickyHeader>
            <TableHead>
              <TableRow>
                <TableCell sx={{ bgcolor: isLight ? 'action.hover' : 'background.paper', color: 'text.secondary', fontSize: '0.6rem', fontWeight: 800, borderBottom: isLight ? '1px solid rgba(0,0,0,0.08)' : `1px solid ${tokens.accent.primary}33`, textTransform: 'uppercase', letterSpacing: 1 }}>Subdomain</TableCell>
                <TableCell align="center" sx={{ bgcolor: isLight ? 'action.hover' : 'background.paper', color: isLight ? tokens.accent.error : '#ff003c', fontSize: '0.6rem', fontWeight: 800, borderBottom: isLight ? '1px solid rgba(0,0,0,0.08)' : `1px solid ${tokens.accent.primary}33`, textTransform: 'uppercase' }}>Crit</TableCell>
                <TableCell align="center" sx={{ bgcolor: isLight ? 'action.hover' : 'background.paper', color: isLight ? '#d97706' : '#ff9f00', fontSize: '0.6rem', fontWeight: 800, borderBottom: isLight ? '1px solid rgba(0,0,0,0.08)' : `1px solid ${tokens.accent.primary}33`, textTransform: 'uppercase' }}>High</TableCell>
                <TableCell align="center" sx={{ bgcolor: isLight ? 'action.hover' : 'background.paper', color: isLight ? '#b45309' : '#fffc00', fontSize: '0.6rem', fontWeight: 800, borderBottom: isLight ? '1px solid rgba(0,0,0,0.08)' : `1px solid ${tokens.accent.primary}33`, textTransform: 'uppercase' }}>Med</TableCell>
                <TableCell align="center" sx={{ bgcolor: isLight ? 'action.hover' : 'background.paper', color: isLight ? tokens.accent.success : '#00ff62', fontSize: '0.6rem', fontWeight: 800, borderBottom: isLight ? '1px solid rgba(0,0,0,0.08)' : `1px solid ${tokens.accent.primary}33`, textTransform: 'uppercase' }}>Low</TableCell>
                <TableCell align="center" sx={{ bgcolor: isLight ? 'action.hover' : 'background.paper', color: tokens.accent.primary, fontSize: '0.6rem', fontWeight: 800, borderBottom: isLight ? '1px solid rgba(0,0,0,0.08)' : `1px solid ${tokens.accent.primary}33`, textTransform: 'uppercase' }}>Total</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {rows.map((row) => (
                <TableRow key={row.host} sx={{ '&:hover': { bgcolor: 'action.hover' } }}>
                  <TableCell sx={cellStyle}>
                    <Typography sx={{ fontSize: '0.7rem', fontWeight: 600, color: 'text.primary' }}>{row.host}</Typography>
                  </TableCell>
                  <TableCell align="center" sx={cellStyle}>
                    <Typography sx={{ fontSize: '0.7rem', fontWeight: 700, color: row.critical > 0 ? (isLight ? tokens.accent.error : '#ff003c') : tokens.text.disabled }}>{row.critical}</Typography>
                  </TableCell>
                  <TableCell align="center" sx={cellStyle}>
                    <Typography sx={{ fontSize: '0.7rem', fontWeight: 700, color: row.high > 0 ? (isLight ? '#d97706' : '#ff9f00') : tokens.text.disabled }}>{row.high}</Typography>
                  </TableCell>
                  <TableCell align="center" sx={cellStyle}>
                    <Typography sx={{ fontSize: '0.7rem', fontWeight: 700, color: row.medium > 0 ? (isLight ? '#b45309' : '#fffc00') : tokens.text.disabled }}>{row.medium}</Typography>
                  </TableCell>
                  <TableCell align="center" sx={cellStyle}>
                    <Typography sx={{ fontSize: '0.7rem', fontWeight: 700, color: row.low > 0 ? (isLight ? tokens.accent.success : '#00ff62') : tokens.text.disabled }}>{row.low}</Typography>
                  </TableCell>
                  <TableCell align="center" sx={cellStyle}>
                    <Box sx={{ px: 1, py: 0.25, borderRadius: 0.5, bgcolor: `${tokens.accent.primary}15`, display: 'inline-block' }}>
                      <Typography sx={{ fontSize: '0.7rem', fontWeight: 800, color: tokens.accent.primary }}>{row.total}</Typography>
                    </Box>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      ) : (
        <Box sx={{ p: 2 }}>
          <Box sx={{ bgcolor: isLight ? `${tokens.accent.warning}15` : 'rgba(255,252,0,0.1)', border: `1px solid ${isLight ? `${tokens.accent.warning}33` : 'rgba(255,252,0,0.2)'}`, p: 2, borderRadius: 1 }}>
            <Typography sx={{ fontSize: '0.75rem', color: isLight ? tokens.accent.warning : '#fffc00', fontWeight: 700, mb: 1 }}>Could not find most vulnerable targets.</Typography>
            <Typography sx={{ fontSize: '0.65rem', color: isLight ? 'text.secondary' : 'rgba(255,252,0,0.6)' }}>Once the vulnerability scan is performed, reNgine will identify the most vulnerable targets.</Typography>
          </Box>
        </Box>
      )}
    </TacticalPanel>
  );
};

const MostCommonVulnsWidget: React.FC<{ vulnerabilities: Vulnerability[], onVulnClick: (v: any) => void, sx?: any }> = ({ vulnerabilities = [], onVulnClick, sx = {} }) => {
  const { tokens, isLight } = useThemeTokens();
  const [ignoreInfo, setIgnoreInfo] = useState(false);
  const filtered = ignoreInfo ? vulnerabilities.filter(v => Number(v.severity) !== 0) : vulnerabilities;

  // Calculate common vulns from the full vulnerabilities list to ensure Info vulns are included
  const commonMap = filtered.reduce((acc: Record<string, any>, v: Vulnerability) => {
    acc[v.name] = acc[v.name] || { name: v.name, count: 0, severity: v.severity, vulnerability: v };
    acc[v.name].count += 1;
    return acc;
  }, {});

  const data = Object.values(commonMap).sort((a: { count: number }, b: { count: number }) => b.count - a.count).slice(0, 10);

  return (
    <TacticalPanel
      title="MOST COMMON VULNERABILITIES"
      icon={<Bug size={14} color={isLight ? tokens.accent.error : '#ff003c'} />}
      sx={{ height: '100%', ...sx }}
      headerAction={
        <FormControlLabel
          control={<Checkbox size="small" checked={ignoreInfo} onChange={(e) => setIgnoreInfo(e.target.checked)} sx={{ color: 'text.secondary', '&.Mui-checked': { color: tokens.accent.primary } }} />}
          label={<Typography sx={{ fontSize: '0.65rem', color: 'text.secondary', fontWeight: 800 }}>Ignore Info Vulnerabilities</Typography>}
        />
      }
    >
      <TableContainer sx={{ flex: 1, overflow: 'auto' }}>
        <Table size="small">
          <TableHead>
            <TableRow sx={{ '& th': { borderBottom: isLight ? '2px solid rgba(0,0,0,0.08)' : '2px solid rgba(255,255,255,0.05)', color: tokens.accent.primary, fontSize: '0.65rem', fontWeight: 900 } }}>
              <TableCell>VULNERABILITY NAME</TableCell>
              <TableCell align="center">COUNT</TableCell>
              <TableCell align="right">SEVERITY</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {data.map((v: { name: string; count: number; severity: string | number; vulnerability: any }, i: number) => (
              <TableRow
                key={i}
                onClick={() => onVulnClick(v.vulnerability)}
                sx={{
                  '& td': { borderBottom: isLight ? '1px solid rgba(0,0,0,0.05)' : '1px solid rgba(255,255,255,0.03)', py: 1.5 },
                  cursor: 'pointer',
                  transition: 'background-color 0.2s',
                  '&:hover': {
                    bgcolor: isLight ? 'action.hover' : 'rgba(255,255,255,0.03)',
                    '& td:first-of-type': { color: tokens.accent.primary }
                  }
                }}
              >
                <TableCell sx={{ color: 'text.primary', fontSize: '0.75rem', fontWeight: 800, transition: 'color 0.2s' }}>{v.name}</TableCell>
                <TableCell align="center">
                  <Box sx={{ display: 'inline-block', px: 1.5, py: 0.5, border: `1px solid ${tokens.accent.error}`, color: tokens.accent.error, borderRadius: 0.5, fontSize: '0.7rem', fontWeight: 900, bgcolor: `${tokens.accent.error}1A` }}>
                    {v.count}
                  </Box>
                </TableCell>
                <TableCell align="right">
                  <SeverityBadge severity={typeof v.severity === 'string' ? (v.severity === 'Critical' ? 4 : v.severity === 'High' ? 3 : v.severity === 'Medium' ? 2 : v.severity === 'Low' ? 1 : 0) : v.severity} />
                </TableCell>
              </TableRow>
            ))}
            {data.length === 0 && (
              <TableRow>
                <TableCell colSpan={3} align="center" sx={{ py: 4, color: isLight ? 'text.disabled' : 'rgba(255,255,255,0.2)', fontSize: '0.7rem' }}>NO VULNERABILITIES FOUND</TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>
    </TacticalPanel>
  );
};

const ImportantSubdomainsWidget: React.FC<{ subdomains: Subdomain[], sx?: any }> = ({ subdomains = [], sx = {} }) => {
  const { tokens } = useThemeTokens();
  return (
    <TacticalPanel title="IMPORTANT SUBDOMAINS" icon={<Box sx={{ width: 14, height: 14, bgcolor: tokens.accent.secondary, borderRadius: 0.5, color: 'text.primary', fontSize: '8px', fontWeight: 900, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>{subdomains.length}</Box>} sx={{ height: '100%', ...sx }}>
      <Box sx={{ p: 2 }}>
        {subdomains.length > 0 ? (
          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
            {subdomains.map((s: Subdomain, i: number) => (
              <Box key={i} sx={{ px: 1.5, py: 0.5, bgcolor: `${tokens.accent.primary}0D`, border: `1px solid ${tokens.accent.primary}15`, borderRadius: 1, color: tokens.accent.primary, fontSize: '0.7rem', fontWeight: 700 }}>
                {s.name}
              </Box>
            ))}
          </Box>
        ) : (
          <Typography sx={{ fontSize: '0.75rem', color: 'text.disabled', fontStyle: 'italic' }}>No subdomains marked as important!</Typography>
        )}
      </Box>
    </TacticalPanel>
  );
};

const ReconNotesWidget: React.FC<{ notes: any[], sx?: any }> = ({ notes = [], sx = {} }) => {
  const { tokens, isLight } = useThemeTokens();
  return (
    <TacticalPanel
      title="RECON NOTE/TODO"
      icon={<Box sx={{ width: 14, height: 14, bgcolor: tokens.accent.info, borderRadius: 0.5, color: 'text.primary', fontSize: '8px', fontWeight: 900, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>{notes.length}</Box>}
      headerAction={<Plus size={14} color={tokens.accent.primary} style={{ cursor: 'pointer' }} />}
      sx={{ height: '100%', ...sx }}
    >
      <Box sx={{ p: 2 }}>
        {notes.length > 0 ? (
          <Stack spacing={1}>
            {notes.map((n: TodoNote) => (
              <Box key={n.id} sx={{ p: 1, bgcolor: isLight ? 'action.hover' : 'rgba(255,255,255,0.03)', border: 1, borderColor: 'divider', borderRadius: 1, display: 'flex', gap: 1.5 }}>
                <Checkbox size="small" checked={n.is_done} sx={{ color: isLight ? 'rgba(0,0,0,0.26)' : 'rgba(255,255,255,0.2)', p: 0 }} />
                <Box>
                  <Typography sx={{ fontSize: '0.75rem', fontWeight: 800, color: n.is_done ? 'text.disabled' : 'text.primary', textDecoration: n.is_done ? 'line-through' : 'none' }}>{n.title}</Typography>
                  <Typography sx={{ fontSize: '0.65rem', color: 'text.secondary' }}>{n.description}</Typography>
                </Box>
              </Box>
            ))}
          </Stack>
        ) : (
          <Box>
            <Typography sx={{ fontSize: '0.75rem', color: 'text.secondary', fontWeight: 700 }}>No todos or notes...</Typography>
            <Typography sx={{ fontSize: '0.65rem', color: 'text.disabled' }}>You can add todo for individual subdomains or you can also add using + symbol above.</Typography>
          </Box>
        )}
      </Box>
    </TacticalPanel>
  );
};

const IpAddressesWidget: React.FC<{ subdomains: Partial<Subdomain>[], sx?: any }> = ({ subdomains = [], sx = {} }) => {
  const { tokens, isLight } = useThemeTokens();
  const ips = Array.from(new Set(subdomains.map(s => s.origin_ip).filter(ip => ip && ip !== '0.0.0.0')));
  return (
    <TacticalPanel title="IP ADDRESSES" icon={<Box sx={{ width: 14, height: 14, bgcolor: tokens.accent.secondary, borderRadius: 0.5, color: 'text.primary', fontSize: '8px', fontWeight: 900, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>{ips.length}</Box>} sx={{ height: '100%', ...sx }}>
      <Box sx={{ p: 2 }}>
        <Typography sx={{ fontSize: '0.6rem', color: isLight ? tokens.accent.warning : '#fffc00', textAlign: 'right', mb: 1, fontWeight: 700 }}>*IP Addresses highlighted with yellow are CDN IP</Typography>
        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
          {ips.map((ip, i) => (
            <Box key={i} sx={{ px: 1, py: 0.4, bgcolor: isLight ? `${tokens.accent.info}15` : 'rgba(33,150,243,0.1)', border: `1px solid ${isLight ? `${tokens.accent.info}33` : 'rgba(33,150,243,0.2)'}`, borderRadius: 0.5, color: tokens.accent.info, fontSize: '0.65rem', fontWeight: 800 }}>
              {ip}
            </Box>
          ))}
        </Box>
      </Box>
    </TacticalPanel>
  );
};

const DiscoveredPortsWidget: React.FC<{ ports: any[], sx?: any }> = ({ ports = [], sx = {} }) => {
  const { tokens, isLight } = useThemeTokens();
  return (
    <TacticalPanel title="DISCOVERED PORTS" icon={<Box sx={{ width: 14, height: 14, bgcolor: tokens.accent.secondary, borderRadius: 0.5, color: 'text.primary', fontSize: '8px', fontWeight: 900, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>{ports.length}</Box>} sx={{ height: '100%', ...sx }}>
      <Box sx={{ p: 2 }}>
        <Typography sx={{ fontSize: '0.6rem', color: isLight ? tokens.accent.warning : '#fffc00', textAlign: 'right', mb: 1, fontWeight: 700 }}>*Ports highlighted with red are uncommon Ports</Typography>
        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
          {ports.map((p, i) => (
            <Box key={i} sx={{ px: 1, py: 0.4, bgcolor: p.is_uncommon ? (isLight ? `${tokens.accent.error}15` : 'rgba(255,0,60,0.1)') : (isLight ? `${tokens.accent.info}15` : 'rgba(33,150,243,0.1)'), border: `1px solid ${p.is_uncommon ? (isLight ? `${tokens.accent.error}33` : 'rgba(255,0,60,0.2)') : (isLight ? `${tokens.accent.info}33` : 'rgba(33,150,243,0.2)')}`, borderRadius: 0.5, color: p.is_uncommon ? (isLight ? tokens.accent.error : '#ff003c') : (isLight ? tokens.accent.info : '#2196f3'), fontSize: '0.65rem', fontWeight: 800 }}>
              {p.number}/{p.service_name}
            </Box>
          ))}
        </Box>
      </Box>
    </TacticalPanel>
  );
};

const DiscoveredTechWidget: React.FC<{ techs: any[], sx?: any }> = ({ techs = [], sx = {} }) => {
  const { tokens, isLight } = useThemeTokens();
  return (
    <TacticalPanel title="DISCOVERED TECHNOLOGIES" icon={<Box sx={{ width: 14, height: 14, bgcolor: tokens.accent.secondary, borderRadius: 0.5, color: 'text.primary', fontSize: '8px', fontWeight: 900, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>{techs.length}</Box>} sx={{ height: '100%', ...sx }}>
      <Box sx={{ p: 2 }}>
        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
          {techs.map((t, i) => (
            <Box key={i} sx={{ px: 1, py: 0.4, bgcolor: isLight ? `${tokens.accent.info}15` : 'rgba(33,150,243,0.1)', border: `1px solid ${isLight ? `${tokens.accent.info}33` : 'rgba(33,150,243,0.2)'}`, borderRadius: 0.5, color: tokens.accent.info, fontSize: '0.65rem', fontWeight: 800 }}>
              {t.name}
            </Box>
          ))}
        </Box>
      </Box>
    </TacticalPanel>
  );
};

export const ScanDetailPage = () => {
  const { theme, isLight, tokens } = useThemeTokens();
  const { projectSlug, scanId } = useParams({ from: '/$projectSlug/scan/detail/$scanId' });
  const { data, isLoading } = useScanSummary(projectSlug, parseInt(scanId));
  const fetchWhois = useFetchWhois(projectSlug, parseInt(scanId));
  const stopScanMutation = useStopScan(projectSlug);
  const retryScanTaskMutation = useRetryScanTask(projectSlug, parseInt(scanId));
  const { data: plugins } = usePlugins();
  const [activeTab, setActiveTab] = useState(0);
  const [infoTab, setInfoTab] = useState(0);
  const [reportModalOpen, setReportModalOpen] = useState(false);
  const [aiExportModalOpen, setAiExportModalOpen] = useState(false);
  const [startScanTargets, setStartScanTargets] = useState<{ ids: number[]; names: string[] } | null>(null);
  const [taskOverlayOpen, setTaskOverlayOpen] = useState(false);
  const [selectedActivity, setSelectedActivity] = useState<{ id: number; title: string } | null>(null);

  const [selectedVulnForInfo, setSelectedVulnForInfo] = useState<any | null>(null);
  const [vulnInfoModalOpen, setVulnInfoModalOpen] = useState(false);

  const handleVulnClick = (v: any) => {
    setSelectedVulnForInfo(v);
    setVulnInfoModalOpen(true);
  };


  const [selectedScanId, setSelectedScanId] = useState<number | null>(null);

  const handleTimelineItemClick = (activity: ScanActivity) => {
    if (activity.id === 'raw-scan-history') {
      setSelectedScanId(scanId ? parseInt(scanId) : null);
      setSelectedActivity(null);
    } else {
      setSelectedScanId(null);
      setSelectedActivity({
        id: Number(activity.id),
        title: activity.title
      });
    }
    setTaskOverlayOpen(true);
  };

  const handleRetryTask = (activity: ScanActivity) => {
    if (confirm(`Are you sure you want to retry ${activity.title}?`)) {
      retryScanTaskMutation.mutate(Number(activity.id));
    }
  };

  const groupedTimeline = useMemo(() => {
    const timeline: ScanActivity[] = data?.timeline ?? [];
    
    // Build map of activity name to Plugin
    const activityToPlugin = new Map<string, any>();
    if (Array.isArray(plugins)) {
      plugins.forEach(p => {
        const workflows = p.manifest?.temporal?.workflows || [];
        const activities = p.manifest?.temporal?.activities || [];
        workflows.forEach((w: string) => activityToPlugin.set(w.split('.').pop()!, p));
        activities.forEach((a: string) => activityToPlugin.set(a.split('.').pop()!, p));
      });
    }

    const tierGroups = new Map<number, ScanActivity[]>();
    const pluginGroups = new Map<string, { plugin: any, activities: ScanActivity[] }>();

    timeline.forEach((act) => {
      const plugin = activityToPlugin.get(act.name);
      if (plugin) {
        if (!pluginGroups.has(plugin.slug)) {
          pluginGroups.set(plugin.slug, { plugin, activities: [] });
        }
        pluginGroups.get(plugin.slug)!.activities.push(act);
      } else {
        const tier = act.tier ?? 7;
        if (!tierGroups.has(tier)) tierGroups.set(tier, []);
        tierGroups.get(tier)!.push(act);
      }
    });

    const sortedTiers = Array.from(tierGroups.entries()).map(([tier, activities]) => ({
      id: `tier-${tier}`,
      sortOrder: tier,
      label: `Tier ${tier} — ${TIER_LABELS[tier] ?? 'Unknown'}`,
      activities,
      type: 'tier' as const,
    }));

    const sortedPlugins = Array.from(pluginGroups.values()).map(({ plugin, activities }) => {
      let sortOrder = 7;
      if (plugin.anchor_step && typeof plugin.anchor_step === 'string') {
        const match = plugin.anchor_step.match(/tier_(\d+)/);
        if (match) {
          const tierNum = parseInt(match[1], 10);
          sortOrder = plugin.runtime_position === 'BEFORE' ? tierNum - 0.5 : tierNum + 0.5;
        }
      }
      return {
        id: `plugin-${plugin.slug}`,
        sortOrder,
        label: `Plugin — ${plugin.name}`,
        activities,
        type: 'plugin' as const,
      };
    });

    return [...sortedTiers, ...sortedPlugins].sort((a, b) => a.sortOrder - b.sortOrder);
  }, [data?.timeline, plugins]);

  if (isLoading || !data) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '60vh' }}>
        <CircularProgress sx={{ color: tokens.accent.primary }} />
      </Box>
    );
  }

  const scanStatus = data.scan_info.scan_status;
  const isTerminal = [0, 2, 3, 4].includes(scanStatus);
  const progressColor = scanStatus === 2 ? tokens.accent.success : (scanStatus === 3 || scanStatus === 0) ? tokens.accent.error : scanStatus === 4 ? tokens.accent.warning : tokens.accent.primary;
  const progressValue = isTerminal ? 100 : data.scan_info.progress;

  const baseTabs = [
    { label: 'HOME', icon: Activity },
    { label: 'SUBDOMAINS', icon: Globe },
    { label: 'BUCKETS', icon: Database, show: data.buckets_count > 0 },
    { label: 'SCREENSHOTS', icon: Camera, show: data.scan_info.tasks?.includes('screenshot') },
    { label: 'DIRECTORIES', icon: Folder, show: data.scan_info.tasks?.includes('dir_file_fuzz') },
    { label: 'URLS', icon: LinkIcon },
    { label: 'PARAMETERS', icon: Search },
    { label: 'VULNERABILITIES', icon: ShieldAlert, show: data.vulnerability_count > 0 },
    { label: 'EXPOSURES', icon: ShieldAlert },
    { label: 'EXPLOITS', icon: Zap, show: data.exploitable_count > 0 },
    { label: 'OSINT', icon: Search },
    { label: 'LEAKS', icon: Shield },
    { label: 'ATTACK PATHS', icon: GitBranch, show: data.vulnerability_count > 0 },
    { label: 'ATTACK SURFACE', icon: MapIcon },
    { label: 'RECON NOTES', icon: FileText },
    { label: 'VISUALIZATION', icon: BarChart2 },
  ].filter(t => t.show !== false);

  // Inject Plugin Tabs
  const pluginTabs: any[] = [];
  if (Array.isArray(plugins)) {
    plugins.forEach(plugin => {
      if (plugin.is_enabled && plugin.manifest?.ui?.tabs && Array.isArray(plugin.manifest.ui.tabs)) {
        plugin.manifest.ui.tabs.forEach((tab: any) => {
          pluginTabs.push({
            label: tab.label,
            icon: Zap, // Default icon for plugins, could be dynamic
            isPlugin: true,
            pluginSlug: plugin.slug,
            componentFile: tab.file
          });
        });
      }
    });
  }

  const tabs = [...baseTabs, ...pluginTabs];

  const renderSidebar = () => (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
      <TacticalPanel title="Scan Status" icon={<Activity size={14} />}>
        <Box sx={{ p: 2 }}>
          <Stack spacing={4}>
            <Box sx={{ textAlign: 'center', position: 'relative' }}>
              <StatusBadge
                status={data.scan_info.scan_status}
                isSpiderFootRunning={data.scan_info.is_spiderfoot_running}
              />
            </Box>

            <Box>
              <Typography sx={{ fontSize: '0.7rem', color: 'text.secondary', mb: 1.5, textTransform: 'uppercase', letterSpacing: 1.5, fontWeight: 700 }}>Current Progress</Typography>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                <Box sx={{ flexGrow: 1, position: 'relative' }}>
                  <LinearProgress
                    variant="determinate"
                    value={progressValue}
                    sx={{
                      height: 6,
                      borderRadius: 3,
                      bgcolor: 'action.hover',
                      '& .MuiLinearProgress-bar': {
                        bgcolor: progressColor,
                        boxShadow: isLight ? 'none' : `0 0 15px ${progressColor}80`
                      }
                    }}
                  />
                </Box>
                <Typography sx={{ fontSize: '1rem', fontWeight: 900, color: progressColor, fontFamily: 'Orbitron' }}>
                  {progressValue}%
                </Typography>
              </Box>
            </Box>

            <Box sx={{ height: '1px', bgcolor: 'action.hover', mx: -2 }} />

            <Grid container spacing={3}>
              <Grid size={{ xs: 6 }}>
                <Typography sx={{ fontSize: '0.65rem', color: 'text.secondary', mb: 1, fontWeight: 700 }}>ENGINE</Typography>
                <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }}>
                  <Cpu size={16} color={tokens.accent.primary} />
                  <Typography sx={{ fontSize: '0.9rem', fontWeight: 800, color: 'text.primary' }}>{data.scan_info.engine_name}</Typography>
                </Stack>
              </Grid>
              <Grid size={{ xs: 6 }}>
                <Typography sx={{ fontSize: '0.65rem', color: 'text.secondary', mb: 1, fontWeight: 700 }}>DURATION</Typography>
                <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }}>
                  <Timer size={16} color={tokens.accent.warning} />
                  <Typography sx={{ fontSize: '0.9rem', fontWeight: 800, color: 'text.primary' }}>{Math.floor(data.scan_info.duration / 60)}m {data.scan_info.duration % 60}s</Typography>
                </Stack>
              </Grid>
            </Grid>
          </Stack>
        </Box>
      </TacticalPanel>

      <TacticalPanel title="Configurations" icon={<Settings size={14} />}>
        <Box sx={{ p: 1 }}>
          <Stack spacing={1.5}>
            <Box>
              <Typography sx={{ fontSize: '0.6rem', color: 'text.secondary', mb: 0.5 }}>STARTING PATH</Typography>
              <Typography sx={{ fontSize: '0.7rem', fontWeight: 700, wordBreak: 'break-all', color: 'text.primary' }}>{data.scan_info.cfg_starting_point_path || '/'}</Typography>
            </Box>
            <Box>
              <Typography sx={{ fontSize: '0.6rem', color: 'text.secondary', mb: 0.5 }}>IMPORTED SUBDOMAINS</Typography>
              {data.scan_info.cfg_imported_subdomains?.length > 0 ? (
                <Stack direction="row" spacing={1} sx={{ alignItems: 'center', flexWrap: 'wrap' }}>
                  {data.scan_info.cfg_imported_subdomains.map((s: string) => <Chip key={s} label={s} size="small" sx={{ height: 18, fontSize: '0.6rem', bgcolor: `${tokens.accent.primary}15`, color: tokens.accent.primary, mb: 0.5 }} />)}
                </Stack>
              ) : <Typography sx={{ fontSize: '0.7rem', color: 'text.disabled' }}>None</Typography>}
            </Box>
            <Box>
              <Typography sx={{ fontSize: '0.6rem', color: 'text.secondary', mb: 0.5 }}>OUT OF SCOPE</Typography>
              {data.scan_info.cfg_out_of_scope_subdomains?.length > 0 ? (
                <Stack direction="row" spacing={1} sx={{ alignItems: 'center', flexWrap: 'wrap' }}>
                  {data.scan_info.cfg_out_of_scope_subdomains.map((s: string) => <Chip key={s} label={s} size="small" sx={{ height: 18, fontSize: '0.6rem', bgcolor: `${tokens.accent.error}15`, color: tokens.accent.error, mb: 0.5 }} />)}
                </Stack>
              ) : <Typography sx={{ fontSize: '0.7rem', color: 'text.disabled' }}>None</Typography>}
            </Box>
          </Stack>
        </Box>
      </TacticalPanel>

      <TacticalPanel title="Timeline" icon={<History size={14} />}>
        <Box sx={{ p: 1, maxHeight: 400, overflow: 'auto' }}>
          {groupedTimeline.length === 0 ? (
            <Typography sx={{ fontSize: '0.65rem', color: 'text.disabled', textAlign: 'center', py: 4 }}>
              NO ACTIVITY LOGS
            </Typography>
          ) : (
            <Stack>
              {groupedTimeline.map((group) => (
                <Box key={group.id}>
                  <Typography sx={{
                    display: 'block',
                    fontSize: '0.55rem',
                    fontWeight: 800,
                    letterSpacing: '0.1em',
                    textTransform: 'uppercase',
                    color: group.type === 'plugin' ? tokens.accent.primary : 'text.secondary',
                    mt: 1.5,
                    mb: 0.5,
                    px: 1,
                  }}>
                    {group.label}
                  </Typography>
                  <Box sx={{ position: 'relative' }}>
                    {group.activities.map((activity) => (
                      <TimelineItem
                        key={activity.task_uid ?? activity.id}
                        activity={activity}
                        onClick={() => handleTimelineItemClick(activity)}
                        onRetry={handleRetryTask}
                        isTerminal={[0, 3].includes(data?.scan_info?.scan_status ?? -1)}
                      />
                    ))}
                  </Box>
                </Box>
              ))}
              {[2, 3, 4].includes(data.scan_info.scan_status) && (
                <TimelineItem
                  activity={{
                    id: 'raw-scan-history',
                    task_uid: null,
                    title: 'Raw Scan History',
                    name: 'raw_scan_history',
                    status: 'SUCCESS',
                    time: new Date().toISOString(),
                    time_started: null,
                    time_ended: null,
                    tier: null,
                    has_commands: true
                  }}
                  onClick={() => handleTimelineItemClick({
                    id: 'raw-scan-history',
                    task_uid: null,
                    title: 'Raw Scan History',
                    name: 'raw_scan_history',
                    status: 'SUCCESS',
                    time: new Date().toISOString(),
                    time_started: null,
                    time_ended: null,
                    tier: null,
                    has_commands: true
                  })}
                />
              )}
            </Stack>
          )}
        </Box>
      </TacticalPanel>

      <TacticalPanel title="Recent Scans" icon={<Activity size={14} />}>
        <Box sx={{ p: 1 }}>
          <Stack spacing={1}>
            {data.recent_scans?.map((scan: any) => (
              <Box
                key={scan.id}
                component={RouterLink}
                to={`/${projectSlug}/scan/detail/${scan.id}`}
                sx={{
                  p: 1.5,
                  borderRadius: 1,
                  bgcolor: scan.id === parseInt(scanId || '0') ? `${tokens.accent.primary}0D` : 'transparent',
                  border: `1px solid ${scan.id === parseInt(scanId || '0') ? `${tokens.accent.primary}33` : (isLight ? tokens.border.subtle : 'rgba(255,255,255,0.05)')}`,
                  textDecoration: 'none',
                  transition: 'all 0.2s',
                  '&:hover': { bgcolor: isLight ? 'rgba(0,0,0,0.02)' : 'rgba(255,255,255,0.03)', borderColor: isLight ? 'rgba(0,0,0,0.1)' : 'rgba(255,255,255,0.1)' }
                }}
              >
                <Stack direction="row" sx={{ justifyContent: 'space-between', alignItems: 'center' }}>
                  <Typography sx={{ fontSize: '0.7rem', fontWeight: 800, color: 'text.primary' }}>{scan.engine_name}</Typography>
                  <SeverityBadge severity={scan.highest_severity === 'critical' ? 4 : scan.highest_severity === 'high' ? 3 : 0} />
                </Stack>
                <Typography sx={{ fontSize: '0.6rem', color: 'text.secondary', mt: 0.5 }}>{scan.completed_ago}</Typography>
              </Box>
            ))}
          </Stack>
        </Box>
      </TacticalPanel>

      <TacticalPanel title="Sub Scan History" icon={<Activity size={14} />}>
        <Box sx={{ p: 1 }}>
          <SubScanWidget subscans={data.subscans} targetName={data.target_info.name} />
        </Box>
      </TacticalPanel>
    </Box>
  );

  const renderHomeContent = () => (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3, width: '100%' }}>
      {/* Row 1: Target Information and HTTP Status Charts (MOVED UP) */}
      <Grid container spacing={2} sx={{ alignItems: 'stretch', width: '100%', m: 0 }}>
        <Grid size={{ xs: 12, md: 6 }} sx={{ display: 'flex' }}>
          <TacticalPanel title="Target Information" icon={<Activity size={14} />} sx={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
            <Box sx={{ p: 2, flex: 1 }}>
              <Tabs value={infoTab} onChange={(_, v) => setInfoTab(v)} sx={{ mb: 2, borderBottom: 1, borderColor: 'divider', minHeight: 32 }}>
                {['Domain Info', 'Whois', 'DNS Records', 'Nameservers', 'History'].map((l) => (
                  <Tab key={l} label={l} sx={{ fontSize: '0.65rem', fontWeight: 900, minHeight: 32, p: 1, color: 'text.secondary', '&.Mui-selected': { color: tokens.accent.primary } }} />
                ))}
              </Tabs>

              {infoTab === 0 && (
                <Grid container spacing={3}>
                  {/* Column 1: ID & Origin */}
                  <Grid size={{ xs: 6 }}>
                    <Stack spacing={2.5}>
                      <Box>
                        <Typography sx={{ fontSize: '0.65rem', color: 'text.disabled', mb: 0.2, textTransform: 'uppercase', letterSpacing: 1 }}>Domain</Typography>
                        <Typography sx={{ fontSize: '0.8rem', fontWeight: 800, color: isLight ? tokens.accent.error : '#ff003c', fontFamily: 'Orbitron', wordBreak: 'break-all' }}>{data.target_info?.name || 'N/A'}</Typography>
                      </Box>
                      <Box>
                        <Typography sx={{ fontSize: '0.65rem', color: 'text.disabled', mb: 0.2, textTransform: 'uppercase', letterSpacing: 1 }}>Dnssec</Typography>
                        <Typography sx={{ fontSize: '0.8rem', fontWeight: 700, color: 'text.primary' }}>{data.domain_info?.dnssec || 'N/A'}</Typography>
                      </Box>
                      <Box>
                        <Typography sx={{ fontSize: '0.65rem', color: 'text.disabled', mb: 0.2, textTransform: 'uppercase', letterSpacing: 1 }}>Geolocation</Typography>
                        <Typography sx={{ fontSize: '0.8rem', fontWeight: 700, color: 'text.primary' }}>{data.domain_info?.geolocation_iso || 'N/A'}</Typography>
                      </Box>
                      <Box>
                        <Typography sx={{ fontSize: '0.65rem', color: 'text.disabled', mb: 0.2, textTransform: 'uppercase', letterSpacing: 1 }}>Created</Typography>
                        <Typography sx={{ fontSize: '0.7rem', color: 'text.primary' }}>{data.domain_info?.created?.split('T')[0] || 'N/A'}</Typography>
                      </Box>
                    </Stack>
                  </Grid>

                  {/* Column 2: Maintenance & Registrar */}
                  <Grid size={{ xs: 6 }}>
                    <Stack spacing={2.5}>
                      <Box>
                        <Typography sx={{ fontSize: '0.65rem', color: 'text.disabled', mb: 0.2, textTransform: 'uppercase', letterSpacing: 1 }}>Updated</Typography>
                        <Typography sx={{ fontSize: '0.7rem', color: 'text.primary' }}>{data.domain_info?.updated?.split('T')[0] || 'N/A'}</Typography>
                      </Box>
                      <Box>
                        <Typography sx={{ fontSize: '0.65rem', color: 'text.disabled', mb: 0.2, textTransform: 'uppercase', letterSpacing: 1 }}>Expires</Typography>
                        <Typography sx={{ fontSize: '0.7rem', color: 'text.primary' }}>{data.domain_info?.expires?.split('T')[0] || 'N/A'}</Typography>
                      </Box>
                      <Box>
                        <Typography sx={{ fontSize: '0.65rem', color: 'text.disabled', mb: 0.2, textTransform: 'uppercase', letterSpacing: 1 }}>Registrar</Typography>
                        <Typography sx={{ fontSize: '0.8rem', fontWeight: 700, color: tokens.accent.primary }}>{data.domain_info?.registrar?.name || 'N/A'}</Typography>
                      </Box>
                    </Stack>
                  </Grid>
                </Grid>
              )}
              {infoTab === 1 && (
                <Box sx={{ maxHeight: 300, overflow: 'auto' }}>
                  {!data.domain_info?.whois_data ? (
                    <Box sx={{ p: 4, textAlign: 'center' }}>
                      <Typography sx={{ fontSize: '0.8rem', color: 'text.secondary', mb: 2 }}>
                        No WHOIS data available for this target.
                      </Typography>
                      <Button
                        size="small"
                        variant="outlined"
                        startIcon={fetchWhois.isPending ? <CircularProgress size={12} /> : <Search size={12} />}
                        disabled={fetchWhois.isPending}
                        onClick={() => fetchWhois.mutate(data.target_info.name)}
                        sx={{
                          color: tokens.accent.primary,
                          borderColor: `${tokens.accent.primary}4D`,
                          fontSize: '0.65rem',
                          fontWeight: 900,
                          '&:hover': {
                            borderColor: tokens.accent.primary,
                            bgcolor: `${tokens.accent.primary}0D`
                          }
                        }}
                      >
                        {fetchWhois.isPending ? 'FETCHING...' : 'FETCH WHOIS DATA'}
                      </Button>
                    </Box>
                  ) : (
                    <Box>
                      <Stack direction="row" sx={{ justifyContent: 'flex-end', mb: 1 }}>
                        <Button
                          size="small"
                          startIcon={fetchWhois.isPending ? <CircularProgress size={10} /> : <RefreshCw size={10} />}
                          disabled={fetchWhois.isPending}
                          onClick={() => fetchWhois.mutate(data.target_info.name)}
                          sx={{ color: 'text.disabled', fontSize: '0.6rem', '&:hover': { color: tokens.accent.primary } }}
                        >
                          Refresh
                        </Button>
                      </Stack>
                      <Typography sx={{ fontSize: '0.7rem', color: 'text.secondary', whiteSpace: 'pre-wrap', fontFamily: 'monospace' }}>
                        {data.domain_info?.whois_data}
                      </Typography>
                    </Box>
                  )}
                </Box>
              )}
              {infoTab === 2 && (
                <Stack spacing={1}>
                  {data.domain_info?.dns_records?.map((r: any, idx: number) => (
                    <Stack key={idx} direction="row" spacing={1} sx={{ alignItems: 'center' }}>
                      <Chip label={r.type?.toUpperCase() ?? 'DNS'} size="small" sx={{ height: 16, fontSize: '0.55rem', fontWeight: 900, bgcolor: `${tokens.accent.primary}15`, color: tokens.accent.primary }} />
                      <Typography sx={{ fontSize: '0.7rem', color: 'text.primary' }}>{r.name} {"->"} {r.value}</Typography>
                    </Stack>
                  ))}
                </Stack>
              )}
              {infoTab === 3 && (
                <Stack spacing={1}>
                  {data.domain_info?.nameservers?.map((ns: string, idx: number) => (
                    <Stack key={idx} direction="row" spacing={1} sx={{ alignItems: 'center' }}>
                      <Globe size={14} color={tokens.accent.primary} />
                      <Typography sx={{ fontSize: '0.7rem', color: 'text.primary' }}>{ns}</Typography>
                    </Stack>
                  ))}
                  {(!data.domain_info?.nameservers || data.domain_info.nameservers.length === 0) && (
                    <Typography sx={{ fontSize: '0.7rem', color: 'text.disabled', p: 1 }}>No nameservers identified</Typography>
                  )}
                </Stack>
              )}
              {infoTab === 4 && (
                <TableContainer sx={{ maxHeight: 300 }}>
                  <Table size="small">
                    <TableHead sx={{ bgcolor: 'action.hover' }}>
                      <TableRow>
                        <TableCell sx={{ color: tokens.accent.primary, fontWeight: 900, fontSize: '0.65rem', borderBottom: `1px solid ${tokens.accent.primary}15` }}>IP ADDRESS</TableCell>
                        <TableCell sx={{ color: tokens.accent.primary, fontWeight: 900, fontSize: '0.65rem', borderBottom: `1px solid ${tokens.accent.primary}15` }}>LOCATION</TableCell>
                        <TableCell sx={{ color: tokens.accent.primary, fontWeight: 900, fontSize: '0.65rem', borderBottom: `1px solid ${tokens.accent.primary}15` }}>OWNER</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {data.domain_info?.historical_ips?.map((ip: any, idx: number) => (
                        <TableRow key={idx}>
                          <TableCell sx={{ color: 'text.primary', fontSize: '0.7rem', borderBottom: 1, borderColor: 'divider' }}>{ip.ip}</TableCell>
                          <TableCell sx={{ color: 'text.primary', fontSize: '0.7rem', borderBottom: 1, borderColor: 'divider' }}>{ip.location}</TableCell>
                          <TableCell sx={{ color: 'text.primary', fontSize: '0.7rem', borderBottom: 1, borderColor: 'divider' }}>{ip.owner}</TableCell>
                        </TableRow>
                      ))}
                      {(!data.domain_info?.historical_ips || data.domain_info.historical_ips.length === 0) && (
                        <TableRow>
                          <TableCell colSpan={3} align="center" sx={{ py: 4, color: 'text.disabled', fontSize: '0.7rem', border: 0 }}>NO HISTORICAL IPS FOUND</TableCell>
                        </TableRow>
                      )}
                    </TableBody>
                  </Table>
                </TableContainer>
              )}
            </Box>
          </TacticalPanel>
        </Grid>
        <Grid size={{ xs: 12, md: 6 }} sx={{ display: 'flex' }}>
          <TacticalPanel title="HTTP Status Breakdown" icon={<Activity size={14} />} sx={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
            <Box sx={{ p: 2, display: 'flex', flexDirection: 'column', justifyContent: 'center', flex: 1 }}>
              <Chart
                options={{
                  chart: { type: 'donut', background: 'transparent' },
                  theme: { mode: isLight ? 'light' : 'dark' as any },
                  labels: (data?.http_status_breakdown || []).slice().sort((a: { http_status: number }, b: { http_status: number }) => a.http_status - b.http_status).map((s: { http_status: number }) => `HTTP ${s.http_status}`),
                  colors: [
                    isLight ? tokens.accent.success : '#00ff62',
                    isLight ? tokens.accent.error : '#ff003c',
                    tokens.accent.primary,
                    isLight ? '#6d28d9' : '#7000ff',
                    isLight ? tokens.accent.warning : '#fffc00',
                    '#ff8000',
                    '#0080ff',
                    '#8000ff'
                  ],
                  stroke: { show: false },
                  dataLabels: { enabled: false },
                  legend: {
                    position: 'right',
                    horizontalAlign: 'left',
                    labels: { colors: isLight ? tokens.text.secondary : 'rgba(255,255,255,0.7)' },
                    itemMargin: { vertical: 2 }
                  },
                  plotOptions: { pie: { donut: { size: '70%' } } }
                }}
                series={(data?.http_status_breakdown || []).slice().sort((a: any, b: any) => a.http_status - b.http_status).map((s: any) => s.count)}
                type="donut"
                width="100%"
                height={300}
              />
            </Box>
          </TacticalPanel>
        </Grid>
      </Grid>

      {/* Row 2: GeoMap (MOVED UP) */}
      <TacticalPanel title="Geographical Distribution" icon={<Globe size={14} />}>
        <Box sx={{ p: 0 }}>
          <GeoMap data={data.asset_countries || []} disableCard={true} />
        </Box>
      </TacticalPanel>

      {/* Row 3: Vulnerability Distribution & Highlights */}
      <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', lg: '1fr 1fr' }, gap: 2, mb: 2, width: '100%' }}>
        <VulnerabilityBreakdown
          counts={{
            critical: data.critical_count,
            high: data.high_count,
            medium: data.medium_count,
            low: data.low_count,
            info: data.info_count,
            unknown: data.unknown_count,
            total: data.vulnerability_count
          }}
          exploitable={data.exploitable_count}
        />
        <VulnHighlights highlights={data.vulnerability_highlights} onVulnClick={handleVulnClick} />
      </Box>

      {/* Row 4: Vulnerability Deep Dive */}
      <Grid container spacing={2} sx={{ mb: 2, width: '100%', m: 0 }}>
        <Grid size={{ xs: 12, md: 6 }}>
          <MostVulnerableSubdomain vulnerabilities={data.vulnerabilities} sx={{ height: '100%' }} />
        </Grid>
        <Grid size={{ xs: 12, md: 6 }}>
          <MostCommonVulnsWidget vulnerabilities={data.vulnerabilities} onVulnClick={handleVulnClick} sx={{ height: '100%' }} />
        </Grid>
      </Grid>

      <VulnerabilityInfoModal
        open={vulnInfoModalOpen}
        onClose={() => setVulnInfoModalOpen(false)}
        vulnerability={selectedVulnForInfo}
      />

      {/* Row 5: Contextual Assets */}
      <Grid container spacing={2} sx={{ mb: 2, width: '100%', m: 0 }}>
        <Grid size={{ xs: 12, md: 6 }}>
          <ImportantSubdomainsWidget subdomains={data.important_subdomains} sx={{ height: '100%' }} />
        </Grid>
        <Grid size={{ xs: 12, md: 6 }}>
          <ReconNotesWidget notes={data.todo_notes} sx={{ height: '100%' }} />
        </Grid>
      </Grid>

      {/* Row 6: Infrastructure & Fingerprinting */}
      <Grid container spacing={2} sx={{ width: '100%', m: 0 }}>
        <Grid size={{ xs: 12, md: 4 }}>
          <IpAddressesWidget subdomains={data.subdomains} sx={{ height: '100%' }} />
        </Grid>
        <Grid size={{ xs: 12, md: 4 }}>
          <DiscoveredPortsWidget ports={data.discovered_ports} sx={{ height: '100%' }} />
        </Grid>
        <Grid size={{ xs: 12, md: 4 }}>
          <DiscoveredTechWidget techs={data.discovered_technologies} sx={{ height: '100%' }} />
        </Grid>
      </Grid>
    </Box>
  );
  const renderBuckets = () => (
    <TacticalPanel title="S3 Buckets Discovered" icon={<Database size={14} />}>
      <TableContainer>
        <Table size="small">
          <TableHead sx={{ bgcolor: 'action.hover' }}>
            <TableRow>
              <TableCell sx={{ color: tokens.accent.primary, fontWeight: 900 }}>BUCKET NAME</TableCell>
              <TableCell sx={{ color: tokens.accent.primary, fontWeight: 900 }}>PUBLIC READ</TableCell>
              <TableCell sx={{ color: tokens.accent.primary, fontWeight: 900 }}>PUBLIC WRITE</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {(data.buckets || []).map((b: any, idx: number) => (
              <TableRow key={idx}>
                <TableCell sx={{ color: 'text.primary', fontWeight: 700 }}>{b.name}</TableCell>
                <TableCell>
                  <Chip label={b.public_read ? 'YES' : 'NO'} size="small" color={b.public_read ? 'error' : 'default'} />
                </TableCell>
                <TableCell>
                  <Chip label={b.public_write ? 'YES' : 'NO'} size="small" color={b.public_write ? 'error' : 'default'} />
                </TableCell>
              </TableRow>
            ))}
            {(!data.buckets || data.buckets.length === 0) && (
              <TableRow>
                <TableCell colSpan={3} align="center" sx={{ py: 4, color: 'text.disabled' }}>NO BUCKETS FOUND</TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>
    </TacticalPanel>
  );


  const renderOSINT = () => (
    <OsintTab data={data} scanId={parseInt(scanId)} />
  );

  const renderLeaks = () => (
    <SecretLeaksTab projectSlug={projectSlug} scanId={parseInt(scanId)} />
  );

  const renderAttackSurface = () => (
    <AttackSurfaceTab projectSlug={projectSlug} scanId={parseInt(scanId)} />
  );

  const renderVisualization = () => (
    <VisualizationTab projectSlug={projectSlug} scanId={parseInt(scanId)} />
  );

  const renderExploits = () => (
    <TacticalPanel title="Potential Exploits & Payloads" icon={<Zap size={14} />}>
      <TableContainer>
        <Table size="small">
          <TableHead sx={{ bgcolor: 'action.hover' }}>
            <TableRow>
              <TableCell sx={{ color: tokens.accent.primary, fontWeight: 900 }}>TARGET</TableCell>
              <TableCell sx={{ color: tokens.accent.primary, fontWeight: 900 }}>EXPLOIT TYPE</TableCell>
              <TableCell sx={{ color: tokens.accent.primary, fontWeight: 900 }}>PAYLOAD</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            <TableRow>
              <TableCell colSpan={3} align="center" sx={{ py: 4, color: 'text.disabled' }}>NO POTENTIAL EXPLOITS IDENTIFIED</TableCell>
            </TableRow>
          </TableBody>
        </Table>
      </TableContainer>
    </TacticalPanel>
  );

  const renderSubdomains = () => (
    <SubdomainsTab projectSlug={projectSlug} scanId={parseInt(scanId)} onTabChange={setActiveTab} />
  );


  const renderEndpoints = () => (
    <EndpointsTab projectSlug={projectSlug} scanId={parseInt(scanId)} matchedGfCounts={data.matched_gf_count} />
  );

  const renderParameters = () => (
    <ParametersTab scanId={parseInt(scanId)} />
  );

  const renderDirectories = () => (
    <DirectoriesTab projectSlug={projectSlug} scanId={parseInt(scanId)} subdomainId={0} subdomainName={data.target_info?.name || ''} targetId={data.target_info?.id || 0} />
  );


  const renderVulnerabilities = () => (
    <TacticalPanel title="VULNERABILITY INTELLIGENCE" icon={<ShieldAlert size={18} color={tokens.accent.primary} />}>
      <PluginComponent
        name="VulnerabilityTable"
        default={VulnerabilityTable}
        projectSlug={projectSlug}
        scanId={parseInt(scanId)}
      />
    </TacticalPanel>
  );

  return (
    <Box sx={{ p: 2 }}>
      {/* Header */}
      <Box sx={{ mb: 3 }}>
        <Stack
          direction={{ xs: 'column', sm: 'row' }}
          sx={{
            justifyContent: 'space-between',
            alignItems: { xs: 'flex-start', sm: 'flex-start' },
            gap: 2
          }}
        >
          <Box sx={{ mt: 0.5 }}>
            <Typography variant="h5" sx={{ display: 'flex', alignItems: 'center', fontWeight: 900, fontFamily: 'Orbitron', color: 'text.primary', letterSpacing: 2 }}>
              SCAN DETAIL
              {data.scan_info?.is_spiderfoot_running && (
                <MuiTooltip title="SpiderFoot OSINT Scan is currently running..." placement="right">
                  <Box component="span" sx={{
                    ml: 2,
                    display: 'inline-flex',
                    alignItems: 'center',
                    color: tokens.accent.primary,
                    '@keyframes spiderPulse': {
                      '0%': { transform: 'scale(1)', opacity: 0.6 },
                      '50%': { transform: 'scale(1.15)', opacity: 1, filter: `drop-shadow(0 0 6px ${tokens.accent.primary})` },
                      '100%': { transform: 'scale(1)', opacity: 0.6 },
                    },
                    animation: 'spiderPulse 2s infinite ease-in-out'
                  }}>
                    <Bug size={20} />
                  </Box>
                </MuiTooltip>
              )}
            </Typography>
            <Typography sx={{ fontSize: '0.7rem', color: 'text.secondary', fontWeight: 600 }}>
              IDENTIFIER: <Box component="span" sx={{
                color: tokens.accent.secondary
                // '@keyframes subtlePulse': {
                //   '0%, 100%': { opacity: 1 },
                //   '50%': { opacity: 0.55 }
                // },
                // animation: 'subtlePulse 3s ease-in-out infinite'
              }}>{scanId}</Box>
              {' | '}
              TARGET: {data.target_info?.id ? (
                <Link
                  component={RouterLink}
                  to={`/${projectSlug}/target/${data.target_info.id}/summary`}
                  sx={{
                    color: tokens.accent.secondary,
                    textDecoration: 'none',
                    animation: 'subtlePulse 3s ease-in-out infinite',
                    animationDelay: '1.5s',
                    '&:hover': {
                      textDecoration: 'underline',
                    }
                  }}
                >
                  {data.target_info.name}
                </Link>
              ) : (
                <Box component="span" sx={{
                  color: tokens.accent.secondary,
                  animation: 'subtlePulse 3s ease-in-out infinite',
                  animationDelay: '1.5s'
                }}>{data.target_info?.name || 'N/A'}</Box>
              )}
            </Typography>
          </Box>
          <Stack spacing={1} sx={{ alignItems: { xs: 'flex-start', sm: 'flex-end' }, width: { xs: '100%', sm: 'auto' } }}>
            <Stack
              direction={{ xs: 'column', md: 'row' }}
              spacing={2}
              sx={{
                alignItems: { xs: 'stretch', md: 'center' },
                width: { xs: '100%', md: 'auto' }
              }}
            >
              <Button
                variant="contained"
                startIcon={<RefreshCw size={16} />}
                onClick={() => setStartScanTargets({ ids: [data.target_info.id], names: [data.target_info.name] })}
                sx={{
                  bgcolor: isLight ? `${tokens.accent.success}1A` : 'rgba(0, 255, 98, 0.1)',
                  color: isLight ? tokens.accent.success : '#00ff62',
                  border: isLight ? `1px solid ${tokens.accent.success}4D` : '1px solid rgba(0, 255, 98, 0.3)',
                  fontFamily: 'Orbitron',
                  fontSize: '0.65rem',
                  fontWeight: 900,
                  px: 2,
                  '&:hover': { bgcolor: isLight ? `${tokens.accent.success}33` : 'rgba(0, 255, 98, 0.2)' }
                }}
              >
                RESCAN
              </Button>
              <Button
                variant="contained"
                startIcon={stopScanMutation.isPending ? <CircularProgress size={16} color="inherit" /> : <AlertTriangle size={16} />}
                onClick={() => stopScanMutation.mutate(parseInt(scanId))}
                disabled={stopScanMutation.isPending || isTerminal}
                sx={{
                  bgcolor: isLight ? `${tokens.accent.error}1A` : 'rgba(255, 0, 60, 0.1)',
                  color: isLight ? tokens.accent.error : '#ff003c',
                  border: isLight ? `1px solid ${tokens.accent.error}4D` : '1px solid rgba(255, 0, 60, 0.3)',
                  fontFamily: 'Orbitron',
                  fontSize: '0.65rem',
                  fontWeight: 900,
                  px: 2,
                  '&:hover': { bgcolor: isLight ? `${tokens.accent.error}33` : 'rgba(255, 0, 60, 0.2)' },
                  '&.Mui-disabled': {
                    color: isLight ? 'rgba(220, 38, 38, 0.45)' : 'rgba(255, 0, 60, 0.45)',
                    borderColor: isLight ? 'rgba(220, 38, 38, 0.18)' : 'rgba(255, 0, 60, 0.18)',
                    bgcolor: isLight ? 'rgba(220, 38, 38, 0.06)' : 'rgba(255, 0, 60, 0.05)',
                  }
                }}
              >
                STOP
              </Button>
              <Button
                variant="contained"
                startIcon={<Brain size={16} />}
                onClick={() => setAiExportModalOpen(true)}
                sx={{
                  bgcolor: isLight ? `${tokens.accent.warning}1A` : 'rgba(255, 193, 7, 0.08)',
                  color: isLight ? '#9a6700' : tokens.accent.warning,
                  border: isLight ? `1px solid ${tokens.accent.warning}4D` : `1px solid ${tokens.accent.warning}4D`,
                  fontFamily: 'Orbitron',
                  fontSize: '0.65rem',
                  fontWeight: 900,
                  px: 2,
                  '&:hover': { bgcolor: isLight ? `${tokens.accent.warning}33` : 'rgba(255, 252, 0, 0.16)' }
                }}
              >
                EXPORT FOR AI
              </Button>
              <Button
                variant="contained"
                startIcon={<FileText size={16} />}
                onClick={() => setReportModalOpen(true)}
                sx={{
                  bgcolor: `${tokens.accent.primary}15`,
                  color: tokens.accent.primary,
                  border: `1px solid ${tokens.accent.primary}4D`,
                  fontFamily: 'Orbitron',
                  fontSize: '0.65rem',
                  fontWeight: 900,
                  px: 2,
                  '&:hover': { bgcolor: `${tokens.accent.primary}33` }
                }}
              >
                GENERATE REPORT
              </Button>
              <Button
                variant="contained"
                component={RouterLink}
                to={`/${projectSlug}/stress_testing/${scanId}`}
                startIcon={<Zap size={16} />}
                sx={{
                  bgcolor: isLight ? `${tokens.accent.secondary}1A` : 'rgba(255, 0, 255, 0.1)',
                  color: tokens.accent.secondary,
                  border: isLight ? `1px solid ${tokens.accent.secondary}4D` : `1px solid ${tokens.accent.secondary}4D`,
                  fontFamily: 'Orbitron',
                  fontSize: '0.65rem',
                  fontWeight: 900,
                  px: 2,
                  '&:hover': { bgcolor: isLight ? `${tokens.accent.secondary}33` : 'rgba(255, 0, 255, 0.2)' }
                }}
              >
                STRESS TEST
              </Button>
            </Stack>
            <Stack direction="row" spacing={1} sx={{ fontSize: '0.65rem', color: 'text.disabled', fontFamily: 'monospace', alignSelf: { xs: 'flex-start', sm: 'flex-end' } }}>
              <span>SCANS</span> / <span>DETAIL</span> / <span style={{ color: tokens.accent.primary }}>{data.target_info.name}</span>
            </Stack>
          </Stack>
        </Stack>
      </Box>

      <PluginCardSlot context={{ type: 'scan', scanId: parseInt(scanId) }} />

      {/* Tab Bar Integration - Now spanning full width at the top */}
      <Box sx={{ mb: 3, borderBottom: 1, borderColor: 'divider', position: 'sticky', top: 0, bgcolor: 'background.paper', zIndex: 10, backdropFilter: 'blur(10px)', borderRadius: '0 0 12px 12px' }}>
        <Tabs
          value={activeTab}
          onChange={(_, v) => setActiveTab(v)}
          variant="scrollable"
          scrollButtons="auto"
          sx={{
            minHeight: 50,
            '& .MuiTabs-indicator': { bgcolor: tokens.accent.primary, height: 3, boxShadow: `0 0 15px ${tokens.accent.primary}` },
            '& .MuiTabs-scrollButtons': { color: tokens.accent.primary }
          }}
        >
          {tabs.map((tab, idx) => (
            <Tab
              key={idx}
              label={
                <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }}>
                  <tab.icon size={14} />
                  <span>{tab.label}</span>
                </Stack>
              }
              sx={{
                fontSize: '0.65rem',
                fontWeight: 900,
                minHeight: 50,
                color: 'text.secondary',
                letterSpacing: 1.5,
                fontFamily: 'Orbitron',
                px: 3,
                '&.Mui-selected': { color: tokens.accent.primary }
              }}
            />
          ))}
        </Tabs>
      </Box>

      {/* MAIN TWO-COLUMN LAYOUT (Sidebar Left, Content Right) */}
      <Box sx={{
        display: 'grid',
        gridTemplateColumns: tabs[activeTab]?.label === 'HOME'
          ? { xs: '1fr', lg: '320px 1fr' }
          : '1fr',
        gap: 3,
        alignItems: 'start',
        width: '100%',
        minWidth: 0
      }}>

        {/* LEFT COLUMN: Scan Metadata & Timeline (Only on HOME tab) */}
        {tabs[activeTab]?.label === 'HOME' && (
          <Box sx={{
            position: { lg: 'sticky' },
            top: 70,
            transition: 'all 0.3s ease',
            minWidth: 0
          }}>
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
              {renderSidebar()}
            </Box>
          </Box>
        )}

        {/* RIGHT COLUMN: Discovery Content */}
        <Box sx={{ minWidth: 0, width: '100%' }}>
          {/* Tab Content Display */}
          <Box sx={{ minHeight: '60vh' }}>
            {tabs[activeTab]?.label === 'HOME' ? (
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>

                {/* Top Row: Discovery Metrics (The 4 KPIs) - Compact Squares */}
                <Box sx={{
                  display: 'grid',
                  gridTemplateColumns: {
                    xs: 'repeat(2, 1fr)',
                    md: 'repeat(4, 1fr)'
                  },
                  gap: 2,
                  width: '100%'
                }}>
                  <KpiCard
                    title="SUBDOMAINS"
                    value={data.subdomain_count}
                    subtitle={`${data.alive_count} ACTIVE`}
                    color={tokens.accent.secondary}
                    icon={Layers}
                    sx={{ height: '100%' }}
                  />
                  <KpiCard
                    title="ENDPOINTS"
                    value={data.endpoint_count}
                    subtitle={`${data.endpoint_alive_count} ALIVE`}
                    color={tokens.accent.secondary}
                    icon={Target}
                    sx={{ height: '100%' }}
                  />
                  <KpiCard
                    title="VULNS"
                    value={data.vulnerability_count}
                    subtitle={`${data.critical_count} CRITICAL`}
                    color={tokens.accent.error}
                    icon={Bug}
                    sx={{ height: '100%' }}
                  />
                  <KpiCard
                    title="OSINT"
                    value={data.secret_leaks_count}
                    subtitle="SENSITIVE DATA"
                    color={tokens.accent.warning}
                    icon={Key}
                    sx={{ height: '100%' }}
                  />
                </Box>

                {/* Discovery Modules (Target Info, etc.) */}
                {renderHomeContent()}
              </Box>
            ) : (
              /* Discovery-Specific Tab Content */
              <Box>
                {tabs[activeTab]?.label === 'SUBDOMAINS' && renderSubdomains()}
                {tabs[activeTab]?.label === 'DIRECTORIES' && renderDirectories()}
                {tabs[activeTab]?.label === 'URLS' && renderEndpoints()}
                {tabs[activeTab]?.label === 'PARAMETERS' && renderParameters()}
                {tabs[activeTab]?.label === 'VULNERABILITIES' && renderVulnerabilities()}
                {tabs[activeTab]?.label === 'EXPOSURES' && (
                  <Box sx={{ p: 2 }}>
                    <ExposureList scan_id={scanId} />
                  </Box>
                )}
                {tabs[activeTab]?.label === 'BUCKETS' && renderBuckets()}
                {tabs[activeTab]?.label === 'SCREENSHOTS' && <ScreenshotsTab projectSlug={projectSlug} scanId={parseInt(scanId)} />}
                {tabs[activeTab]?.label === 'OSINT' && renderOSINT()}
                {tabs[activeTab]?.label === 'LEAKS' && renderLeaks()}
                {tabs[activeTab]?.label === 'ATTACK SURFACE' && renderAttackSurface()}
                {tabs[activeTab]?.label === 'VISUALIZATION' && renderVisualization()}
                {tabs[activeTab]?.label === 'RECON NOTES' && <ReconNotesWidget notes={data.todo_notes} />}
                {tabs[activeTab]?.label === 'ATTACK PATHS' && <AttackPathsTab scanId={parseInt(scanId)} />}
                {tabs[activeTab]?.label === 'EXPLOITS' && renderExploits()}

                {tabs[activeTab]?.isPlugin && tabs[activeTab]?.pluginSlug && tabs[activeTab]?.componentFile && (
                  <PluginComponentLoader
                    pluginSlug={tabs[activeTab].pluginSlug}
                    componentFile={tabs[activeTab].componentFile}
                    scanId={parseInt(scanId)}
                    projectSlug={projectSlug}
                  />
                )}

                {!['HOME', 'SUBDOMAINS', 'DIRECTORIES', 'URLS', 'PARAMETERS', 'VULNERABILITIES', 'EXPOSURES', 'BUCKETS', 'SCREENSHOTS', 'OSINT', 'LEAKS', 'EXPLOITS', 'RECON NOTES', 'ATTACK SURFACE', 'VISUALIZATION', 'ATTACK PATHS'].includes(tabs[activeTab]?.label) && !tabs[activeTab]?.isPlugin && (
                  <Box sx={{ p: 4, textAlign: 'center', border: '1px dashed', borderColor: 'divider', borderRadius: 2 }}>
                    <Typography sx={{ color: 'text.disabled', fontFamily: 'Orbitron', fontSize: '0.8rem' }}>MODULE STAGING AREA: {tabs[activeTab]?.label}</Typography>
                    <Typography sx={{ color: 'text.disabled', fontSize: '0.65rem', mt: 1 }}>SYNCHRONIZING DATA FROM LEGACY INTERFACE...</Typography>
                  </Box>
                )}
              </Box>
            )}
          </Box>
        </Box>
      </Box>
      <ScanReportModal
        open={reportModalOpen}
        onClose={() => setReportModalOpen(false)}
        scanId={parseInt(scanId)}
      />
      <AiExportModal
        open={aiExportModalOpen}
        onClose={() => setAiExportModalOpen(false)}
        projectSlug={projectSlug}
        scanId={parseInt(scanId)}
        targetName={data.target_info.name}
      />

      <TaskOverlay
        open={taskOverlayOpen}
        onClose={() => setTaskOverlayOpen(false)}
        activityId={selectedActivity?.id || null}
        scanId={selectedScanId}
        activityTitle={selectedActivity?.title || (selectedScanId ? 'Raw Scan History' : '')}
      />

      {startScanTargets && (
        <StartScanModal
          open={!!startScanTargets}
          onClose={() => setStartScanTargets(null)}
          domainIds={startScanTargets.ids}
          domainNames={startScanTargets.names}
          projectSlug={projectSlug}
        />
      )}
    </Box>
  );
};
