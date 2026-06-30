import React from 'react';
import { 
  Box, 
  Card, 
  CardContent, 
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
  MenuItem
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
  AlertTriangle
} from 'lucide-react';
import { useScans } from '../api';
import { useAppContext } from '../../../context/AppContext';
import { useParams } from '@tanstack/react-router';
import { StartScanModal } from './StartScanModal';
import type { ScanHistory } from '../types';
import { useThemeTokens } from '../../../theme/useThemeTokens';

export const ScanList: React.FC = () => {
  const { tokens, isLight, theme } = useThemeTokens();
  const { projectSlug = 'default' } = useParams({ strict: false }) as any;
  const { data: scans, isLoading } = useScans(projectSlug);
  const [isStartScanModalOpen, setIsStartScanModalOpen] = React.useState(false);
  const [anchorEl, setAnchorEl] = React.useState<null | HTMLElement>(null);
  const [activeScanId, setActiveScanId] = React.useState<number | null>(null);
  const [rescanTarget, setRescanTarget] = React.useState<{ ids: number[]; names: string[] } | null>(null);

  const handleMenuOpen = (event: React.MouseEvent<HTMLElement>, id: number) => {
    setAnchorEl(event.currentTarget);
    setActiveScanId(id);
  };

  const handleMenuClose = () => {
    setAnchorEl(null);
    setActiveScanId(null);
  };

  const getStatusChip = (scan: ScanHistory) => {
    const status = scan.scan_status;
    switch (status) {
      case 2: { // Complete
        const total = scan.total_task_count ?? 0;
        const ok    = scan.successful_task_count ?? 0;
        const label = total > 0 ? `COMPLETE ${ok}/${total}` : 'COMPLETE';
        const color = isLight ? tokens.accent.success : '#00ff62';
        return <Chip label={label} size="small" sx={{ bgcolor: isLight ? `${tokens.accent.success}1A` : 'rgba(0, 255, 98, 0.1)', color: color, border: `1px solid ${color}33`, fontSize: '0.6rem', fontWeight: 900, fontFamily: 'Orbitron' }} icon={<CheckCircle2 size={12} />} />;
      }
      case 1: // Running
        return <Chip label="RUNNING" size="small" sx={{ bgcolor: `${tokens.accent.primary}15`, color: tokens.accent.primary, border: `1px solid ${tokens.accent.primary}33`, fontSize: '0.6rem', fontWeight: 900, fontFamily: 'Orbitron' }} icon={<RefreshCw size={12} className="spin" />} />;
      case 0: { // Failed
        const total = scan.total_task_count ?? 0;
        const ok    = scan.successful_task_count ?? 0;
        const label = total > 0 ? `FAILED ${ok}/${total}` : 'FAILED';
        const color = isLight ? tokens.accent.error : '#ff003c';
        return <Chip label={label} size="small" sx={{ bgcolor: isLight ? `${tokens.accent.error}1A` : 'rgba(255, 0, 60, 0.1)', color: color, border: `1px solid ${color}33`, fontSize: '0.6rem', fontWeight: 900, fontFamily: 'Orbitron' }} icon={<XCircle size={12} />} />;
      }
      case 4: { // Partially Complete
        const warnColor = isLight ? '#d97706' : '#fffc00';
        return <Chip label="PARTIALLY COMPLETE" size="small" sx={{ bgcolor: isLight ? '#d977061A' : 'rgba(255, 252, 0, 0.1)', color: warnColor, border: `1px solid ${warnColor}33`, fontSize: '0.6rem', fontWeight: 900, fontFamily: 'Orbitron' }} icon={<AlertTriangle size={12} />} />;
      }
      default:
        return <Chip label="PENDING" size="small" sx={{ bgcolor: 'action.hover', color: 'text.secondary', border: isLight ? '1px solid rgba(0,0,0,0.08)' : '1px solid rgba(255,255,255,0.1)', fontSize: '0.6rem', fontWeight: 900, fontFamily: 'Orbitron' }} />;
    }
  };

  if (isLoading) return <LinearProgress sx={{ bgcolor: `${tokens.accent.primary}15`, '& .MuiLinearProgress-bar': { bgcolor: tokens.accent.primary } }} />;

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 4 }}>
        <Box>
          <Typography variant="h4" sx={{ 
            fontFamily: 'Orbitron', 
            fontWeight: 900, 
            letterSpacing: 2, 
            color: 'text.primary',
            textShadow: `0 0 20px ${tokens.accent.primary}80`,
            mb: 1
          }}>
            SCAN OPERATIONS
          </Typography>
          <Typography variant="body2" sx={{ color: 'text.secondary', letterSpacing: 1 }}>
            HISTORICAL MISSION LOGS & ACTIVE DEPLOYMENTS
          </Typography>
        </Box>
      </Box>

      <Card sx={{ 
        bgcolor: isLight ? tokens.surface.secondary : 'rgba(10, 10, 20, 0.6)', 
        backdropFilter: 'blur(10px)', 
        border: `1px solid ${tokens.accent.primary}15`,
        borderRadius: 4,
        overflow: 'hidden'
      }}>
        <Box sx={{ p: 2, borderBottom: 1, borderColor: 'divider', display: 'flex', gap: 2 }}>
          <TextField 
            placeholder="Filter operations..."
            variant="outlined"
            size="small"
            sx={{ 
              maxWidth: 400,
              flex: 1,
              '& .MuiOutlinedInput-root': {
                color: 'text.primary',
                bgcolor: isLight ? 'rgba(0,0,0,0.02)' : 'rgba(255,255,255,0.03)',
                '& fieldset': { borderColor: isLight ? 'rgba(0,0,0,0.1)' : 'rgba(255,255,255,0.1)' },
                '&:hover fieldset': { borderColor: `${tokens.accent.primary}4D` },
                '&.Mui-focused fieldset': { borderColor: tokens.accent.primary },
              }
            }}
            slotProps={{
              input: {
                startAdornment: (
                  <InputAdornment position="start">
                    <Search size={16} style={{ color: theme.palette.text.disabled }} />
                  </InputAdornment>
                ),
              }
            }}
          />
        </Box>
        <TableContainer>
          <Table>
            <TableHead sx={{ bgcolor: isLight ? 'rgba(0,0,0,0.02)' : 'rgba(0, 243, 255, 0.03)' }}>
              <TableRow>
                <TableCell sx={{ color: tokens.accent.primary, fontWeight: 800, fontFamily: 'Orbitron', fontSize: '0.75rem', borderBottom: `1px solid ${tokens.accent.primary}15` }}>TARGET / ENGINE</TableCell>
                <TableCell sx={{ color: tokens.accent.primary, fontWeight: 800, fontFamily: 'Orbitron', fontSize: '0.75rem', borderBottom: `1px solid ${tokens.accent.primary}15` }}>PROGRESS</TableCell>
                <TableCell sx={{ color: tokens.accent.primary, fontWeight: 800, fontFamily: 'Orbitron', fontSize: '0.75rem', borderBottom: `1px solid ${tokens.accent.primary}15` }}>RESULTS</TableCell>
                <TableCell sx={{ color: tokens.accent.primary, fontWeight: 800, fontFamily: 'Orbitron', fontSize: '0.75rem', borderBottom: `1px solid ${tokens.accent.primary}15` }}>STATUS</TableCell>
                <TableCell sx={{ color: tokens.accent.primary, fontWeight: 800, fontFamily: 'Orbitron', fontSize: '0.75rem', borderBottom: `1px solid ${tokens.accent.primary}15` }}>TIMELINE</TableCell>
                <TableCell sx={{ color: tokens.accent.primary, fontWeight: 800, fontFamily: 'Orbitron', fontSize: '0.75rem', borderBottom: `1px solid ${tokens.accent.primary}15`, textAlign: 'right' }}>ACTIONS</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {scans?.map((scan) => (
                <TableRow key={scan.id!} sx={{ '&:hover': { bgcolor: 'action.hover' }, transition: 'all 0.2s' }}>
                  <TableCell sx={{ borderBottom: 1, borderColor: 'divider' }}>
                    <a
                      href={`/${projectSlug}/scan/detail/${scan.id!}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      style={{ textDecoration: 'none' }}
                    >
                      <Typography
                        variant="body2"
                        sx={{
                          fontWeight: 700,
                          color: 'text.primary',
                          '&:hover': {
                            color: tokens.accent.primary,
                            textDecoration: 'underline'
                          }
                        }}
                      >
                        {scan.domain?.name || 'N/A'}
                      </Typography>
                    </a>
                    <Typography variant="caption" sx={{ color: `${tokens.accent.primary}99`, fontWeight: 600 }}>{scan.scan_type?.engine_name || 'Standard'}</Typography>
                  </TableCell>
                  <TableCell sx={{ borderBottom: 1, borderColor: 'divider', minWidth: 150 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
                      <LinearProgress 
                        variant="determinate" 
                        value={Number(scan.current_progress || 0)} 
                        sx={{ 
                          flexGrow: 1, 
                          height: 4, 
                          borderRadius: 2,
                          bgcolor: 'action.hover',
                          '& .MuiLinearProgress-bar': {
                            bgcolor: scan.scan_status === -1 ? '#ff003c' : tokens.accent.primary,
                            boxShadow: `0 0 10px ${scan.scan_status === -1 ? 'rgba(255, 0, 60, 0.5)' : `${tokens.accent.primary}80`}`
                          }
                        }} 
                      />
                      <Typography variant="caption" sx={{ fontWeight: 900, color: scan.scan_status === -1 ? '#ff003c' : tokens.accent.primary, width: 35 }}>
                        {Math.round(Number(scan.current_progress || 0))}%
                      </Typography>
                    </Box>
                  </TableCell>
                  <TableCell sx={{ borderBottom: 1, borderColor: 'divider' }}>
                    <Box sx={{ display: 'flex', gap: 1.5 }}>
                      <Tooltip title="Subdomains Found">
                        <Box sx={{ textAlign: 'center' }}>
                          <Typography variant="caption" sx={{ display: 'block', color: 'text.secondary', fontWeight: 800 }}>SUB</Typography>
                          <Typography variant="body2" sx={{ fontWeight: 900, color: 'text.primary' }}>{scan.subdomain_count || 0}</Typography>
                        </Box>
                      </Tooltip>
                      <Tooltip title="Vulnerabilities Detected">
                        <Box sx={{ textAlign: 'center' }}>
                          <Typography variant="caption" sx={{ display: 'block', color: 'text.secondary', fontWeight: 800 }}>VUL</Typography>
                          <Typography variant="body2" sx={{ fontWeight: 900, color: Number(scan.vulnerability_count || 0) > 0 ? tokens.accent.error : 'text.primary' }}>
                            {scan.vulnerability_count || 0}
                          </Typography>
                        </Box>
                      </Tooltip>
                    </Box>
                  </TableCell>
                  <TableCell sx={{ borderBottom: 1, borderColor: 'divider' }}>
                    {getStatusChip(scan)}
                  </TableCell>
                  <TableCell sx={{ borderBottom: 1, borderColor: 'divider' }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                      <Clock size={12} style={{ color: theme.palette.text.secondary }} />
                      <Typography variant="caption" sx={{ color: 'text.secondary' }}>{scan.completed_ago || (scan.scan_status === 1 ? 'Active' : 'N/A')}</Typography>
                    </Box>
                    <Typography variant="caption" sx={{ display: 'block', color: 'text.disabled', fontSize: '0.65rem' }}>
                      Time: {scan.elapsed_time || '0s'}
                    </Typography>
                  </TableCell>
                  <TableCell sx={{ borderBottom: 1, borderColor: 'divider', textAlign: 'right' }}>
                    <Box sx={{ display: 'flex', justifyContent: 'flex-end', gap: 1 }}>
                      <Tooltip title="View Detailed Report">
                        <IconButton 
                          size="small" 
                          component="a"
                          href={`/${projectSlug}/scan/detail/${scan.id!}`}
                          target="_blank"
                          sx={{ color: tokens.accent.primary, '&:hover': { bgcolor: `${tokens.accent.primary}15` } }}
                        >
                          <Eye size={16} />
                        </IconButton>
                      </Tooltip>
                      {scan.scan_status === 1 && (
                        <Tooltip title="Stop Scan">
                          <IconButton size="small" sx={{ color: '#ff003c', '&:hover': { bgcolor: 'rgba(255, 0, 60, 0.1)' } }}>
                            <StopCircle size={16} />
                          </IconButton>
                        </Tooltip>
                      )}
                      <IconButton 
                        size="small" 
                        onClick={(e) => handleMenuOpen(e, scan.id!)}
                        sx={{ color: 'text.disabled', '&:hover': { color: tokens.accent.primary, bgcolor: `${tokens.accent.primary}15` } }}
                      >
                        <MoreVertical size={16} />
                      </IconButton>
                    </Box>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
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
        <MenuItem onClick={() => {
          console.log('RESCAN clicked (ScanList), activeScanId:', activeScanId);
          if (activeScanId) {
            const scan = scans?.find(s => s.id === activeScanId);
            console.log('Found scan (ScanList):', scan);
            if (scan && scan.domain) {
              setRescanTarget({
                ids: [scan.domain.id!],
                names: [scan.domain.name]
              });
            }
          }
          handleMenuClose();
        }}>
          <RefreshCw size={14} /> RESCAN
        </MenuItem>
        <MenuItem onClick={() => {
          if (activeScanId) {
            // handle stop scan if needed
          }
          handleMenuClose();
        }}>
          <StopCircle size={14} /> STOP SCAN
        </MenuItem>
      </Menu>

      {rescanTarget && (
        <StartScanModal 
          open={!!rescanTarget}
          onClose={() => setRescanTarget(null)}
          domainIds={rescanTarget.ids}
          domainNames={rescanTarget.names}
          projectSlug={projectSlug}
        />
      )}
    </Box>
  );
};
