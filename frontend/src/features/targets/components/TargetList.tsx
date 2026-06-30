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
  Button,
  LinearProgress,
  Tooltip,
  TextField,
  InputAdornment,
  Menu,
  MenuItem,
  ListItemIcon,
  ListItemText,
  Checkbox,
  Select,
  FormControl,
  TablePagination,
  alpha
} from '@mui/material';
import {
  Search,
  MoreVertical,
  Activity,
  ShieldAlert,
  ExternalLink,
  Play,
  Settings,
  Plus,
  Trash2,
  Filter,
  Eye,
  ChevronRight,
  Target,
  Pencil,
  PauseCircle,
  Pause,
} from 'lucide-react';
import { useDomains, useDeleteTargets } from '../api';
import { usePauseScan, useUnpauseScan } from '../../scans/api';
import { useParams, Link } from '@tanstack/react-router';
import { AddTargetModal } from './AddTargetModal';
import { EditTargetModal } from './EditTargetModal';
import { StartScanModal } from '../../scans/components/StartScanModal';
import type { Domain } from '../types';
import type { ExtendedDomain } from './EditTargetModal';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import { useTheme } from '@mui/material/styles';
import { getFieldSx, getMenuPaperSx, getSurfaceSx } from '../../../theme/semanticColors';

const ScanStatusCell: React.FC<{ status?: string, progress?: number }> = ({ status, progress = 0 }) => {
  const { tokens } = useThemeTokens();
  
  if (!status || status === 'NEW') {
    return (
      <Typography variant="caption" sx={{ color: 'text.secondary', fontWeight: 800, textTransform: 'uppercase', letterSpacing: 0.5 }}>
        new
      </Typography>
    );
  }

  if (status === 'NEVER_SCANNED') {
    return (
      <Typography variant="caption" sx={{ color: 'text.secondary', fontWeight: 800, letterSpacing: 0.2 }}>
        Never scanned
      </Typography>
    );
  }

  if (status === 'RUNNING' || status === 'INITITATED') {
    return (
      <Box sx={{ minWidth: 100, display: 'flex', flexDirection: 'column', gap: 0.5 }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Typography 
            variant="caption" 
            sx={{ 
              color: tokens.accent.primary, 
              fontWeight: 800, 
              textTransform: 'uppercase', 
              letterSpacing: 0.5, 
              display: 'flex', 
              alignItems: 'center', 
              gap: 0.5 
            }}
          >
            <Box 
              sx={{ 
                width: 6, 
                height: 6, 
                bgcolor: tokens.accent.primary, 
                borderRadius: '50%', 
                animation: 'pulse 1.5s infinite',
                '@keyframes pulse': {
                  '0%': { transform: 'scale(0.85)', opacity: 0.5 },
                  '50%': { transform: 'scale(1.2)', opacity: 1 },
                  '100%': { transform: 'scale(0.85)', opacity: 0.5 }
                }
              }} 
            />
            {status === 'INITITATED' ? 'starting' : 'running'}
          </Typography>
          <Typography variant="caption" sx={{ color: 'text.primary', fontWeight: 800 }}>{progress}%</Typography>
        </Box>
        <LinearProgress 
          variant="determinate" 
          value={progress} 
          sx={{ 
            height: 4, 
            borderRadius: 2,
            bgcolor: 'action.hover',
            '& .MuiLinearProgress-bar': { bgcolor: tokens.accent.primary }
          }} 
        />
      </Box>
    );
  }

  if (status === 'SUCCESS') {
    return (
      <Typography variant="caption" sx={{ color: tokens.accent.success, fontWeight: 800, textTransform: 'uppercase', letterSpacing: 0.5 }}>
        done
      </Typography>
    );
  }

  if (status === 'FAILED') {
    return (
      <Typography variant="caption" sx={{ color: tokens.accent.error, fontWeight: 800, textTransform: 'uppercase', letterSpacing: 0.5 }}>
        failed
      </Typography>
    );
  }

  if (status === 'ABORTED') {
    return (
      <Typography variant="caption" sx={{ color: 'text.secondary', fontWeight: 800, textTransform: 'uppercase', letterSpacing: 0.5 }}>
        aborted
      </Typography>
    );
  }

  if (status === 'PAUSED') {
    return (
      <Typography variant="caption" sx={{ color: tokens.accent.warning, fontWeight: 800, textTransform: 'uppercase', letterSpacing: 0.5 }}>
        paused
      </Typography>
    );
  }

  return (
    <Typography variant="caption" sx={{ color: 'text.secondary', fontWeight: 800, textTransform: 'uppercase', letterSpacing: 0.5 }}>
      {status.toLowerCase()}
    </Typography>
  );
};

export const TargetList: React.FC = () => {
  const theme = useTheme();
  const { tokens, isLight } = useThemeTokens();
  const headerStyles = {
    color: theme.palette.text.secondary,
    fontWeight: 800,
    fontFamily: 'var(--r3-heading-font)',
    fontSize: '0.75rem',
    letterSpacing: 1,
    borderBottom: `1px solid ${theme.palette.divider}`,
    py: 1.5,
  };
  const { projectSlug = 'default' } = useParams({ strict: false }) as any;
  const { data: domains, isLoading, error } = useDomains(projectSlug);
  const { mutate: deleteTargets } = useDeleteTargets(projectSlug);
  const pauseScanMutation = usePauseScan(projectSlug);
  const unpauseScanMutation = useUnpauseScan(projectSlug);
  
  const [isAddModalOpen, setIsAddModalOpen] = React.useState(false);
  const [editTarget, setEditTarget] = React.useState<ExtendedDomain | null>(null);
  const [startScanTargets, setStartScanTargets] = React.useState<{ ids: number[]; names: string[] } | null>(null);
  const [selectedIds, setSelectedIds] = React.useState<number[]>([]);
  const [resultsPerPage, setResultsPerPage] = React.useState(20);
  const [page, setPage] = React.useState(0);
  const [searchQuery, setSearchQuery] = React.useState('');
  const [anchorEl, setAnchorEl] = React.useState<null | HTMLElement>(null);
  const [activeTarget, setActiveTarget] = React.useState<{ id: number; name: string } | null>(null);

  const handleMenuOpen = (event: React.MouseEvent<HTMLElement>, target: { id: number; name: string }) => {
    setAnchorEl(event.currentTarget);
    setActiveTarget(target);
  };

  const handleMenuClose = () => {
    setAnchorEl(null);
    setActiveTarget(null);
  };

  const sortedDomains = React.useMemo(() => {
    if (!domains) return [];
    return [...domains].sort((a, b) => (b.id || 0) - (a.id || 0));
  }, [domains]);

  const filteredDomains = React.useMemo(() => {
    return sortedDomains.filter(domain =>
      domain.name?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      domain.description?.toLowerCase().includes(searchQuery.toLowerCase())
    );
  }, [sortedDomains, searchQuery]);

  const paginatedDomains = React.useMemo(() => {
    return filteredDomains.slice(page * resultsPerPage, page * resultsPerPage + resultsPerPage);
  }, [filteredDomains, page, resultsPerPage]);

  const handleSelectAll = (event: React.ChangeEvent<HTMLInputElement>) => {
    if (event.target.checked && filteredDomains) {
      setSelectedIds(filteredDomains.map(d => d.id!));
    } else {
      setSelectedIds([]);
    }
  };

  const handleSelectOne = (id: number) => {
    setSelectedIds(prev => 
      prev.includes(id) ? prev.filter(i => i !== id) : [...prev, id]
    );
  };

  const handleDeleteMultiple = () => {
    if (selectedIds.length > 0) {
      if (window.confirm(`Are you sure you want to delete ${selectedIds.length} targets?`)) {
        deleteTargets(selectedIds);
        setSelectedIds([]);
      }
    }
  };

  if (isLoading) return <LinearProgress sx={{ bgcolor: `${tokens.accent.primary}1A`, '& .MuiLinearProgress-bar': { bgcolor: tokens.accent.primary } }} />;

  return (
    <Box sx={{ p: 3 }}>
      {/* Top Breadcrumb Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
        <Typography variant="h5" sx={{ fontFamily: 'var(--r3-heading-font)', fontWeight: 900, color: 'text.primary', letterSpacing: 1 }}>
          TARGETS
        </Typography>
        <Typography variant="caption" sx={{ color: 'text.secondary', fontFamily: 'var(--r3-heading-font)' }}>
          Targets {'>'} <Box component="span" sx={{ color: 'text.secondary' }}>All Targets</Box>
        </Typography>
      </Box>

      {/* Action Bar */}
      <Card sx={{ 
        ...getSurfaceSx(isLight, tokens, theme),
        borderRadius: 2,
        p: 1.5,
        mb: 3,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between'
      }}>
        <Button
          variant="outlined"
          startIcon={<Filter size={18} />}
          sx={{
            borderColor: tokens.accent.primary,
            color: tokens.accent.primary,
            fontFamily: 'Orbitron',
            fontWeight: 800,
            px: 3,
            '&:hover': { borderColor: tokens.accent.primary, bgcolor: alpha(tokens.accent.primary, 0.05) }
          }}
        >
          FILTER
        </Button>

        <Box sx={{ display: 'flex', gap: 1.5 }}>
          <Button
            variant="contained"
            onClick={() => setIsAddModalOpen(true)}
            sx={{
              bgcolor: alpha(tokens.accent.primary, 0.15),
              color: tokens.accent.primary,
              fontFamily: 'Orbitron',
              fontWeight: 700,
              fontSize: '0.75rem',
              '&:hover': { bgcolor: alpha(tokens.accent.primary, 0.25) }
            }}
          >
            Add Targets
          </Button>
          <Button
            variant="contained"
            disabled={selectedIds.length === 0}
            onClick={() => {
              const selectedDomains = domains?.filter(d => selectedIds.includes(d.id!)) || [];
              setStartScanTargets({
                ids: selectedIds,
                names: selectedDomains.map(d => d.name)
              });
            }}
            sx={{
              bgcolor: alpha(tokens.accent.primary, 0.15),
              color: tokens.accent.primary,
              fontFamily: 'Orbitron',
              fontWeight: 700,
              fontSize: '0.75rem',
              '&:hover': { bgcolor: alpha(tokens.accent.primary, 0.25) },
              '&.Mui-disabled': { 
                bgcolor: 'action.hover', 
                color: 'text.disabled' 
              }
            }}
          >
            Scan Multiple Targets
          </Button>
          <Button
            variant="contained"
            onClick={handleDeleteMultiple}
            disabled={selectedIds.length === 0}
            sx={{
              bgcolor: alpha(tokens.accent.error, 0.15),
              color: tokens.accent.error,
              fontFamily: 'Orbitron',
              fontWeight: 700,
              fontSize: '0.75rem',
              '&:hover': { bgcolor: alpha(tokens.accent.error, 0.25) },
              '&.Mui-disabled': { 
                bgcolor: 'action.hover', 
                color: 'text.disabled' 
              }
            }}
          >
            Delete Multiple Targets
          </Button>
        </Box>
      </Card>

      {/* Main Content Card */}
      <Card sx={{ 
        ...getSurfaceSx(isLight, tokens, theme),
        borderRadius: 3,
        overflow: 'hidden'
      }}>
        {/* Table Controls */}
        <Box sx={{ 
          p: 2.5, 
          display: 'flex', 
          justifyContent: 'space-between', 
          alignItems: 'center', 
          bgcolor: 'action.hover',
          borderBottom: `1px solid ${theme.palette.divider}`
        }}>
          <TextField 
            placeholder="Search..."
            variant="outlined"
            size="small"
            value={searchQuery}
            onChange={(e) => {
              setSearchQuery(e.target.value);
              setPage(0);
            }}
            sx={{ 
              width: 280,
              ...getFieldSx(isLight, tokens),
              '& .MuiOutlinedInput-root': { bgcolor: 'action.hover' }
            }}
            slotProps={{
              input: {
                startAdornment: (
                  <InputAdornment position="start">
                    <Search size={16} style={{ color: theme.palette.text.secondary }} />
                  </InputAdornment>
                ),
              }
            }}
          />
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Typography sx={{ color: 'text.secondary', fontSize: '0.75rem', fontFamily: 'Orbitron' }}>Results :</Typography>
            <Select
              value={resultsPerPage}
              onChange={(e) => {
                setResultsPerPage(Number(e.target.value));
                setPage(0);
              }}
              size="small"
              sx={{ 
                color: 'text.primary',
                bgcolor: 'action.hover',
                height: 32,
                fontSize: '0.75rem',
                fontFamily: 'Orbitron',
                '& .MuiOutlinedInput-notchedOutline': { borderColor: tokens.border.subtle }
              }}
            >
              <MenuItem value={10}>10</MenuItem>
              <MenuItem value={20}>20</MenuItem>
              <MenuItem value={50}>50</MenuItem>
              <MenuItem value={100}>100</MenuItem>
            </Select>
          </Box>
        </Box>

        <TableContainer>
          <Table>
            <TableHead sx={{ bgcolor: 'action.hover' }}>
              <TableRow>
                <TableCell padding="checkbox" sx={{ borderBottom: `1px solid ${theme.palette.divider}` }}>
                  <Checkbox 
                    indeterminate={selectedIds.length > 0 && selectedIds.length < (domains?.length || 0)}
                    checked={selectedIds.length > 0 && selectedIds.length === (domains?.length || 0)}
                    onChange={handleSelectAll}
                    sx={{ color: theme.palette.text.secondary, '&.Mui-checked': { color: tokens.accent.primary } }} 
                  />
                </TableCell>
                <TableCell sx={headerStyles}>TARGET</TableCell>
                <TableCell sx={headerStyles}>DESCRIPTION</TableCell>
                <TableCell sx={headerStyles}>ADDED ON</TableCell>
                <TableCell sx={headerStyles}>LAST SCANNED</TableCell>
                <TableCell sx={headerStyles}>SCAN STATUS</TableCell>
                <TableCell sx={{ ...headerStyles, textAlign: 'center' }}>ACTION</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {paginatedDomains.map((domain) => (
                <TableRow 
                  key={domain.id!} 
                  selected={selectedIds.includes(domain.id!)}
                  sx={{ 
                    '&:hover': { bgcolor: 'action.hover' }, 
                    '&.Mui-selected': { bgcolor: alpha(tokens.accent.primary, 0.05) },
                    transition: 'all 0.2s' 
                  }}
                >
                  <TableCell padding="checkbox" sx={{ borderBottom: `1px solid ${theme.palette.divider}` }}>
                    <Checkbox 
                      checked={selectedIds.includes(domain.id!)}
                      onChange={() => handleSelectOne(domain.id!)}
                      sx={{ color: theme.palette.text.secondary, '&.Mui-checked': { color: tokens.accent.primary } }} 
                    />
                  </TableCell>
                  <TableCell sx={{ borderBottom: `1px solid ${theme.palette.divider}` }}>
                    <Box sx={{ display: 'flex', flexDirection: 'column' }}>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Typography variant="body2" sx={{ fontWeight: 800, color: 'text.primary' }}>{domain.name}</Typography>
                      </Box>
                      {domain.most_recent_scan ? (
                        <Typography 
                          variant="caption" 
                          component="a"
                          href={`/${projectSlug}/scan/detail/${domain.most_recent_scan}`}
                          target="_blank"
                          sx={{ 
                            color: tokens.accent.info, 
                            display: 'flex', 
                            alignItems: 'center', 
                            gap: 0.5, 
                            cursor: 'pointer', 
                            mt: 0.5,
                            textDecoration: 'none',
                            '&:hover': { textDecoration: 'underline' }
                          }}
                        >
                          Recent Scan <ExternalLink size={10} />
                        </Typography>
                      ) : (
                        <Typography variant="caption" sx={{ color: 'text.secondary', opacity: 0.5, mt: 0.5 }}>
                          No Recent Scans
                        </Typography>
                      )}
                    </Box>
                  </TableCell>
                  <TableCell sx={{ borderBottom: `1px solid ${theme.palette.divider}` }}>
                    <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                      {domain.organization || 'No Organization'}
                    </Typography>
                  </TableCell>
                  <TableCell sx={{ borderBottom: `1px solid ${theme.palette.divider}` }}>
                    <Chip 
                      label={domain.insert_date_humanized} 
                      size="small"
                      sx={{ 
                        bgcolor: `${tokens.accent.info}26`, 
                        color: tokens.accent.info, 
                        fontWeight: 700,
                        fontSize: '0.65rem',
                        borderRadius: 1,
                        height: 24,
                        border: `1px solid ${tokens.accent.info}4D`
                      }}
                    />
                  </TableCell>
                  <TableCell sx={{ borderBottom: `1px solid ${theme.palette.divider}` }}>
                    <Chip 
                      label={domain.start_scan_date_humanized || 'Never scanned'} 
                      size="small"
                      sx={{ 
                        bgcolor: `${tokens.accent.info}1A`, 
                        color: tokens.accent.info, 
                        fontWeight: 700,
                        fontSize: '0.65rem',
                        borderRadius: 1,
                        height: 24,
                        border: `1px solid ${tokens.accent.info}33`
                      }}
                    />
                  </TableCell>
                  <TableCell sx={{ borderBottom: `1px solid ${theme.palette.divider}` }}>
                    <ScanStatusCell 
                      status={(domain as any).most_recent_scan_status} 
                      progress={(domain as any).most_recent_scan_progress} 
                    />
                  </TableCell>
                  <TableCell sx={{ borderBottom: `1px solid ${theme.palette.divider}`, textAlign: 'right' }}>
                    <Box sx={{ display: 'flex', gap: 1, justifyContent: 'flex-end' }}>
                      <Button
                        size="small"
                        component={Link}
                        to={`/${projectSlug}/target/${domain.id!}/summary`}
                        startIcon={<Target size={14} />}
                        sx={{
                          bgcolor: alpha(tokens.accent.info, 0.05),
                          color: tokens.accent.info,
                          fontFamily: 'Orbitron',
                          fontSize: '0.65rem',
                          fontWeight: 700,
                          border: `1px solid ${alpha(tokens.accent.info, 0.1)}`,
                          '&:hover': { bgcolor: alpha(tokens.accent.info, 0.15) },
                        }}
                      >
                        Target Summary
                      </Button>
                      <Button
                        size="small"
                        startIcon={<Play size={14} />}
                        onClick={() => setStartScanTargets({ ids: [domain.id!], names: [domain.name] })}
                        sx={{
                          bgcolor: alpha(tokens.accent.info, 0.05),
                          color: tokens.accent.info,
                          fontFamily: 'Orbitron',
                          fontSize: '0.65rem',
                          fontWeight: 700,
                          border: `1px solid ${alpha(tokens.accent.info, 0.1)}`,
                          '&:hover': { bgcolor: alpha(tokens.accent.info, 0.15) }
                        }}
                      >
                        Initiate Scan
                      </Button>
                      <IconButton
                        size="small"
                        onClick={() => setEditTarget(domain as ExtendedDomain)}
                        sx={{
                          color: tokens.accent.warning,
                          bgcolor: alpha(tokens.accent.warning, 0.08),
                          borderRadius: 1,
                          '&:hover': { color: tokens.accent.warning, bgcolor: alpha(tokens.accent.warning, 0.16) },
                        }}
                      >
                        <Pencil size={16} />
                      </IconButton>
                      <IconButton
                        size="small"
                        onClick={(e) => handleMenuOpen(e, { id: domain.id!, name: domain.name })}
                        sx={{ color: tokens.accent.info, bgcolor: alpha(tokens.accent.info, 0.08), borderRadius: 1 }}
                      >
                        <MoreVertical size={18} />
                      </IconButton>
                    </Box>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
        <TablePagination
          component="div"
          count={filteredDomains.length}
          page={page}
          onPageChange={(_, newPage) => setPage(newPage)}
          rowsPerPage={resultsPerPage}
          onRowsPerPageChange={(e) => {
            setResultsPerPage(parseInt(e.target.value, 10));
            setPage(0);
          }}
          sx={{
            color: 'text.secondary',
            borderTop: `1px solid ${theme.palette.divider}`,
            '.MuiTablePagination-selectIcon': { color: 'text.secondary' },
            '.MuiTablePagination-actions': { color: 'text.secondary' },
            '.MuiTablePagination-toolbar': { minHeight: 48 }
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
              ...getMenuPaperSx(isLight, theme, tokens),
              borderRadius: 0,
              minWidth: 180,
              '& .MuiMenuItem-root': {
                fontFamily: 'Orbitron',
                fontSize: '0.7rem',
                fontWeight: 700,
                color: theme.palette.text.primary,
                gap: 1.5,
                py: 1.2,
                '&:hover': { bgcolor: alpha(tokens.accent.info, 0.08), color: tokens.accent.info },
                '& svg': { color: tokens.accent.info }
              }
            }
          }
        }}
      >
        <MenuItem onClick={() => {
          if (activeTarget) {
            const domain = domains?.find(d => d.id === activeTarget.id);
            if (domain) setEditTarget(domain as ExtendedDomain);
          }
          handleMenuClose();
        }} sx={{ color: `${tokens.accent.warning} !important`, '& svg': { color: `${tokens.accent.warning} !important` } }}>
          <Pencil size={14} /> EDIT TARGET
        </MenuItem>
        <MenuItem onClick={() => {
          if (activeTarget) {
            setStartScanTargets({ ids: [activeTarget.id], names: [activeTarget.name] });
          }
          handleMenuClose();
        }}>
          <Play size={14} /> INITIATE SCAN
        </MenuItem>
        <MenuItem onClick={() => {
          if (activeTarget) {
            pauseScanMutation.mutate({ target_id: activeTarget.id });
          }
          handleMenuClose();
        }} sx={{ color: `${tokens.accent.warning} !important`, '& svg': { color: `${tokens.accent.warning} !important` } }}>
          <PauseCircle size={14} /> PAUSE ALL SCANS
        </MenuItem>
        <MenuItem onClick={() => {
          if (activeTarget) {
            unpauseScanMutation.mutate({ target_id: activeTarget.id });
          }
          handleMenuClose();
        }} sx={{ color: `${tokens.accent.success} !important`, '& svg': { color: `${tokens.accent.success} !important` } }}>
          <Play size={14} /> RESUME ALL SCANS
        </MenuItem>
        <MenuItem onClick={() => {
          if (activeTarget) {
            if (window.confirm(`Are you sure you want to delete target ${activeTarget.name}?`)) {
              deleteTargets([activeTarget.id]);
            }
          }
          handleMenuClose();
        }} sx={{ color: `${tokens.accent.error} !important`, '& svg': { color: `${tokens.accent.error} !important` } }}>
          <Trash2 size={14} /> DELETE TARGET
        </MenuItem>
      </Menu>

      <AddTargetModal
        open={isAddModalOpen}
        onClose={() => setIsAddModalOpen(false)}
        projectSlug={projectSlug}
      />

      {editTarget && (
        <EditTargetModal
          open={!!editTarget}
          onClose={() => setEditTarget(null)}
          domain={editTarget}
          projectSlug={projectSlug}
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
    </Box>
  );
};
