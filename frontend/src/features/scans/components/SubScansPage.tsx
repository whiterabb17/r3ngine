import React, { useState, useMemo } from 'react';
import { useParams, Link as RouterLink } from '@tanstack/react-router';
import { 
  Box, 
  Typography, 
  Button, 
  TextField, 
  InputAdornment, 
  IconButton, 
  Tooltip,
  Chip,
  CircularProgress,
  TablePagination,
  Card
} from '@mui/material';
import { useTheme } from '@mui/material/styles';
import { 
  Search, 
  Trash2, 
  History, 
  ExternalLink, 
  CheckCircle2, 
  XCircle,
  AlertCircle,
  Square,
  Play,
  Filter
} from 'lucide-react';
import { useSubScans, useBulkStopSubScans, useBulkDeleteSubScans } from '../api';
import { useThemeTokens } from '../../../theme/useThemeTokens';

export const SubScansPage: React.FC = () => {
  const theme = useTheme();
  const { tokens, isLight } = useThemeTokens();
  const { projectSlug = 'default' } = useParams({ strict: false }) as any;
  const { data, isLoading, isError } = useSubScans(projectSlug);
  const stopMutation = useBulkStopSubScans(projectSlug);
  const deleteMutation = useBulkDeleteSubScans(projectSlug);

  const [searchQuery, setSearchQuery] = useState('');
  const [selectedIds, setSelectedIds] = useState<number[]>([]);
  
  // Pagination State
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(10);

  const filteredData = useMemo(() => {
    if (!data) return [];
    return data.filter(scan => 
      scan.subdomain_name?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      scan.type?.toLowerCase().includes(searchQuery.toLowerCase())
    );
  }, [data, searchQuery]);

  const paginatedData = useMemo(() => {
    const startIndex = page * rowsPerPage;
    return filteredData.slice(startIndex, startIndex + rowsPerPage);
  }, [filteredData, page, rowsPerPage]);

  const handlePageChange = (_: unknown, newPage: number) => {
    setPage(newPage);
  };

  const handleRowsPerPageChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };

  const handleSelectAll = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.checked) {
      setSelectedIds(filteredData.map(s => s.id!));
    } else {
      setSelectedIds([]);
    }
  };

  const handleSelectOne = (id: number) => {
    setSelectedIds(prev => 
      prev.includes(id) ? prev.filter(i => i !== id) : [...prev, id]
    );
  };

  const handleBulkStop = () => {
    if (window.confirm(`Stop ${selectedIds.length} running subscans?`)) {
      stopMutation.mutate(selectedIds, {
        onSuccess: () => setSelectedIds([])
      });
    }
  };

  const handleBulkDelete = () => {
    if (window.confirm(`Delete ${selectedIds.length} subscan records?`)) {
      deleteMutation.mutate(selectedIds, {
        onSuccess: () => setSelectedIds([])
      });
    }
  };

  if (isError) {
    return (
      <Box sx={{ p: 4, textAlign: 'center', color: '#ff003c' }}>
        <AlertCircle size={48} />
        <Typography variant="h6" sx={{ mt: 2, fontFamily: 'Orbitron' }}>DATABASE ACCESS DENIED: SUBSCAN REGISTRY FAILURE</Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      {/* Header Section */}
      <Box sx={{ 
        display: 'flex', 
        justifyContent: 'space-between', 
        alignItems: 'center', 
        mb: 4,
        background: 'linear-gradient(90deg, rgba(188, 19, 254, 0.05) 0%, transparent 100%)',
        p: 2,
        borderRadius: 1,
        borderLeft: `4px solid ${tokens.accent.secondary}`
      }}>
        <Box>
          <Typography variant="h4" sx={{ 
            fontFamily: 'Orbitron', 
            fontWeight: 900, 
            letterSpacing: 4,
            textShadow: '0 0 15px rgba(188, 19, 254, 0.3)',
            display: 'flex',
            alignItems: 'center',
            gap: 2,
            color: tokens.accent.secondary
          }}>
            <History size={32} />
            SUBSCAN HISTORY
          </Typography>
          <Typography variant="caption" sx={{ color: 'text.secondary', letterSpacing: 2 }}>
            TACTICAL EXECUTION LOGS
          </Typography>
        </Box>

        <Box sx={{ display: 'flex', gap: 2 }}>
          <Button
            variant="outlined"
            startIcon={<Filter size={18} />}
            sx={{ 
              fontFamily: 'Orbitron',
              color: tokens.accent.primary,
              borderColor: tokens.accent.primary,
              '&:hover': { borderColor: tokens.accent.primary, bgcolor: `${tokens.accent.primary}0D` }
            }}
          >
            FILTER
          </Button>
          {selectedIds.length > 0 && (
            <>
              <Button
                variant="contained"
                onClick={handleBulkStop}
                sx={{ 
                  fontFamily: 'Orbitron',
                  fontWeight: 700,
                  bgcolor: 'rgba(255, 183, 77, 0.1)',
                  border: '1px solid #ffb74d',
                  color: '#ffb74d',
                  '&:hover': { bgcolor: 'rgba(255, 183, 77, 0.2)' }
                }}
              >
                STOP {selectedIds.length}
              </Button>
              <Button
                variant="contained"
                color="error"
                startIcon={<Trash2 size={18} />}
                onClick={handleBulkDelete}
                sx={{ 
                  fontFamily: 'Orbitron',
                  fontWeight: 700,
                  bgcolor: 'rgba(255, 0, 60, 0.1)',
                  border: '1px solid #ff003c',
                  color: '#ff003c',
                  '&:hover': { bgcolor: 'rgba(255, 0, 60, 0.2)' }
                }}
              >
                DELETE {selectedIds.length}
              </Button>
            </>
          )}
        </Box>
      </Box>

      {/* Search Bar */}
      <Box sx={{ 
        mb: 3, 
        p: 2, 
        bgcolor: 'rgba(0,0,0,0.3)', 
        borderRadius: 1, 
        border: 1, borderColor: 'divider'
      }}>
        <TextField
          placeholder="SEARCH TACTICAL OPERATIONS..."
          variant="standard"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          sx={{ 
            width: 400,
            '& .MuiInputBase-root': {
              fontFamily: 'monospace',
              color: tokens.accent.secondary,
              fontSize: '14px',
              '&:before, &:after': { borderBottomColor: 'rgba(188, 19, 254, 0.3)' }
            }
          }}
          slotProps={{
            input: {
              startAdornment: (
                <InputAdornment position="start">
                  <Search size={18} color={tokens.accent.secondary} />
                </InputAdornment>
              ),
            }
          }}
        />
      </Box>

      {/* Main Table */}
      <Card sx={{ 
        bgcolor: isLight ? tokens.surface.secondary : 'rgba(10, 15, 25, 0.7)', 
        borderRadius: 1, 
        border: `1px solid ${isLight ? theme.palette.divider : 'rgba(188, 19, 254, 0.1)'}`,
        overflow: 'hidden',
        position: 'relative'
      }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
          <thead>
            <tr style={{ borderBottom: `2px solid ${isLight ? theme.palette.divider : 'rgba(188, 19, 254, 0.2)'}`, background: isLight ? 'rgba(0,0,0,0.02)' : 'rgba(188, 19, 254, 0.03)' }}>
              <th style={{ padding: '16px' }}>
                <input 
                  type="checkbox" 
                  checked={selectedIds.length === filteredData.length && filteredData.length > 0}
                  onChange={handleSelectAll}
                  style={{ accentColor: tokens.accent.secondary }}
                />
              </th>
              <th style={{ padding: '16px', color: tokens.accent.secondary, fontFamily: 'Orbitron', fontSize: '12px', letterSpacing: 2 }}>SCANNED SUBDOMAIN</th>
              <th style={{ padding: '16px', color: tokens.accent.secondary, fontFamily: 'Orbitron', fontSize: '12px', letterSpacing: 2 }}>TASK</th>
              <th style={{ padding: '16px', color: tokens.accent.secondary, fontFamily: 'Orbitron', fontSize: '12px', letterSpacing: 2 }}>ENGINE</th>
              <th style={{ padding: '16px', color: tokens.accent.secondary, fontFamily: 'Orbitron', fontSize: '12px', letterSpacing: 2 }}>SCAN STARTED</th>
              <th style={{ padding: '16px', color: tokens.accent.secondary, fontFamily: 'Orbitron', fontSize: '12px', letterSpacing: 2, textAlign: 'center' }}>STATUS</th>
              <th style={{ padding: '16px', color: tokens.accent.secondary, fontFamily: 'Orbitron', fontSize: '12px', letterSpacing: 2, textAlign: 'center' }}>ACTION</th>
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              <tr>
                <td colSpan={7} style={{ padding: '100px', textAlign: 'center' }}>
                  <CircularProgress size={40} sx={{ color: tokens.accent.secondary }} />
                  <Typography sx={{ mt: 2, fontFamily: 'monospace', color: tokens.accent.secondary }}>RETRIEVING SUBSCAN TELEMETRY...</Typography>
                </td>
              </tr>
            ) : paginatedData.length === 0 ? (
              <tr>
                <td colSpan={7} style={{ padding: '60px', textAlign: 'center' }}>
                  <Typography sx={{ fontFamily: 'monospace', color: 'text.disabled' }}>NO SUBSCAN DATA DETECTED</Typography>
                </td>
              </tr>
            ) : (
              paginatedData.map((scan) => (
                <tr 
                  key={scan.id!} 
                  style={{ 
                    borderBottom: 1, borderColor: 'divider',
                    transition: 'background 0.2s',
                  }}
                  onMouseEnter={(e) => (e.currentTarget.style.background = isLight ? 'rgba(0, 0, 0, 0.01)' : 'rgba(188, 19, 254, 0.02)')}
                  onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
                >
                  <td style={{ padding: '12px 16px' }}>
                    <input 
                      type="checkbox" 
                      checked={selectedIds.includes(scan.id!)}
                      onChange={() => handleSelectOne(scan.id!)}
                      style={{ accentColor: tokens.accent.secondary }}
                    />
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    <Typography sx={{ color: 'text.primary', fontWeight: 600, fontSize: '13px' }}>{scan.subdomain_name}</Typography>
                    <Typography sx={{ color: 'text.secondary', fontSize: '11px' }}>{scan.subdomain_name?.split('.').slice(-2).join('.') || ''}</Typography>
                    <Box sx={{ mt: 0.5, display: 'flex', alignItems: 'center', gap: 0.5 }}>
                      <Typography sx={{ color: tokens.accent.primary, fontSize: '10px', display: 'flex', alignItems: 'center', gap: 0.5, cursor: 'pointer' }}>
                        Recent Scan <ExternalLink size={10} />
                      </Typography>
                    </Box>
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    <Chip 
                      label={scan.type} 
                      size="small" 
                      sx={{ 
                        bgcolor: 'rgba(188, 19, 254, 0.1)', 
                        color: tokens.accent.secondary, 
                        border: '1px solid rgba(188, 19, 254, 0.3)',
                        fontSize: '10px',
                        fontFamily: 'monospace',
                        fontWeight: 700
                      }} 
                    />
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    <Chip 
                      label={scan.engine} 
                      size="small" 
                      sx={{ 
                        bgcolor: `${tokens.accent.primary}15`, 
                        color: tokens.accent.primary, 
                        border: `1px solid ${tokens.accent.primary}4D`,
                        fontSize: '10px',
                        fontFamily: 'monospace',
                        fontWeight: 700
                      }} 
                    />
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    <Typography sx={{ color: 'text.primary', fontSize: '12px' }}>{scan.completed_ago}</Typography>
                    <Typography sx={{ color: 'text.secondary', fontSize: '10px', fontFamily: 'monospace' }}>
                      ({new Date(scan.start_scan_date).toLocaleString()})
                    </Typography>
                  </td>
                  <td style={{ padding: '12px 16px', textAlign: 'center' }}>
                    <Chip 
                      label={scan.status === 2 ? 'SUCCESSFUL' : scan.status === 3 ? 'ABORTED' : scan.status === 0 ? 'FAILED' : 'RUNNING'} 
                      size="small" 
                      sx={{ 
                        bgcolor: scan.status === 2 ? 'rgba(0, 255, 157, 0.1)' : scan.status === 3 ? 'rgba(255, 0, 60, 0.1)' : scan.status === 0 ? 'rgba(255, 0, 60, 0.1)' : 'rgba(255, 183, 77, 0.1)', 
                        color: scan.status === 2 ? '#00ff9d' : scan.status === 3 ? '#ff003c' : scan.status === 0 ? '#ff003c' : '#ffb74d', 
                        border: '1px solid',
                        borderColor: scan.status === 2 ? 'rgba(0, 255, 157, 0.3)' : scan.status === 3 ? 'rgba(255, 0, 60, 0.3)' : scan.status === 0 ? 'rgba(255, 0, 60, 0.3)' : 'rgba(255, 183, 77, 0.3)',
                        fontSize: '10px',
                        fontWeight: 900,
                        letterSpacing: 1
                      }} 
                    />
                  </td>
                  <td style={{ padding: '12px 16px', textAlign: 'center' }}>
                    <Button
                      variant="contained"
                      size="small"
                      component={RouterLink}
                      to={`/${projectSlug}/scan/detail/${scan.scan_history}`}
                      sx={{ 
                        fontSize: '10px', 
                        fontFamily: 'Orbitron',
                        bgcolor: `${tokens.accent.primary}15`,
                        color: tokens.accent.primary,
                        border: `1px solid ${tokens.accent.primary}`,
                        '&:hover': { bgcolor: `${tokens.accent.primary}33` }
                      }}
                    >
                      VIEW RESULTS
                    </Button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>

        {/* Pagination Section */}
        <TablePagination
          component="div"
          count={filteredData.length}
          page={page}
          onPageChange={handlePageChange}
          rowsPerPage={rowsPerPage}
          onRowsPerPageChange={handleRowsPerPageChange}
          sx={{
            color: tokens.accent.secondary,
            fontFamily: 'monospace',
            borderTop: `1px solid ${theme.palette.divider}`,
            '& .MuiTablePagination-selectIcon': { color: tokens.accent.secondary },
            '& .MuiTablePagination-actions': { color: tokens.accent.secondary },
            '& .MuiTablePagination-select': { fontFamily: 'monospace' },
            '& .MuiTablePagination-displayedRows': { fontFamily: 'monospace' },
          }}
        />
      </Card>

      {/* Footer Info */}
      <Box sx={{ mt: 2, display: 'flex', justifyContent: 'space-between', px: 1 }}>
        <Typography variant="caption" sx={{ color: 'text.disabled', fontFamily: 'monospace' }}>
          TOTAL RECORDS: {filteredData.length}
        </Typography>
        <Box sx={{ display: 'flex', gap: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
            <Box sx={{ width: 8, height: 8, borderRadius: '50%', bgcolor: '#00ff9d' }} />
            <Typography variant="caption" sx={{ color: 'text.secondary' }}>SUCCESSFUL</Typography>
          </Box>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
            <Box sx={{ width: 8, height: 8, borderRadius: '50%', bgcolor: '#ffb74d' }} />
            <Typography variant="caption" sx={{ color: 'text.secondary' }}>RUNNING</Typography>
          </Box>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
            <Box sx={{ width: 8, height: 8, borderRadius: '50%', bgcolor: '#ff003c' }} />
            <Typography variant="caption" sx={{ color: 'text.secondary' }}>ABORTED</Typography>
          </Box>
        </Box>
      </Box>
    </Box>
  );
};
