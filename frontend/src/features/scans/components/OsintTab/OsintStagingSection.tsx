import React, { useState, useMemo } from 'react';
import type { SelectChangeEvent } from '@mui/material';
import {
  Box,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
  Tooltip,
  TextField,
  InputAdornment,
  Checkbox,
  Button,
  Stack,
  CircularProgress,
  Collapse,
  Alert,
  Pagination,
  Select,
  MenuItem,
  FormControl
} from '@mui/material';
import { 
  Search, 
  Trash2, 
  Check, 
  Filter, 
  ChevronDown, 
  ChevronUp, 
  Database,
  ExternalLink,
  ShieldCheck,
  AlertCircle,
  X
} from 'lucide-react';

import { TacticalPanel } from '../../../../components/TacticalPanel';
import { 
  useOsintStaging, 
  useBulkDiscardOsint, 
  useBulkPromoteOsint
} from '../../api';
import type { OsintStaging } from '../../types';
import { useThemeTokens } from '../../../../theme/useThemeTokens';
import { StagingTypeBadge } from './StagingTypeBadge';
import { StagingMetadataPanel } from './StagingMetadataPanel';

const stripAnsi = (str: string) => {
  if (!str) return '';
  return str.replace(/[\u001b\u009b][[()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nqry=><]/g, '').replace(/\[0m/g, '');
};

interface OsintStagingSectionProps {
  scanId: number;
}

export const OsintStagingSection: React.FC<OsintStagingSectionProps> = ({ scanId }) => {
  const { tokens } = useThemeTokens();
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);
  const [rowsPerPage, setRowsPerPage] = useState(10);
  const [selected, setSelected] = useState<number[]>([]);
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [typeFilter, setTypeFilter] = useState<string>('');

  const { data, isLoading, refetch } = useOsintStaging({
    scan_id: scanId,
    search: search,
    page: page,
    osint_type: typeFilter || undefined
  });

  const discardMutation = useBulkDiscardOsint();
  const promoteMutation = useBulkPromoteOsint();

  const paginatedData = useMemo(() => {
    if (!data?.results) return [];
    
    let resultsToPaginate = data.results;
    if (data.results.length > rowsPerPage) {
      const startIndex = (page - 1) * rowsPerPage;
      resultsToPaginate = data.results.slice(startIndex, startIndex + rowsPerPage);
    }
    
    return resultsToPaginate.map((item: OsintStaging) => ({
      ...item,
      content: stripAnsi(item.content || '')
    }));
  }, [data?.results, page, rowsPerPage]);

  const handleSelectAll = (event: React.ChangeEvent<HTMLInputElement>) => {
    if (event.target.checked && data) {
      setSelected(paginatedData.map((item: OsintStaging) => item.id));
    } else {
      setSelected([]);
    }
  };

  const handleSelectOne = (id: number) => {
    if (selected.includes(id)) {
      setSelected(selected.filter(i => i !== id));
    } else {
      setSelected([...selected, id]);
    }
  };

  const handleTypeFilterChange = (event: SelectChangeEvent) => {
    setTypeFilter(event.target.value);
    setPage(1);
  };

  const handleBulkDiscard = async () => {
    if (window.confirm(`Are you sure you want to discard ${selected.length} items?`)) {
      await discardMutation.mutateAsync(selected);
      setSelected([]);
      refetch();
    }
  };

  const handleIndividualDiscard = async (id: number) => {
    await discardMutation.mutateAsync([id]);
    setSelected(selected.filter(i => i !== id));
    refetch();
  };

  const handleBulkPromote = async () => {
    if (window.confirm(`Promote ${selected.length} items to primary tables?`)) {
      await promoteMutation.mutateAsync(selected);
      setSelected([]);
      refetch();
    }
  };

  const handleIndividualPromote = async (id: number) => {
    await promoteMutation.mutateAsync([id]);
    setSelected(selected.filter(i => i !== id));
    refetch();
  };

  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 80) return '#00ff62';
    if (confidence >= 60) return tokens.accent.primary;
    return '#fffc00';
  };

  return (
    <TacticalPanel 
      title="OSINT STAGING (PENDING VALIDATION)" 
      icon={<Database size={18} />}
      headerAction={
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <TextField
            size="small"
            placeholder="Search OSINT..."
            value={search}
            onChange={(e) => {
                setSearch(e.target.value);
                setPage(1);
            }}
            slotProps={{
              input: {
                startAdornment: (
                  <InputAdornment position="start">
                    <Search size={14} color="rgba(255,255,255,0.4)" />
                  </InputAdornment>
                ),
                endAdornment: search && (
                  <InputAdornment position="end">
                    <IconButton size="small" onClick={() => setSearch('')}>
                      <X size={14} />
                    </IconButton>
                  </InputAdornment>
                ),
                sx: {
                  fontSize: '0.75rem',
                  bgcolor: 'rgba(255,255,255,0.03)',
                  border: 1, borderColor: 'divider',
                  '&:hover': { border: '1px solid rgba(255,255,255,0.2)' }
                }
              }
            }}
            sx={{ width: 250 }}
          />
          <FormControl size="small" sx={{ minWidth: 130 }}>
            <Select
              displayEmpty
              value={typeFilter}
              onChange={handleTypeFilterChange}
              sx={{
                fontSize: '0.72rem',
                bgcolor: 'rgba(255,255,255,0.03)',
                border: 1, borderColor: 'divider',
                '& .MuiSelect-select': { py: 0.75 },
              }}
            >
              <MenuItem value=""><em>All Types</em></MenuItem>
              {['SSL', 'DNS', 'Email', 'Employee', 'Phone', 'Social', 'IP', 'Port',
                'Tech', 'OS', 'Leak', 'Crypto', 'Hosting', 'Subdomain'].map(t => (
                <MenuItem key={t} value={t} sx={{ fontSize: '0.72rem' }}>{t}</MenuItem>
              ))}
            </Select>
          </FormControl>
          {selected.length > 0 && (
            <Stack direction="row" spacing={1}>
              <Button
                size="small"
                variant="outlined"
                color="success"
                startIcon={<Check size={14} />}
                onClick={handleBulkPromote}
                sx={{ 
                  fontFamily: 'Orbitron', 
                  fontSize: '0.65rem', 
                  fontWeight: 900,
                  bgcolor: 'rgba(0, 255, 98, 0.05)',
                  border: '1px solid #00ff6240',
                  '&:hover': { bgcolor: 'rgba(0, 255, 98, 0.1)', border: '1px solid #00ff62' }
                }}
              >
                VALIDATE {selected.length} ITEMS
              </Button>
              <Button
                size="small"
                variant="outlined"
                color="error"
                startIcon={<Trash2 size={14} />}
                onClick={handleBulkDiscard}
                sx={{ 
                  fontFamily: 'Orbitron', 
                  fontSize: '0.65rem', 
                  fontWeight: 900,
                  bgcolor: 'rgba(255, 0, 60, 0.05)',
                  border: '1px solid #ff003c40',
                  '&:hover': { bgcolor: 'rgba(255, 0, 60, 0.1)', border: '1px solid #ff003c' }
                }}
              >
                DISCARD {selected.length} ITEMS
              </Button>
            </Stack>
          )}
        </Box>
      }
    >
      <TableContainer sx={{ minHeight: 400 }}>
        {isLoading ? (
          <Box sx={{ display: 'flex', justifyContent: 'center', py: 8 }}>
            <CircularProgress size={24} color="info" />
          </Box>
        ) : (
          <>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ '& th': { borderBottom: '2px solid rgba(255,255,255,0.05)', py: 1.5 } }}>
                  <TableCell padding="checkbox">
                    <Checkbox
                      size="small"
                      indeterminate={selected.length > 0 && selected.length < paginatedData.length}
                      checked={paginatedData.length > 0 && paginatedData.every((item: OsintStaging) => selected.includes(item.id))}
                      onChange={handleSelectAll}
                      sx={{ color: 'text.disabled', '&.Mui-checked': { color: tokens.accent.primary } }}
                    />
                  </TableCell>
                  <TableCell sx={{ color: 'text.secondary', fontWeight: 'bold', fontSize: '0.65rem' }}>TYPE</TableCell>
                  <TableCell sx={{ color: 'text.secondary', fontWeight: 'bold', fontSize: '0.65rem' }}>CONTENT</TableCell>
                  <TableCell sx={{ color: 'text.secondary', fontWeight: 'bold', fontSize: '0.65rem' }}>SOURCE</TableCell>
                  <TableCell sx={{ color: 'text.secondary', fontWeight: 'bold', fontSize: '0.65rem' }}>CONFIDENCE</TableCell>
                  <TableCell align="right" sx={{ color: 'text.secondary', fontWeight: 'bold', fontSize: '0.65rem' }}>ACTIONS</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {paginatedData.map((item: OsintStaging) => (
                  <React.Fragment key={item.id}>
                    <TableRow 
                      hover 
                      sx={{ 
                        '& td': { borderBottom: '1px solid rgba(255,255,255,0.03)' },
                        bgcolor: expandedId === item.id ? 'rgba(0, 243, 255, 0.02)' : 'transparent'
                      }}
                    >
                      <TableCell padding="checkbox">
                        <Checkbox
                          size="small"
                          checked={selected.includes(item.id)}
                          onChange={() => handleSelectOne(item.id)}
                          sx={{ color: 'text.disabled', '&.Mui-checked': { color: tokens.accent.primary } }}
                        />
                      </TableCell>
                      <TableCell>
                        <StagingTypeBadge osintType={item.osint_type} />
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.75rem', maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {item.content}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="caption" sx={{ color: 'text.secondary', fontFamily: 'monospace' }}>
                          {item.source}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <Box 
                            sx={{ 
                              width: 30, 
                              height: 4, 
                              bgcolor: 'action.hover', 
                              borderRadius: 1,
                              overflow: 'hidden'
                            }}
                          >
                            <Box 
                              sx={{ 
                                width: `${item.confidence}%`, 
                                height: '100%', 
                                bgcolor: getConfidenceColor(item.confidence) 
                              }} 
                            />
                          </Box>
                          <Typography sx={{ fontSize: '0.7rem', fontWeight: 900, color: getConfidenceColor(item.confidence) }}>
                            {item.confidence}%
                          </Typography>
                        </Box>
                      </TableCell>
                      <TableCell align="right">
                        <Stack direction="row" sx={{ justifyContent: 'flex-end', gap: 0.5 }}>
                          <Tooltip title="Validate / Promote">
                            <IconButton 
                              size="small" 
                              onClick={() => handleIndividualPromote(item.id)}
                              sx={{ color: 'success.main', opacity: 0.7, '&:hover': { opacity: 1 } }}
                            >
                              <Check size={14} />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="View Metadata">
                            <IconButton 
                              size="small" 
                              onClick={() => setExpandedId(expandedId === item.id ? null : item.id)}
                              sx={{ color: 'info.main' }}
                            >
                              {expandedId === item.id ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Discard">
                            <IconButton 
                              size="small" 
                              onClick={() => handleIndividualDiscard(item.id)}
                              sx={{ color: 'error.main', opacity: 0.7, '&:hover': { opacity: 1 } }}
                            >
                              <Trash2 size={14} />
                            </IconButton>
                          </Tooltip>
                        </Stack>
                      </TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell colSpan={6} sx={{ p: 0, border: 'none' }}>
                        <Collapse in={expandedId === item.id} timeout="auto" unmountOnExit>
                          <StagingMetadataPanel item={item} onPromote={handleIndividualPromote} />
                        </Collapse>
                      </TableCell>
                    </TableRow>
                  </React.Fragment>
                ))}
                {data?.results?.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={6} align="center" sx={{ py: 8 }}>
                      <Typography sx={{ color: 'text.disabled', fontSize: '0.8rem', fontStyle: 'italic' }}>
                        No staging items found for this scan.
                      </Typography>
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mt: 2, px: 1, pb: 2 }}>
              <Box sx={{ color: 'rgba(0, 243, 255, 0.5)', fontSize: '0.78rem', fontFamily: 'monospace', minWidth: 160 }}>
                {data?.count
                  ? `${(page - 1) * rowsPerPage + 1}–${Math.min(page * rowsPerPage, data.count)} of ${data.count}`
                  : '0 results'}
              </Box>

              <Pagination
                count={Math.ceil((data?.count || 0) / rowsPerPage)}
                page={page}
                onChange={(_: React.ChangeEvent<unknown>, p: number) => setPage(p)}
                shape="rounded"
                sx={{
                  '& .MuiPaginationItem-root': {
                    color: 'rgba(0, 243, 255, 0.6)',
                    borderColor: 'rgba(0, 243, 255, 0.2)',
                    fontFamily: 'monospace',
                    fontSize: '0.8rem',
                    '&.Mui-selected': {
                      bgcolor: 'rgba(0, 243, 255, 0.2)',
                      color: '#00f3ff',
                      borderColor: '#00f3ff',
                    },
                    '&:hover': {
                      bgcolor: 'rgba(0, 243, 255, 0.1)',
                      borderColor: 'rgba(0, 243, 255, 0.4)',
                    }
                  }
                }}
              />

              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, minWidth: 160, justifyContent: 'flex-end' }}>
                <Box sx={{ color: 'rgba(0, 243, 255, 0.4)', fontSize: '0.75rem', fontFamily: 'monospace', whiteSpace: 'nowrap' }}>
                  per page
                </Box>
                <FormControl size="small" variant="outlined" sx={{ minWidth: 80 }}>
                  <Select
                    value={rowsPerPage}
                    onChange={(e) => {
                      setRowsPerPage(Number(e.target.value));
                      setPage(1);
                    }}
                    sx={{
                      color: '#00f3ff',
                      bgcolor: 'rgba(0, 243, 255, 0.05)',
                      fontFamily: 'monospace',
                      fontSize: '0.8rem',
                      '& .MuiOutlinedInput-notchedOutline': { borderColor: 'rgba(0, 243, 255, 0.2)' },
                      '&:hover .MuiOutlinedInput-notchedOutline': { borderColor: 'rgba(0, 243, 255, 0.4)' },
                      '&.Mui-focused .MuiOutlinedInput-notchedOutline': { borderColor: '#00f3ff' },
                      '& .MuiSvgIcon-root': { color: '#00f3ff' },
                    }}
                  >
                    <MenuItem value={10}>10</MenuItem>
                    <MenuItem value={25}>25</MenuItem>
                    <MenuItem value={50}>50</MenuItem>
                    <MenuItem value={100}>100</MenuItem>
                  </Select>
                </FormControl>
              </Box>
            </Box>
          </>
        )}
      </TableContainer>
    </TacticalPanel>
  );
};
