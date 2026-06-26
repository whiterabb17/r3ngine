import React, { useState } from 'react';
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
  TablePagination
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

interface OsintStagingSectionProps {
  scanId: number;
}

export const OsintStagingSection: React.FC<OsintStagingSectionProps> = ({ scanId }) => {
  const { tokens } = useThemeTokens();
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(10);
  const [selected, setSelected] = useState<number[]>([]);
  const [expandedId, setExpandedId] = useState<number | null>(null);

  const { data, isLoading, refetch } = useOsintStaging({ 
    scan_id: scanId, 
    search: search,
    page: page + 1 
  });

  const discardMutation = useBulkDiscardOsint();
  const promoteMutation = useBulkPromoteOsint();

  const handleSelectAll = (event: React.ChangeEvent<HTMLInputElement>) => {
    if (event.target.checked && data) {
      setSelected(data.results.map((item: OsintStaging) => item.id));
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
                setPage(0);
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
                      indeterminate={selected.length > 0 && selected.length < (data?.results?.length || 0)}
                      checked={(data?.results?.length || 0) > 0 && selected.length === (data?.results?.length || 0)}
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
                {data?.results?.map((item: OsintStaging) => (
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
            <TablePagination
              component="div"
              count={data?.count || 0}
              page={page}
              onPageChange={(_, newPage) => setPage(newPage)}
              rowsPerPage={rowsPerPage}
              onRowsPerPageChange={(e) => {
                setRowsPerPage(parseInt(e.target.value, 10));
                setPage(0);
              }}
              sx={{
                borderTop: '1px solid rgba(255,255,255,0.05)',
                color: 'rgba(255,255,255,0.6)',
                '& .MuiTablePagination-select': { color: 'text.primary' },
                '& .MuiIconButton-root': { color: tokens.accent.primary }
              }}
            />
          </>
        )}
      </TableContainer>
    </TacticalPanel>
  );
};
