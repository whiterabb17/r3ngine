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
  Paper,
  Button,
  Chip,
  TextField,
  InputAdornment,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Pagination,
  Stack,
  useTheme,
  CircularProgress
} from '@mui/material';
import { useParams } from '@tanstack/react-router';
import { Search, CheckCircle, XCircle, AlertTriangle, ShieldCheck } from 'lucide-react';
import { useVulnerabilityQueue, useVerifyVulnerability, useRejectVulnerability } from '../api';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import { TacticalPanel } from '../../../components/TacticalPanel';
import { getSeverityColor } from '../../../theme/semanticColors';

export const VerificationQueue: React.FC = () => {
  const { tokens } = useThemeTokens();
  const { projectSlug } = useParams({ strict: false }) as { projectSlug?: string };
  const theme = useTheme();
  const isLight = theme.palette.mode === 'light';

  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [rejectingVulnId, setRejectingVulnId] = useState<number | null>(null);
  const [rejectReason, setRejectReason] = useState('');

  const pageSize = 10;

  const { data, isLoading, refetch } = useVulnerabilityQueue(
    projectSlug || '',
    page,
    search,
    pageSize
  );

  const verifyMutation = useVerifyVulnerability();
  const rejectMutation = useRejectVulnerability();

  if (!projectSlug) {
    return (
      <Box sx={{ p: 4, textAlign: 'center' }}>
        <Typography color="error">Project context missing.</Typography>
      </Box>
    );
  }

  const handleVerify = async (id: number) => {
    await verifyMutation.mutateAsync(id);
    refetch();
  };

  const handleOpenReject = (id: number) => {
    setRejectingVulnId(id);
    setRejectReason('');
  };

  const handleConfirmReject = async () => {
    if (rejectingVulnId && rejectReason.trim()) {
      await rejectMutation.mutateAsync({ id: rejectingVulnId, reason: rejectReason });
      setRejectingVulnId(null);
      setRejectReason('');
      refetch();
    }
  };



  return (
    <Box sx={{ p: 4 }}>
      <Box sx={{ mb: 4 }}>
        <Typography
          variant="h4"
          sx={{
            fontFamily: 'Orbitron',
            fontWeight: 900,
            letterSpacing: 2,
            color: 'text.primary',
            textShadow: `0 0 20px ${tokens.accent.primary}80`,
            mb: 1
          }}
        >
          VERIFICATION QUEUE
        </Typography>
        <Typography variant="body2" sx={{ color: 'text.secondary', letterSpacing: 1 }}>
          PROJECT: {projectSlug.toUpperCase()} | PENDING ANALYST REVIEW
        </Typography>
      </Box>

      <TacticalPanel
        title="Verification Backlog"
        icon={<ShieldCheck size={18} color={tokens.accent.primary} />}
      >
        <Box sx={{ p: 2 }}>
          {/* Search Bar */}
          <Box sx={{ mb: 3 }}>
            <TextField
              placeholder="Search pending findings..."
              size="small"
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setPage(1);
              }}
              slotProps={{
                input: {
                  startAdornment: (
                    <InputAdornment position="start">
                      <Search size={16} color="gray" />
                    </InputAdornment>
                  )
                }
              }}
              sx={{
                width: 300,
                '& .MuiOutlinedInput-root': {
                  bgcolor: isLight ? 'rgba(0,0,0,0.02)' : 'rgba(255,255,255,0.02)',
                  borderColor: isLight ? 'rgba(0,0,0,0.1)' : 'rgba(255,255,255,0.1)',
                  '&:hover fieldset': {
                    borderColor: tokens.accent.primary
                  },
                  '&.Mui-focused fieldset': {
                    borderColor: tokens.accent.primary
                  }
                }
              }}
            />
          </Box>

          {/* Table */}
          {isLoading ? (
            <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
              <CircularProgress size={24} sx={{ color: tokens.accent.primary }} />
            </Box>
          ) : !data?.results || data.results.length === 0 ? (
            <Box sx={{ p: 4, textAlign: 'center' }}>
              <Typography sx={{ color: 'text.secondary' }}>
                All findings cleared. Queue is empty.
              </Typography>
            </Box>
          ) : (
            <TableContainer component={Paper} sx={{ bgcolor: 'transparent', boxShadow: 'none' }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ borderBottom: `2px solid ${isLight ? 'rgba(0,0,0,0.08)' : 'rgba(255,255,255,0.08)'}` }}>
                    <TableCell sx={{ fontWeight: 800 }}>Vulnerability</TableCell>
                    <TableCell sx={{ fontWeight: 800 }}>Severity</TableCell>
                    <TableCell sx={{ fontWeight: 800 }}>Confidence</TableCell>
                    <TableCell sx={{ fontWeight: 800 }}>Validation Status</TableCell>
                    <TableCell sx={{ fontWeight: 800 }}>Target URL</TableCell>
                    <TableCell sx={{ fontWeight: 800, textAlign: 'right' }}>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {data.results.map((vuln) => (
                    <TableRow
                      key={vuln.id}
                      sx={{
                        '&:hover': {
                          bgcolor: isLight ? 'rgba(0,0,0,0.01)' : 'rgba(255,255,255,0.01)'
                        },
                        borderBottom: `1px solid ${isLight ? 'rgba(0,0,0,0.04)' : 'rgba(255,255,255,0.04)'}`
                      }}
                    >
                      <TableCell sx={{ fontWeight: 600 }}>{vuln.name}</TableCell>
                      <TableCell>
                        <Chip
                          label={(vuln.severity || 'Unknown').toUpperCase()}
                          size="small"
                          sx={{
                            bgcolor: `${getSeverityColor(vuln.severity || 'info', tokens)}1A`,
                            color: getSeverityColor(vuln.severity || 'info', tokens),
                            border: `1px solid ${getSeverityColor(vuln.severity || 'info', tokens)}44`,
                            fontSize: '0.65rem',
                            fontWeight: 900,
                            fontFamily: 'Orbitron',
                            height: 20
                          }}
                        />
                      </TableCell>
                      <TableCell>
                        <Typography sx={{ fontSize: '0.75rem', fontWeight: 600 }}>
                          {vuln.validation_confidence !== null && vuln.validation_confidence !== undefined
                            ? `${Math.round(vuln.validation_confidence * 100)}%`
                            : '0%'}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={(vuln.validation_status || 'new').toUpperCase()}
                          size="small"
                          sx={{
                            bgcolor: vuln.validation_status === 'needs_review' ? `${tokens.accent.warning}1A` : `${tokens.accent.primary}1A`,
                            color: vuln.validation_status === 'needs_review' ? tokens.accent.warning : tokens.accent.primary,
                            border: `1px solid ${vuln.validation_status === 'needs_review' ? tokens.accent.warning : tokens.accent.primary}44`,
                            fontSize: '0.6rem',
                            fontWeight: 900,
                            fontFamily: 'Orbitron',
                            height: 18
                          }}
                        />
                      </TableCell>
                      <TableCell sx={{ fontSize: '0.75rem', fontFamily: 'monospace' }}>
                        {vuln.http_url || 'N/A'}
                      </TableCell>
                      <TableCell sx={{ textAlign: 'right' }}>
                        <Stack direction="row" spacing={1} sx={{ justifyContent: 'flex-end' }}>
                          <Button
                            variant="outlined"
                            color="success"
                            size="small"
                            onClick={() => vuln.id !== undefined && handleVerify(vuln.id)}
                            startIcon={<CheckCircle size={14} />}
                            sx={{
                              borderColor: `${tokens.accent.success}44`,
                              '&:hover': {
                                borderColor: tokens.accent.success,
                                bgcolor: `${tokens.accent.success}08`
                              }
                            }}
                          >
                            Verify
                          </Button>
                          <Button
                            variant="outlined"
                            color="error"
                            size="small"
                            onClick={() => vuln.id !== undefined && handleOpenReject(vuln.id)}
                            startIcon={<XCircle size={14} />}
                            sx={{
                              borderColor: `${tokens.accent.error}44`,
                              '&:hover': {
                                borderColor: tokens.accent.error,
                                bgcolor: `${tokens.accent.error}08`
                              }
                            }}
                          >
                            Reject
                          </Button>
                        </Stack>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}

          {/* Pagination */}
          {data && data.count > pageSize && (
            <Box sx={{ mt: 3, display: 'flex', justifyContent: 'center' }}>
              <Pagination
                count={Math.ceil(data.count / pageSize)}
                page={page}
                onChange={(_, val) => setPage(val)}
                color="primary"
                size="small"
              />
            </Box>
          )}
        </Box>
      </TacticalPanel>

      {/* Reject Modal */}
      <Dialog
        open={rejectingVulnId !== null}
        onClose={() => setRejectingVulnId(null)}
        slotProps={{
          paper: {
            sx: {
              bgcolor: isLight ? '#ffffff' : '#0f172a',
              border: `1px solid ${isLight ? 'rgba(0,0,0,0.1)' : 'rgba(255,255,255,0.1)'}`
            }
          }
        }}
      >
        <DialogTitle sx={{ fontFamily: 'Orbitron', fontWeight: 900, display: 'flex', alignItems: 'center', gap: 1 }}>
          <AlertTriangle color={tokens.accent.error} size={20} />
          REJECT FINDING
        </DialogTitle>
        <DialogContent>
          <Typography variant="body2" sx={{ mb: 2, color: 'text.secondary' }}>
            Please provide a justification reason for marking this finding as a false positive.
          </Typography>
          <TextField
            autoFocus
            multiline
            rows={3}
            fullWidth
            placeholder="e.g. Host header injection is not exploitable / fallback behavior."
            value={rejectReason}
            onChange={(e) => setRejectReason(e.target.value)}
            sx={{
              '& .MuiOutlinedInput-root': {
                '& fieldset': {
                  borderColor: isLight ? 'rgba(0,0,0,0.1)' : 'rgba(255,255,255,0.1)'
                },
                '&:hover fieldset': {
                  borderColor: tokens.accent.primary
                },
                '&.Mui-focused fieldset': {
                  borderColor: tokens.accent.primary
                }
              }
            }}
          />
        </DialogContent>
        <DialogActions sx={{ p: 2 }}>
          <Button onClick={() => setRejectingVulnId(null)} color="inherit">
            Cancel
          </Button>
          <Button
            onClick={handleConfirmReject}
            color="error"
            variant="contained"
            disabled={!rejectReason.trim()}
          >
            Confirm Reject
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};
