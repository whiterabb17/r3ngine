import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  Dialog, DialogTitle, DialogContent, DialogActions,
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
  Typography, Button, Box, CircularProgress, LinearProgress, IconButton,
} from '@mui/material';
import { CheckCircle2, XCircle, X } from 'lucide-react';
import { checkProxy, checkProxyBulk } from '../api';
import { useThemeTokens } from '../../../theme/useThemeTokens';

export interface ProxyValidationResult {
  proxy: string;
  status: 'pending' | 'checking' | 'valid' | 'invalid';
}

interface ProxyValidationModalProps {
  open: boolean;
  onClose: () => void;
  onSave: (validProxies: string[]) => void;
  proxyList: string[];
  projectSlug: string;
}

const BATCH_SIZE = 50;

export const ProxyValidationModal: React.FC<ProxyValidationModalProps> = ({
  open, onClose, onSave, proxyList, projectSlug,
}) => {
  const { tokens } = useThemeTokens();
  const [results, setResults] = useState<ProxyValidationResult[]>([]);
  const [isRunning, setIsRunning] = useState(false);
  const [isDone, setIsDone] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  const validCount = results.filter(r => r.status === 'valid').length;
  const invalidCount = results.filter(r => r.status === 'invalid').length;
  const checkedCount = validCount + invalidCount;
  const totalCount = proxyList.length;
  const progress = totalCount > 0 ? Math.round((checkedCount / totalCount) * 100) : 0;

  const runValidation = useCallback(async () => {
    const controller = new AbortController();
    abortRef.current = controller;

    setResults(proxyList.map(p => ({ proxy: p, status: 'pending' })));
    setIsRunning(true);
    setIsDone(false);

    const batches: string[][] = [];
    for (let i = 0; i < proxyList.length; i += BATCH_SIZE) {
      batches.push(proxyList.slice(i, i + BATCH_SIZE));
    }

    setResults(proxyList.map(p => ({ proxy: p, status: 'checking' })));

    try {
      await Promise.all(
        batches.map(async (batch) => {
          if (controller.signal.aborted) return;
          try {
            const res = await checkProxyBulk(projectSlug, batch, controller.signal);
            setResults(prev =>
              prev.map(r => {
                if (batch.includes(r.proxy)) {
                  const isValid = res.results[r.proxy];
                  return { ...r, status: isValid ? 'valid' : 'invalid' };
                }
                return r;
              })
            );
          } catch {
            if (!controller.signal.aborted) {
              setResults(prev =>
                prev.map(r => batch.includes(r.proxy) ? { ...r, status: 'invalid' } : r)
              );
            }
          }
        })
      );
    } catch (err) {
      console.error('Proxy validation error:', err);
    } finally {
      if (!controller.signal.aborted) {
        setIsRunning(false);
        setIsDone(true);
      }
    }
  }, [proxyList, projectSlug]);

  useEffect(() => {
    if (open && proxyList.length > 0) {
      runValidation();
    }
    return () => {
      abortRef.current?.abort();
    };
  }, [open]); // eslint-disable-line react-hooks/exhaustive-deps

  const handleStop = () => {
    abortRef.current?.abort();
    setIsRunning(false);
    setIsDone(true);
  };

  const handleSave = () => {
    onSave(results.filter(r => r.status === 'valid').map(r => r.proxy));
  };

  const handleClose = () => {
    abortRef.current?.abort();
    onClose();
  };

  const statusCell = (status: ProxyValidationResult['status']) => {
    switch (status) {
      case 'pending':
        return (
          <Typography sx={{ color: 'rgba(255,255,255,0.3)', fontFamily: 'Orbitron', fontSize: '0.75rem' }}>
            —
          </Typography>
        );
      case 'checking':
        return <CircularProgress size={16} sx={{ color: tokens.accent.primary }} />;
      case 'valid':
        return (
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
            <CheckCircle2 size={16} color="#00ff62" />
            <Typography sx={{ color: '#00ff62', fontFamily: 'Orbitron', fontSize: '0.75rem', fontWeight: 700 }}>
              VALID
            </Typography>
          </Box>
        );
      case 'invalid':
        return (
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
            <XCircle size={16} color="#ff0055" />
            <Typography sx={{ color: '#ff0055', fontFamily: 'Orbitron', fontSize: '0.75rem', fontWeight: 700 }}>
              FAILED
            </Typography>
          </Box>
        );
    }
  };

  return (
    <Dialog
      open={open}
      onClose={isRunning ? undefined : handleClose}
      maxWidth="md"
      fullWidth
      slotProps={{
        paper: {
          sx: {
            bgcolor: 'background.paper',
            border: `1px solid ${tokens.accent.primary}4D`,
            backdropFilter: 'blur(20px)',
            boxShadow: `0 0 40px ${tokens.accent.primary}1A`,
          },
        },
      }}
    >
      <DialogTitle sx={{ borderBottom: 1, borderColor: 'divider', pb: 2 }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Box>
            <Typography sx={{
              fontFamily: 'Orbitron', fontWeight: 900, color: tokens.accent.primary,
              letterSpacing: 2, fontSize: '1rem',
            }}>
              PROXY VALIDATION
            </Typography>
            <Typography variant="caption" sx={{ color: 'text.secondary', fontFamily: 'Orbitron' }}>
              {isDone
                ? `COMPLETE — ${validCount} / ${totalCount} PROXIES VALID`
                : isRunning
                  ? `CHECKING ${checkedCount} / ${totalCount}...`
                  : 'INITIALIZING...'}
            </Typography>
          </Box>
          {!isRunning && (
            <IconButton onClick={handleClose} size="small" sx={{ color: 'text.secondary' }}>
              <X size={16} />
            </IconButton>
          )}
        </Box>

        <LinearProgress
          variant="determinate"
          value={progress}
          sx={{
            mt: 1.5, height: 4, borderRadius: 2,
            bgcolor: 'action.hover',
            '& .MuiLinearProgress-bar': {
              bgcolor: isDone
                ? (validCount > 0 ? '#00ff62' : '#ff0055')
                : tokens.accent.primary,
              transition: 'background-color 0.3s ease',
            },
          }}
        />
      </DialogTitle>

      <DialogContent
        sx={{
          p: 0,
          maxHeight: 420,
          overflowY: 'auto',
          '&::-webkit-scrollbar': { width: 4 },
          '&::-webkit-scrollbar-track': { bgcolor: 'action.hover' },
          '&::-webkit-scrollbar-thumb': { bgcolor: `${tokens.accent.primary}4D`, borderRadius: 2 },
        }}
      >
        {results.length === 0 ? (
          <Box sx={{ p: 4, textAlign: 'center' }}>
            <CircularProgress sx={{ color: tokens.accent.primary }} />
          </Box>
        ) : (
          <TableContainer>
            <Table size="small" stickyHeader>
              <TableHead>
                <TableRow>
                  <TableCell sx={{
                    bgcolor: 'background.paper',
                    borderBottom: 1, borderColor: 'divider',
                    fontFamily: 'Orbitron', fontSize: '0.7rem',
                    color: tokens.accent.primary, fontWeight: 700, letterSpacing: 1,
                  }}>
                    PROXY
                  </TableCell>
                  <TableCell sx={{
                    bgcolor: 'background.paper',
                    borderBottom: 1, borderColor: 'divider',
                    fontFamily: 'Orbitron', fontSize: '0.7rem',
                    color: tokens.accent.primary, fontWeight: 700, letterSpacing: 1,
                    width: 130,
                  }}>
                    STATUS
                  </TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {results.map((entry, idx) => (
                  <TableRow
                    key={idx}
                    sx={{
                      bgcolor: entry.status === 'checking' ? `${tokens.accent.primary}08` : 'transparent',
                      '&:hover': { bgcolor: 'action.hover' },
                    }}
                  >
                    <TableCell sx={{ borderBottom: 1, borderColor: 'divider', py: 0.75 }}>
                      <Typography sx={{
                        fontFamily: 'monospace', fontSize: '0.82rem',
                        color: entry.status === 'valid' ? 'rgba(0,255,98,0.9)'
                          : entry.status === 'invalid' ? 'rgba(255,0,85,0.6)'
                          : entry.status === 'checking' ? 'text.primary'
                          : 'text.disabled',
                      }}>
                        {entry.proxy}
                      </Typography>
                    </TableCell>
                    <TableCell sx={{ borderBottom: 1, borderColor: 'divider', py: 0.75 }}>
                      {statusCell(entry.status)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </DialogContent>

      <DialogActions sx={{
        borderTop: 1, borderColor: 'divider',
        px: 3, py: 2,
        justifyContent: 'space-between',
      }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Box sx={{
            px: 1.5, py: 0.5, borderRadius: 1,
            bgcolor: 'rgba(0,255,98,0.08)',
            border: '1px solid rgba(0,255,98,0.2)',
          }}>
            <Typography sx={{ fontFamily: 'Orbitron', fontSize: '0.75rem', color: '#00ff62', fontWeight: 700 }}>
              {validCount} VALID
            </Typography>
          </Box>
          <Box sx={{
            px: 1.5, py: 0.5, borderRadius: 1,
            bgcolor: 'rgba(255,0,85,0.08)',
            border: '1px solid rgba(255,0,85,0.2)',
          }}>
            <Typography sx={{ fontFamily: 'Orbitron', fontSize: '0.75rem', color: '#ff0055', fontWeight: 700 }}>
              {invalidCount} FAILED
            </Typography>
          </Box>
        </Box>

        <Box sx={{ display: 'flex', gap: 1.5 }}>
          {isRunning && (
            <Button
              variant="outlined"
              onClick={handleStop}
              sx={{
                borderColor: 'rgba(255,165,0,0.5)', color: '#ffa500',
                fontFamily: 'Orbitron', fontSize: '0.75rem', fontWeight: 700,
                '&:hover': { borderColor: '#ffa500', bgcolor: 'rgba(255,165,0,0.05)' },
              }}
            >
              STOP
            </Button>
          )}
          <Button
            variant="outlined"
            onClick={handleClose}
            disabled={isRunning}
            sx={{
              borderColor: 'rgba(255,255,255,0.2)', color: 'rgba(255,255,255,0.5)',
              fontFamily: 'Orbitron', fontSize: '0.75rem', fontWeight: 700,
              '&:hover': { borderColor: 'rgba(255,255,255,0.4)', bgcolor: 'rgba(255,255,255,0.03)' },
            }}
          >
            CANCEL
          </Button>
          <Button
            variant="contained"
            onClick={handleSave}
            disabled={validCount === 0}
            sx={{
              bgcolor: `${tokens.accent.primary}1A`, color: tokens.accent.primary,
              border: 1, borderColor: `${tokens.accent.primary}66`,
              fontFamily: 'Orbitron', fontSize: '0.75rem', fontWeight: 800,
              '&:hover': { bgcolor: `${tokens.accent.primary}33`, boxShadow: `0 0 20px ${tokens.accent.primary}4D` },
              '&.Mui-disabled': {
                color: 'text.disabled',
                borderColor: 'divider',
                bgcolor: 'transparent',
              },
            }}
          >
            SAVE {validCount > 0 ? `${validCount} ` : ''}VALID PROXIES
          </Button>
        </Box>
      </DialogActions>
    </Dialog>
  );
};
