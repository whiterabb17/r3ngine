import React, { useEffect, useRef } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Box,
  Typography,
  IconButton,
  useTheme,
  CircularProgress
} from '@mui/material';
import { X, Terminal } from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import axios from 'axios';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import { getDialogPaperSx } from '../../../theme/semanticColors';

interface ExtractAuthModalProps {
  open: boolean;
  onClose: () => void;
  url: string;
  workflowId: string | null;
  status: 'idle' | 'extracting' | 'completed' | 'error';
  onComplete?: (status: 'completed' | 'error') => void;
}

const fetchAuthLogs = async (workflowId: string): Promise<string[]> => {
  const { data } = await axios.get(`/api/action/directory-file/auth-logs/?workflow_id=${workflowId}`);
  return (data.logs ?? []) as string[];
};

// Returns true when the log stream has reached a terminal state.
const isTerminalLogs = (logs: string[]) =>
  logs.some(l => l.includes('[COMPLETE]') || l.includes('[ERROR]'));

// 3-minute timeout — lets the user close if Redis log writes silently failed.
const POLL_TIMEOUT_MS = 3 * 60 * 1000;

export const ExtractAuthModal: React.FC<ExtractAuthModalProps> = ({
  open,
  onClose,
  url,
  workflowId,
  status: initialStatus,
  onComplete,
}) => {
  const { tokens } = useThemeTokens();
  const theme = useTheme();
  const isLight = tokens.mode === 'light';
  const logsEndRef = useRef<HTMLDivElement>(null);
  const timeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const [internalStatus, setInternalStatus] = React.useState<'idle' | 'extracting' | 'completed' | 'error'>(initialStatus);
  const [timedOut, setTimedOut] = React.useState(false);

  // Sync when the parent resets state (new extraction or prop-driven error).
  // Guarded: once we've locally completed/errored, don't revert to 'extracting'.
  React.useEffect(() => {
    if (initialStatus !== 'extracting') {
      setInternalStatus(initialStatus);
    } else if (internalStatus === 'idle') {
      setInternalStatus('extracting');
    }
    // Reset timeout flag on each new workflow run.
    if (workflowId) setTimedOut(false);
  }, [initialStatus, workflowId]); // eslint-disable-line react-hooks/exhaustive-deps

  // Start a safety-valve timeout once we have a workflowId and are extracting.
  useEffect(() => {
    if (workflowId && open && internalStatus === 'extracting') {
      timeoutRef.current = setTimeout(() => setTimedOut(true), POLL_TIMEOUT_MS);
    }
    return () => {
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
        timeoutRef.current = null;
      }
    };
  }, [workflowId, open]); // eslint-disable-line react-hooks/exhaustive-deps

  // Poll logs from Redis stream.  Stop as soon as data contains a terminal marker
  // so that the interval is driven by the query's own data, not external React state.
  const { data: logs = [] } = useQuery<string[]>({
    queryKey: ['auth-logs', workflowId],
    queryFn: () => fetchAuthLogs(workflowId as string),
    enabled: !!workflowId && open,
    refetchInterval: (_query) => {
      const current = (_query.state.data as string[] | undefined) ?? [];
      return isTerminalLogs(current) ? false : 1000;
    },
  });

  // Derive completion from the full log list — not just the last entry — to
  // handle the case where an INFO line follows the first [COMPLETE] marker.
  useEffect(() => {
    if (logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
    if (logs.length > 0 && internalStatus === 'extracting') {
      if (logs.some(l => l.includes('[COMPLETE]'))) {
        setInternalStatus('completed');
        onComplete?.('completed');
      } else if (logs.some(l => l.includes('[ERROR]'))) {
        setInternalStatus('error');
        onComplete?.('error');
      }
    }
  }, [logs, internalStatus, onComplete]);

  const canClose = internalStatus !== 'extracting' || timedOut;

  return (
    <Dialog
      open={open}
      onClose={canClose ? onClose : undefined}
      maxWidth="md"
      fullWidth
      slotProps={{
        paper: {
          sx: {
            ...getDialogPaperSx(isLight, theme, tokens),
            height: '60vh',
            display: 'flex',
            flexDirection: 'column'
          }
        }
      }}
    >
      <DialogTitle sx={{
        color: tokens.accent.primary,
        fontFamily: 'Orbitron',
        fontSize: '0.9rem',
        letterSpacing: 2,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between'
      }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Terminal size={18} />
          Auth Extraction
        </Box>
        {canClose && (
          <IconButton onClick={onClose} size="small" sx={{ color: tokens.text.secondary }}>
            <X size={18} />
          </IconButton>
        )}
      </DialogTitle>
      <DialogContent sx={{ flex: 1, display: 'flex', flexDirection: 'column', p: 0 }}>
        <Box sx={{
          p: 2,
          borderBottom: '1px solid',
          borderColor: 'divider',
          bgcolor: tokens.surface.elevated
        }}>
          <Typography variant="body2" sx={{ color: tokens.text.secondary }}>
            Target: <Typography component="span" sx={{ color: tokens.text.primary, fontFamily: 'monospace' }}>{url}</Typography>
          </Typography>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mt: 1 }}>
            <Typography variant="body2" sx={{ color: tokens.text.secondary }}>
              Status:
            </Typography>
            {internalStatus === 'extracting' && !timedOut && (
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, color: tokens.accent.primary }}>
                <CircularProgress size={12} thickness={5} sx={{ color: 'inherit' }} />
                <Typography variant="caption" sx={{ fontWeight: 600 }}>Extracting...</Typography>
              </Box>
            )}
            {internalStatus === 'extracting' && timedOut && (
              <Typography variant="caption" sx={{ color: '#ffbb33' }}>Timed out — no log data received</Typography>
            )}
            {internalStatus === 'completed' && <Typography variant="caption" sx={{ color: '#00C851' }}>Completed</Typography>}
            {internalStatus === 'error' && <Typography variant="caption" sx={{ color: '#ff4444' }}>Failed</Typography>}
          </Box>
        </Box>

        <Box sx={{
          flex: 1,
          bgcolor: isLight ? '#1e1e1e' : '#000000',
          color: '#00ff00',
          fontFamily: 'monospace',
          p: 2,
          overflowY: 'auto',
          fontSize: '0.85rem',
          lineHeight: 1.5
        }}>
          {logs.length === 0 && internalStatus === 'extracting' && !timedOut && (
            <Typography variant="body2" sx={{ color: '#888' }}>Initializing...</Typography>
          )}
          {logs.length === 0 && timedOut && (
            <Typography variant="body2" sx={{ color: '#888' }}>
              No log data was received. The extraction may have completed without writing logs (check the Auth Candidates tab), or an error occurred on the backend.
            </Typography>
          )}
          {logs.map((log: string, idx: number) => {
            let color = '#00ff00';
            if (log.includes('[ERROR]')) color = '#ff4444';
            if (log.includes('[WARNING]')) color = '#ffbb33';
            if (log.includes('[INFO]')) color = '#33b5e5';
            if (log.includes('[COMPLETE]')) color = '#00C851';

            return (
              <Box key={idx} sx={{ color }}>
                {log}
              </Box>
            );
          })}
          <div ref={logsEndRef} />
        </Box>
      </DialogContent>
      <DialogActions sx={{ p: 2, borderTop: '1px solid', borderColor: 'divider' }}>
        <Button
          onClick={onClose}
          disabled={!canClose}
          sx={{ color: tokens.text.secondary }}
        >
          {!canClose ? 'Please Wait' : 'Close'}
        </Button>
      </DialogActions>
    </Dialog>
  );
};
