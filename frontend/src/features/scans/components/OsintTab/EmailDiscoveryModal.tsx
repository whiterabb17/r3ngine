import React, { useEffect, useRef, useCallback } from 'react';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import CircularProgress from '@mui/material/CircularProgress';
import Collapse from '@mui/material/Collapse';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import Divider from '@mui/material/Divider';
import Typography from '@mui/material/Typography';
import { CheckCircle, XCircle, AlertCircle, ChevronDown, ChevronUp } from 'lucide-react';
import { useThemeTokens } from '../../../../theme/useThemeTokens';
import {
  useEmailDiscoveryStore,
  type ToolKey,
  type ToolStatus,
} from '../../../../store/emailDiscoveryStore';
import { useStartEmailDiscovery, useStopEmailDiscovery } from '../../api';

interface EmailDiscoveryModalProps {
  open: boolean;
  onClose: () => void;
  scanId: number;
  onComplete: () => void;
}

const TOOL_LABELS: Record<ToolKey, string> = {
  hunter:    'Hunter.io',
  harvester: 'theHarvester',
  phonebook: 'Phonebook.cz',
  pattern:   'Pattern Inference',
  crawled:   'Crawled URLs',
};

const TOOL_ORDER: ToolKey[] = ['hunter', 'harvester', 'phonebook', 'pattern', 'crawled'];

function ToolRow({ toolKey, status, found, message }: {
  toolKey: ToolKey; status: ToolStatus; found: number; message: string;
}) {
  const { tokens } = useThemeTokens();
  const [expanded, setExpanded] = React.useState(false);

  const icon = {
    pending:   <Box sx={{ width: 16, height: 16, borderRadius: '50%', border: '2px solid', borderColor: tokens.text.disabled }} />,
    running:   <CircularProgress size={16} />,
    done:      <CheckCircle size={16} color={tokens.accent.success} />,
    error:     <AlertCircle size={16} color={tokens.accent.error} />,
    cancelled: <XCircle size={16} color={tokens.text.secondary} />,
  }[status] ?? null;

  return (
    <Box>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, py: 0.75 }}>
        {icon}
        <Typography variant="body2" sx={{ flex: 1 }}>
          {TOOL_LABELS[toolKey]}
        </Typography>
        {status === 'done' && (
          <Typography variant="caption" sx={{ color: tokens.text.secondary }}>
            {found} found
          </Typography>
        )}
        {status === 'running' && (
          <Typography variant="caption" sx={{ color: tokens.text.secondary }}>
            running...
          </Typography>
        )}
        {status === 'error' && message && (
          <Button size="small" onClick={() => setExpanded(!expanded)} sx={{ minWidth: 0, p: 0 }}>
            {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
          </Button>
        )}
      </Box>
      {status === 'error' && message && (
        <Collapse in={expanded}>
          <Typography variant="caption" sx={{ color: tokens.accent.error, pl: 4, display: 'block', pb: 0.5 }}>
            {message}
          </Typography>
        </Collapse>
      )}
    </Box>
  );
}

export const EmailDiscoveryModal: React.FC<EmailDiscoveryModalProps> = ({
  open, onClose, scanId, onComplete,
}) => {
  const { tokens } = useThemeTokens();
  const store = useEmailDiscoveryStore();
  const startMutation = useStartEmailDiscovery();
  const stopMutation = useStopEmailDiscovery();
  const wsRef = useRef<WebSocket | null>(null);
  const hasCompletedRef = useRef(false);
  // Keep a ref to always-current store actions so WS handlers don't go stale
  const storeRef = useRef(store);
  storeRef.current = store;

  const buildWsUrl = () => {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${proto}//${window.location.host}/ws/logs/${scanId}/`;
  };

  const connectWebSocket = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;
    const ws = new WebSocket(buildWsUrl());

    ws.onmessage = (ev) => {
      try {
        const frame = JSON.parse(ev.data as string);
        // ScanLogConsumer wraps as { type: 'log_update', data: payload }
        if (frame.type !== 'log_update') return;
        const payload = frame.data as Record<string, unknown> | undefined;
        if (!payload || payload['job_id'] !== storeRef.current.jobId) return;

        if (payload['type'] === 'email_discovery_progress') {
          storeRef.current.handleProgressEvent(
            payload as Parameters<typeof storeRef.current.handleProgressEvent>[0]
          );
        } else if (payload['type'] === 'email_discovery_complete') {
          storeRef.current.handleCompleteEvent(
            payload as Parameters<typeof storeRef.current.handleCompleteEvent>[0]
          );
          if (!hasCompletedRef.current) {
            hasCompletedRef.current = true;
            onComplete();
          }
        }
      } catch {
        // ignore malformed frames
      }
    };

    ws.onerror = () => ws.close();
    wsRef.current = ws;
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [onComplete, scanId]);

  // On open: start discovery or reconnect to existing job
  useEffect(() => {
    if (!open) return;

    const existingJobId = sessionStorage.getItem(`email_discovery_job_${scanId}`);

    if (existingJobId && store.running) {
      // Reconnect to existing job — WS replay handles state restoration
      connectWebSocket();
      return;
    }

    if (!store.running && !store.complete) {
      // Start a new discovery run
      startMutation.mutateAsync({ scanId }).then(({ job_id }) => {
        sessionStorage.setItem(`email_discovery_job_${scanId}`, job_id);
        store.startJob(job_id);
        connectWebSocket();
      }).catch(() => {});
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  // Replay events from REST API on reconnect (WS stream replay also covers this,
  // but REST replay is faster for initial mount when WS is still connecting)
  useEffect(() => {
    if (!open || !store.jobId) return;
    const jobId = store.jobId;
    fetch(`/api/emailDiscovery/${jobId}/replay/`, { credentials: 'include' })
      .then((r) => r.json())
      .then(({ events, complete }: { events: object[]; complete: boolean }) => {
        store.replayEvents(events);
        if (complete && !hasCompletedRef.current) {
          hasCompletedRef.current = true;
          onComplete();
        }
      })
      .catch(() => {});
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, store.jobId]);

  // Cleanup WS on unmount
  useEffect(() => {
    return () => {
      wsRef.current?.close();
    };
  }, []);

  const handleHide = () => {
    wsRef.current?.close();
    wsRef.current = null;
    onClose();
  };

  const handleStop = () => {
    if (!store.jobId) return;
    stopMutation.mutate({ jobId: store.jobId });
  };

  const handleViewEmails = () => {
    store.reset();
    sessionStorage.removeItem(`email_discovery_job_${scanId}`);
    onClose();
  };

  const totalSoFar = Object.values(store.tools).reduce((acc, t) => acc + t.found, 0);

  return (
    <Dialog open={open} onClose={handleHide} maxWidth="xs" fullWidth>
      <DialogTitle>
        Email Discovery
      </DialogTitle>
      <DialogContent>
        {store.complete ? (
          <Box sx={{ textAlign: 'center', py: 2 }}>
            <CheckCircle size={40} color={tokens.accent.success} />
            <Typography variant="h6" sx={{ mt: 1 }}>
              Discovery complete
            </Typography>
            <Typography variant="body2" sx={{ color: tokens.text.secondary }}>
              {store.totalFound} new email{store.totalFound !== 1 ? 's' : ''} found
            </Typography>
          </Box>
        ) : (
          <Box>
            {TOOL_ORDER.map((key) => (
              <ToolRow key={key} toolKey={key} {...store.tools[key]} />
            ))}
            <Divider sx={{ my: 1 }} />
            <Typography variant="caption" sx={{ color: tokens.text.secondary }}>
              Total discovered so far: {totalSoFar}
            </Typography>
          </Box>
        )}
      </DialogContent>
      <DialogActions>
        {store.complete ? (
          <>
            <Button onClick={handleViewEmails} variant="contained">
              View in Email Table
            </Button>
            <Button onClick={onClose}>Close</Button>
          </>
        ) : (
          <>
            <Button onClick={handleHide}>Hide</Button>
            <Button
              color="error"
              onClick={handleStop}
              disabled={stopMutation.isPending || !store.running}
            >
              Stop Discovery
            </Button>
          </>
        )}
      </DialogActions>
    </Dialog>
  );
};
