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
}

const fetchAuthLogs = async (workflowId: string) => {
  const { data } = await axios.get(`/api/action/directory-file/auth-logs/?workflow_id=${workflowId}`);
  return data.logs || [];
};

export const ExtractAuthModal: React.FC<ExtractAuthModalProps> = ({
  open,
  onClose,
  url,
  workflowId,
  status: initialStatus
}) => {
  const { tokens } = useThemeTokens();
  const theme = useTheme();
  const isLight = tokens.mode === 'light';
  const logsEndRef = useRef<HTMLDivElement>(null);
  const [internalStatus, setInternalStatus] = React.useState(initialStatus);

  React.useEffect(() => {
    setInternalStatus(initialStatus);
  }, [initialStatus, workflowId]);

  const { data: logs = [] } = useQuery({
    queryKey: ['auth-logs', workflowId],
    queryFn: () => fetchAuthLogs(workflowId as string),
    enabled: !!workflowId && open,
    refetchInterval: (query) => (internalStatus === 'extracting' ? 1000 : false),
  });

  useEffect(() => {
    if (logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
    // Check if finished
    if (logs.length > 0 && internalStatus === 'extracting') {
      const lastLog = logs[logs.length - 1] || '';
      if (lastLog.includes('[COMPLETE]')) {
        setInternalStatus('completed');
      } else if (lastLog.includes('[ERROR]')) {
        setInternalStatus('error');
      }
    }
  }, [logs]);

  return (
    <Dialog
      open={open}
      onClose={internalStatus === 'extracting' ? undefined : onClose}
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
        {internalStatus !== 'extracting' && (
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
            {internalStatus === 'extracting' && (
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, color: tokens.accent.primary }}>
                <CircularProgress size={12} thickness={5} sx={{ color: 'inherit' }} />
                <Typography variant="caption" sx={{ fontWeight: 600 }}>Extracting...</Typography>
              </Box>
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
          {logs.length === 0 && internalStatus === 'extracting' && (
            <Typography variant="body2" sx={{ color: '#888' }}>Initializing...</Typography>
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
          disabled={internalStatus === 'extracting'}
          sx={{ color: tokens.text.secondary }}
        >
          {internalStatus === 'extracting' ? 'Please Wait' : 'Close'}
        </Button>
      </DialogActions>
    </Dialog>
  );
};
