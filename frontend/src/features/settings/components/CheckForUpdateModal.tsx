import React, { useState } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Typography,
  Box,
  CircularProgress,
  IconButton,
  Divider,
  Paper,
  Alert
} from '@mui/material';
import { X, RefreshCw, ExternalLink, ShieldCheck, AlertCircle } from 'lucide-react';
import { useRengineUpdateCheck } from '../api';
import type { RengineUpdateResponse } from '../api';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import { getSafeUrl } from '../../../utils/securityUtils';

interface CheckForUpdateModalProps {
  open: boolean;
  onClose: () => void;
  onUpdateFound?: (available: boolean) => void;
}

export const CheckForUpdateModal: React.FC<CheckForUpdateModalProps> = ({ open, onClose, onUpdateFound }) => {
  const { tokens } = useThemeTokens();
  const [result, setResult] = useState<RengineUpdateResponse | null>(null);
  const updateCheck = useRengineUpdateCheck();

  const handleCheck = async () => {
    try {
      const data = await updateCheck.mutateAsync();
      setResult(data);
      if (data.update_available && onUpdateFound) {
        onUpdateFound(true);
        localStorage.setItem('update_available', 'true');
      } else if (!data.update_available && onUpdateFound) {
        onUpdateFound(false);
        localStorage.setItem('update_available', 'false');
      }
    } catch (err) {
      console.error('Update check failed', err);
    }
  };

  const handleClose = () => {
    setResult(null);
    onClose();
  };

  React.useEffect(() => {
    if (open && !result && !updateCheck.isPending) {
      handleCheck();
    }
  }, [open]);

  return (
    <Dialog
      open={open}
      onClose={handleClose}
      maxWidth="md"
      fullWidth
      slotProps={{
        paper: {
          sx: {
            bgcolor: 'background.paper',
            backdropFilter: 'blur(15px)',
            border: 1,
            borderColor: 'divider',
            borderRadius: 4,
            boxShadow: `0 0 40px ${tokens.accent.primary}1A`,
            backgroundImage: 'none'
          }
        }
      }}
    >
      <DialogTitle sx={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        p: 3,
        pb: 1
      }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <RefreshCw size={24} color={tokens.accent.primary} style={{ animation: updateCheck.isPending ? 'spin 2s linear infinite' : 'none' }} />
          <Typography variant="h5" sx={{ fontFamily: 'Orbitron', fontWeight: 900, color: 'text.primary', letterSpacing: 1 }}>
            VERSION CHECK
          </Typography>
        </Box>
        <IconButton onClick={handleClose} sx={{ color: 'text.secondary' }}>
          <X size={20} />
        </IconButton>
      </DialogTitle>

      <DialogContent sx={{ p: 3 }}>
        {updateCheck.isPending ? (
          <Box sx={{ py: 8, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 3 }}>
            <CircularProgress sx={{ color: tokens.accent.primary }} size={60} thickness={2} />
            <Typography sx={{ color: `${tokens.accent.primary}99`, fontFamily: 'Orbitron', fontSize: '0.8rem', letterSpacing: 2 }}>
              CONTACTING CENTRAL COMMAND...
            </Typography>
          </Box>
        ) : result ? (
          <Box>
            {result.update_available ? (
              <Box>
                <Alert
                  severity="info"
                  icon={<AlertCircle size={24} />}
                  sx={{
                    bgcolor: `${tokens.accent.primary}1A`,
                    color: tokens.accent.primary,
                    border: `1px solid ${tokens.accent.primary}4D`,
                    mb: 3,
                    '& .MuiAlert-icon': { color: tokens.accent.primary }
                  }}
                >
                  <Typography variant="subtitle1" sx={{ fontWeight: 800, mb: 0.5 }}>
                    UPDATE AVAILABLE: v{result.latest_version}
                  </Typography>
                  <Typography variant="body2">
                    A newer version of r3Ngine is ready for deployment. Please follow the update instructions to upgrade from v{result.current_version}.
                  </Typography>
                </Alert>

                <Typography variant="overline" sx={{ color: 'text.secondary', fontWeight: 900, letterSpacing: 2 }}>
                  CHANGELOG DATA
                </Typography>
                <Paper sx={{
                  mt: 1,
                  p: 3,
                  bgcolor: 'action.hover',
                  border: 1,
                  borderColor: 'divider',
                  maxHeight: 400,
                  overflowY: 'auto',
                  '&::-webkit-scrollbar': { width: 4 },
                  '&::-webkit-scrollbar-thumb': { bgcolor: `${tokens.accent.primary}33`, borderRadius: 10 }
                }}>
                  <Box sx={{
                    color: 'text.primary',
                    '& h1, & h2, & h3': { color: tokens.accent.primary, fontFamily: 'Orbitron', mt: 2, mb: 1 },
                    '& p': { mb: 2, lineHeight: 1.6 },
                    '& ul, & ol': { pl: 3, mb: 2 },
                    '& li': { mb: 1 },
                    '& code': { bgcolor: 'rgba(0,0,0,0.3)', p: '2px 6px', borderRadius: 1, color: tokens.accent.secondary },
                    '& pre': { bgcolor: 'rgba(0,0,0,0.5)', p: 2, borderRadius: 2, overflowX: 'auto', mb: 2 }
                  }}>
                    {/* Using a simple formatter to bypass react-markdown build issues in this environment */}
                    <Box sx={{ whiteSpace: 'pre-wrap', fontFamily: 'Inter, sans-serif' }}>
                      {(result.changelog || 'No changelog provided.').split('\n').map((line, i) => {
                        if (line.startsWith('### ')) return <Typography key={i} variant="h6" sx={{ color: tokens.accent.primary, mt: 2, mb: 1, fontWeight: 800 }}>{line.replace('### ', '')}</Typography>;
                        if (line.startsWith('## ')) return <Typography key={i} variant="h5" sx={{ color: tokens.accent.primary, mt: 2, mb: 1, fontWeight: 800 }}>{line.replace('## ', '')}</Typography>;
                        if (line.startsWith('# ')) return <Typography key={i} variant="h4" sx={{ color: tokens.accent.primary, mt: 2, mb: 1, fontWeight: 800 }}>{line.replace('# ', '')}</Typography>;
                        if (line.startsWith('- ') || line.startsWith('* ')) return <Box key={i} sx={{ display: 'flex', gap: 1, mb: 0.5 }}><Typography sx={{ color: tokens.accent.primary }}>•</Typography><Typography variant="body2">{line.substring(2)}</Typography></Box>;
                        return <Typography key={i} variant="body2" sx={{ mb: 1 }}>{line}</Typography>;
                      })}
                    </Box>
                  </Box>
                </Paper>
              </Box>
            ) : result.message === 'RateLimited' ? (
              <Box sx={{ py: 4, textAlign: 'center' }}>
                <AlertCircle size={48} color="#ff0055" style={{ marginBottom: 16 }} />
                <Typography variant="h6" sx={{ color: 'text.primary', mb: 1 }}>GitHub Rate Limit Exceeded</Typography>
                <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                  We couldn't check for updates because GitHub's API rate limit was reached.
                  Please try again in about an hour.
                </Typography>
              </Box>
            ) : (
              <Box sx={{ py: 6, textAlign: 'center' }}>
                <ShieldCheck size={64} color="#00ff9d" style={{ marginBottom: 24, filter: 'drop-shadow(0 0 15px rgba(0, 255, 157, 0.3))' }} />
                <Typography variant="h5" sx={{ color: 'text.primary', fontFamily: 'Orbitron', fontWeight: 900, mb: 1 }}>
                  SYSTEM OPTIMIZED
                </Typography>
                <Typography variant="body1" sx={{ color: 'text.secondary' }}>
                  You are running the latest version of r3Ngine (v{result.current_version}).
                </Typography>
              </Box>
            )}
          </Box>
        ) : (
          <Typography sx={{ color: 'text.secondary', textAlign: 'center', py: 4 }}>
            Something went wrong. Please try again.
          </Typography>
        )}
      </DialogContent>

      <Divider sx={{ borderColor: 'divider' }} />

      <DialogActions sx={{ p: 3 }}>
        <Button
          onClick={handleClose}
          sx={{ color: 'text.secondary', fontFamily: 'Orbitron' }}
        >
          CLOSE
        </Button>
        {result?.update_available && (
          <Button
            variant="contained"
            startIcon={<ExternalLink size={18} />}
            href={getSafeUrl(result.redirect_link) ?? '#'}
            target="_blank"
            sx={{
              bgcolor: tokens.accent.primary,
              color: '#000',
              fontWeight: 900,
              fontFamily: 'Orbitron',
              '&:hover': { bgcolor: tokens.accent.primary, filter: 'brightness(1.1)' }
            }}
          >
            UPDATE NOW
          </Button>
        )}
        {!updateCheck.isPending && (
          <Button
            variant="outlined"
            onClick={handleCheck}
            startIcon={<RefreshCw size={18} />}
            sx={{
              borderColor: tokens.accent.primary,
              color: tokens.accent.primary,
              fontWeight: 900,
              fontFamily: 'Orbitron',
              '&:hover': { borderColor: tokens.accent.primary, bgcolor: `${tokens.accent.primary}1A` }
            }}
          >
            RECHECK
          </Button>
        )}
      </DialogActions>

      <style>{`
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      `}</style>
    </Dialog>
  );
};
