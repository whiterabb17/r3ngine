import React, { useState } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  TextField,
  Box,
  Typography,
  IconButton,
  MenuItem,
  CircularProgress,
  Alert,
  alpha,
  useTheme
} from '@mui/material';
import { X, Target, Clock, Settings2, Search } from 'lucide-react';
import { useDomains, useUpdateTarget, useEngines } from '../../targets/api';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import { getDialogPaperSx, getFieldSx } from '../../../theme/semanticColors';

interface AddMonitoringTargetModalProps {
  open: boolean;
  onClose: () => void;
  projectSlug: string;
}

export const AddMonitoringTargetModal: React.FC<AddMonitoringTargetModalProps> = ({ open, onClose, projectSlug }) => {
  const { tokens, isLight, isCyber } = useThemeTokens();
  const theme = useTheme();
  
  const [formData, setFormData] = useState({
    target_id: '',
    monitor_frequency: 'daily',
    monitor_engine_id: '',
    monitor_scan_scope: 'none',
  });

  const { data: domains, isLoading: loadingDomains } = useDomains(projectSlug);
  const { data: engines, isLoading: loadingEngines } = useEngines();
  const { mutate: updateTarget, isPending, error, reset } = useUpdateTarget(projectSlug);

  // Filter out targets that are already monitored
  const unmonitoredDomains = domains?.filter(d => !d.is_monitored) || [];

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    if (!formData.target_id) return;

    updateTarget({
      id: Number(formData.target_id),
      is_monitored: true,
      monitor_frequency: formData.monitor_frequency,
      monitor_engine_id: formData.monitor_engine_id ? Number(formData.monitor_engine_id) : null,
      monitor_scan_scope: formData.monitor_scan_scope,
    }, {
      onSuccess: () => {
        onClose();
        setFormData({
          target_id: '',
          monitor_frequency: 'daily',
          monitor_engine_id: '',
          monitor_scan_scope: 'none',
        });
        reset();
      },
    });
  };

  const handleClose = () => {
    onClose();
    reset();
  };

  const fieldStyles = {
    ...getFieldSx(isLight, tokens, tokens.accent.primary),
    '& .MuiOutlinedInput-root': {
      color: 'text.primary',
      '& fieldset': { borderColor: isLight ? 'rgba(0, 0, 0, 0.12)' : 'rgba(255, 255, 255, 0.1)' },
      '&:hover fieldset': { borderColor: alpha(tokens.accent.primary, 0.4) },
      '&.Mui-focused fieldset': { borderColor: tokens.accent.primary },
      bgcolor: isLight ? 'rgba(0,0,0,0.01)' : 'rgba(255,255,255,0.03)',
    },
    '& .MuiInputLabel-root': { 
      color: 'text.secondary',
      '&.Mui-focused': { color: tokens.accent.primary }
    },
    '& .MuiSelect-icon': { color: 'text.secondary' },
  };

  return (
    <Dialog 
      open={open} 
      onClose={handleClose}
      slotProps={{
        paper: {
          sx: {
            ...getDialogPaperSx(isLight, theme, tokens),
            borderRadius: 4,
            maxWidth: 600,
            width: '100%',
            backgroundImage: isLight ? 'none' : 'radial-gradient(circle at top right, rgba(0, 243, 255, 0.05), transparent)',
            border: `1px solid ${isLight ? 'rgba(0,0,0,0.08)' : `${tokens.accent.primary}33`}`,
          }
        }
      }}
    >
      <DialogTitle sx={{ 
        display: 'flex', 
        justifyContent: 'space-between', 
        alignItems: 'center',
        borderBottom: `1px solid ${isLight ? 'rgba(0,0,0,0.06)' : 'rgba(255,255,255,0.05)'}`,
        pb: 2
      }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
          <Box sx={{ 
            p: 1, 
            borderRadius: 2, 
            bgcolor: alpha(tokens.accent.primary, 0.1), 
            color: tokens.accent.primary,
            display: 'flex'
          }}>
            <Target size={20} />
          </Box>
          <Typography variant="h6" sx={{ 
            fontFamily: 'Orbitron', 
            fontWeight: 800, 
            letterSpacing: 1,
            color: tokens.text.primary
          }}>
            ADD MONITORING TARGET
          </Typography>
        </Box>
        <IconButton onClick={handleClose} sx={{ color: 'text.disabled', '&:hover': { color: tokens.accent.error } }}>
          <X size={20} />
        </IconButton>
      </DialogTitle>

      <form onSubmit={handleSubmit}>
        <DialogContent sx={{ mt: 2 }}>
          {error && (
            <Alert severity="error" sx={{ 
              mb: 3, 
              bgcolor: alpha(tokens.accent.error, 0.1), 
              color: tokens.accent.error,
              border: `1px solid ${alpha(tokens.accent.error, 0.2)}`,
              '& .MuiAlert-icon': { color: tokens.accent.error }
            }}>
              {error.message}
            </Alert>
          )}

          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
            <TextField
              label="Select Target"
              select
              fullWidth
              required
              value={formData.target_id}
              onChange={(e) => setFormData({ ...formData, target_id: e.target.value })}
              sx={fieldStyles}
              disabled={loadingDomains}
              slotProps={{
                input: {
                  startAdornment: <Target size={18} style={{ marginRight: 12, color: tokens.accent.primary }} />
                }
              }}
            >
              {unmonitoredDomains.map((domain) => (
                <MenuItem key={domain.id} value={domain.id}>
                  {domain.domain_name}
                </MenuItem>
              ))}
              {unmonitoredDomains.length === 0 && (
                <MenuItem disabled value="">
                  <em>No unmonitored targets available</em>
                </MenuItem>
              )}
            </TextField>

            <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 2 }}>
              <TextField
                label="Frequency"
                select
                fullWidth
                size="small"
                required
                value={formData.monitor_frequency}
                onChange={(e) => setFormData({ ...formData, monitor_frequency: e.target.value })}
                sx={fieldStyles}
                slotProps={{
                  input: {
                    startAdornment: <Clock size={16} style={{ marginRight: 8, color: 'text.secondary' }} />
                  }
                }}
              >
                <MenuItem value="hourly">Hourly</MenuItem>
                <MenuItem value="daily">Daily</MenuItem>
                <MenuItem value="weekly">Weekly</MenuItem>
                <MenuItem value="monthly">Monthly</MenuItem>
              </TextField>

              <TextField
                label="Auto Scan Scope"
                select
                fullWidth
                size="small"
                required
                value={formData.monitor_scan_scope}
                onChange={(e) => setFormData({ ...formData, monitor_scan_scope: e.target.value })}
                sx={fieldStyles}
                slotProps={{
                  input: {
                    startAdornment: <Search size={16} style={{ marginRight: 8, color: 'text.secondary' }} />
                  }
                }}
              >
                <MenuItem value="none">None (Discovery Only)</MenuItem>
                <MenuItem value="targeted">Targeted Scan</MenuItem>
                <MenuItem value="full">Full Scan</MenuItem>
              </TextField>
            </Box>

            <TextField
              label="Monitoring Engine"
              select
              fullWidth
              size="small"
              required
              value={formData.monitor_engine_id}
              onChange={(e) => setFormData({ ...formData, monitor_engine_id: e.target.value })}
              sx={fieldStyles}
              disabled={loadingEngines}
              slotProps={{
                input: {
                  startAdornment: <Settings2 size={16} style={{ marginRight: 8, color: 'text.secondary' }} />
                }
              }}
            >
              {engines?.map((engine: any) => (
                <MenuItem key={engine.id} value={engine.id}>
                  {engine.engine_name}
                </MenuItem>
              ))}
            </TextField>
          </Box>
        </DialogContent>

        <DialogActions sx={{ p: 3, borderTop: '1px solid', borderColor: 'divider' }}>
          <Button 
            onClick={handleClose} 
            sx={{ 
              color: 'text.secondary',
              fontFamily: 'Orbitron',
              fontSize: '0.7rem',
              fontWeight: 800,
              '&:hover': { color: tokens.accent.error }
            }}
          >
            CANCEL
          </Button>
          <Button
            type="submit"
            variant="contained"
            disabled={isPending || !formData.target_id || !formData.monitor_engine_id}
            sx={{
              bgcolor: tokens.accent.primary,
              color: isLight ? '#fff' : '#000',
              fontWeight: 900,
              fontFamily: 'Orbitron',
              letterSpacing: 1,
              px: 4,
              '&:hover': {
                bgcolor: alpha(tokens.accent.primary, 0.8),
                boxShadow: isCyber ? `0 0 20px ${alpha(tokens.accent.primary, 0.4)}` : 'none'
              },
              '&.Mui-disabled': {
                bgcolor: alpha(tokens.accent.primary, 0.2),
                color: isLight ? 'rgba(0,0,0,0.26)' : 'rgba(255,255,255,0.3)'
              }
            }}
          >
            {isPending ? <CircularProgress size={20} sx={{ color: isLight ? '#fff' : '#000' }} /> : 'ENABLE MONITORING'}
          </Button>
        </DialogActions>
      </form>
    </Dialog>
  );
};
