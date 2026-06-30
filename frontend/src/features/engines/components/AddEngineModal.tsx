import React, { useState, useEffect } from 'react';
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
  Tooltip,
  useTheme,
  alpha,
} from '@mui/material';
import { X, Cpu, BookOpen } from 'lucide-react';
import { useCreateEngine, useFullYamlConfig } from '../api';
import { EngineConfigReferenceModal } from './EngineConfigReferenceModal';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import { getDialogPaperSx, getFieldSx } from '../../../theme/semanticColors';

interface AddEngineModalProps {
  open: boolean;
  onClose: () => void;
}

export const AddEngineModal: React.FC<AddEngineModalProps> = ({ open, onClose }) => {
  const [name, setName] = useState('');
  const [yaml, setYaml] = useState('');
  const [refOpen, setRefOpen] = useState(false);
  const createEngine = useCreateEngine();
  const { data: fullConfig } = useFullYamlConfig();
  const theme = useTheme();
  const { tokens } = useThemeTokens();
  const isLight = tokens.mode === 'light';

  useEffect(() => {
    if (fullConfig) {
      setYaml(fullConfig);
    }
  }, [fullConfig]);

  const handleSubmit = async () => {
    if (!name || !yaml) return;
    try {
      await createEngine.mutateAsync({ engine_name: name, yaml_configuration: yaml });
      setName('');
      setYaml('');
      onClose();
    } catch (error) {
      console.error(error);
    }
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      maxWidth="md"
      fullWidth
      slotProps={{
        paper: {
          sx: {
            ...getDialogPaperSx(isLight, theme, tokens),
            backgroundImage: isLight
              ? 'none'
              : `linear-gradient(${alpha(tokens.accent.primary, 0.05)} 1px, transparent 1px), linear-gradient(90deg, ${alpha(tokens.accent.primary, 0.05)} 1px, transparent 1px)`,
            backgroundSize: '20px 20px',
            border: `1px solid ${alpha(tokens.accent.primary, 0.2)}`,
            boxShadow: isLight ? 'none' : `0 0 30px ${alpha(tokens.accent.primary, 0.1)}`,
          }
        }
      }}
    >
      <DialogTitle sx={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        borderBottom: '1px solid',
        borderColor: 'divider',
        pb: 2
      }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
          <Cpu size={20} style={{ color: tokens.accent.primary }} />
          <Typography sx={{ fontFamily: 'Orbitron', fontWeight: 800, color: 'text.primary', letterSpacing: 1 }}>
            PROVISION NEW ENGINE
          </Typography>
        </Box>
        <IconButton onClick={onClose} size="small" sx={{ color: tokens.text.muted, '&:hover': { color: tokens.accent.error } }}>
          <X size={20} />
        </IconButton>
      </DialogTitle>

      <DialogContent sx={{ mt: 2 }}>
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
          <TextField
            label="ENGINE IDENTITY"
            placeholder="e.g. Full Recon Suite"
            fullWidth
            value={name}
            onChange={(e) => setName(e.target.value)}
            variant="outlined"
            sx={getFieldSx(isLight, tokens)}
          />

          <Box>
            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 0.5 }}>
              <Typography sx={{ color: tokens.text.secondary, fontFamily: 'Orbitron', fontSize: '0.7rem' }}>
                YAML CONFIGURATION BLUEPRINT
              </Typography>
              <Tooltip title="View configuration reference">
                <IconButton
                  size="small"
                  onClick={() => setRefOpen(true)}
                  sx={{
                    color: tokens.text.secondary,
                    p: 0.5,
                    '&:hover': { color: tokens.accent.primary, bgcolor: alpha(tokens.accent.primary, 0.08) },
                  }}
                >
                  <BookOpen size={14} />
                </IconButton>
              </Tooltip>
            </Box>
            <TextField
              placeholder="# Enter your engine configuration here"
              fullWidth
              multiline
              rows={15}
              value={yaml}
              onChange={(e) => setYaml(e.target.value)}
              variant="outlined"
              sx={{
                ...getFieldSx(isLight, tokens),
                '& .MuiOutlinedInput-root': {
                  ...getFieldSx(isLight, tokens)['& .MuiOutlinedInput-root'],
                  fontFamily: 'monospace',
                  fontSize: '0.85rem',
                }
              }}
            />
          </Box>
        </Box>
      </DialogContent>

      <DialogActions sx={{ p: 3, borderTop: '1px solid', borderColor: 'divider' }}>
        <Button
          onClick={onClose}
          sx={{ color: tokens.text.secondary, fontFamily: 'Orbitron', fontSize: '0.7rem', '&:hover': { color: tokens.text.primary } }}
        >
          CANCEL
        </Button>
        <Button
          onClick={handleSubmit}
          disabled={!name || !yaml || createEngine.isPending}
          variant="contained"
          sx={{
            bgcolor: tokens.accent.primary,
            color: theme.palette.getContrastText(tokens.accent.primary),
            fontFamily: 'Orbitron',
            fontWeight: 900,
            fontSize: '0.75rem',
            px: 4,
            '&:hover': { bgcolor: alpha(tokens.accent.primary, 0.85) },
            '&.Mui-disabled': { bgcolor: alpha(tokens.text.primary, 0.1), color: tokens.text.disabled }
          }}
        >
          {createEngine.isPending ? 'PROVISIONING...' : 'INITIALIZE ENGINE'}
        </Button>
      </DialogActions>
      <EngineConfigReferenceModal open={refOpen} onClose={() => setRefOpen(false)} />
    </Dialog>
  );
};
