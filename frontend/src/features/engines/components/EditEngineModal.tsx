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
  CircularProgress,
  Tooltip,
  useTheme,
  alpha
} from '@mui/material';
import { X, Cpu, Save, BookOpen } from 'lucide-react';
import { fetchEngineDetails, useUpdateEngine } from '../api';
import { EngineConfigReferenceModal } from './EngineConfigReferenceModal';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import { getDialogPaperSx, getFieldSx } from '../../../theme/semanticColors';

interface EditEngineModalProps {
  open: boolean;
  onClose: () => void;
  engineId: number | null;
}

export const EditEngineModal: React.FC<EditEngineModalProps> = ({ open, onClose, engineId }) => {
  const [name, setName] = useState('');
  const [yaml, setYaml] = useState('');
  const [loading, setLoading] = useState(false);
  const [refOpen, setRefOpen] = useState(false);
  const updateEngine = useUpdateEngine();
  const backgroundRef = React.useRef<HTMLPreElement>(null);
  const theme = useTheme();
  const { tokens } = useThemeTokens();
  const isLight = tokens.mode === 'light';

  const handleScroll = (e: React.UIEvent<HTMLTextAreaElement>) => {
    if (backgroundRef.current) {
      backgroundRef.current.scrollTop = e.currentTarget.scrollTop;
    }
  };

  useEffect(() => {
    if (open && engineId) {
      setLoading(true);
      fetchEngineDetails(engineId)
        .then(data => {
          setName(data.engine_name);
          setYaml(data.yaml_configuration);
          setLoading(false);
        })
        .catch(err => {
          console.error(err);
          setLoading(false);
        });
    }
  }, [open, engineId]);

  const handleSubmit = async () => {
    if (!name || !yaml || !engineId) return;
    try {
      await updateEngine.mutateAsync({
        engine_id: engineId,
        engine_name: name,
        yaml_configuration: yaml
      });
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
            MODIFY ENGINE CONFIG
          </Typography>
        </Box>
        <IconButton onClick={onClose} size="small" sx={{ color: tokens.text.muted, '&:hover': { color: tokens.accent.error } }}>
          <X size={20} />
        </IconButton>
      </DialogTitle>

      <DialogContent sx={{ mt: 2, minHeight: 400, display: 'flex', flexDirection: 'column' }}>
        {loading ? (
          <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', flexGrow: 1 }}>
            <CircularProgress sx={{ color: tokens.accent.primary }} />
          </Box>
        ) : (
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
            <TextField
              label="ENGINE IDENTITY"
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
              <Box sx={{
                position: 'relative',
                width: '100%',
                height: 500,
                bgcolor: isLight ? 'transparent' : alpha(tokens.text.primary, 0.02),
                border: `1px solid ${tokens.border.subtle}`,
                borderRadius: 1,
                overflow: 'hidden'
              }}>
                <pre
                  ref={backgroundRef}
                  style={{
                    position: 'absolute',
                    top: 0,
                    left: 0,
                    right: 0,
                    bottom: 0,
                    margin: 0,
                    padding: '16px',
                    pointerEvents: 'none',
                    overflow: 'hidden',
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-all',
                    fontFamily: 'monospace',
                    fontSize: '14px',
                    lineHeight: '1.5',
                    color: 'transparent',
                    boxSizing: 'border-box',
                  }}
                >
                  {yaml.split('\n').map((line, i) => {
                    const cleanLine = line.replace('\r', '');
                    const isComment = cleanLine.trim().startsWith('#');
                    const keyMatch = cleanLine.match(/^(\s*)([^#\s][^:]+:)(.*)$/);

                    if (isComment) {
                      return (
                        <span key={i} style={{ color: tokens.text.muted }}>
                          {cleanLine}{i === yaml.split('\n').length - 1 ? '' : '\n'}
                        </span>
                      );
                    }

                    if (keyMatch) {
                      const [full, indent, key, rest] = keyMatch;
                      const isTopLevel = indent.length === 0;

                      return (
                        <span key={i}>
                          <span>{indent}</span>
                          <span style={{
                            color: isTopLevel 
                              ? (isLight ? '#c2410c' : tokens.accent.error) 
                              : (isLight ? '#b45309' : tokens.accent.warning),
                            fontWeight: isTopLevel ? 900 : 400
                          }}>
                            {key}
                          </span>
                          <span style={{ color: tokens.text.primary }}>{rest}</span>
                          {i === yaml.split('\n').length - 1 ? '' : '\n'}
                        </span>
                      );
                    }

                    return (
                      <span key={i} style={{ color: tokens.text.primary }}>
                        {cleanLine}{i === yaml.split('\n').length - 1 ? '' : '\n'}
                      </span>
                    );
                  })}
                </pre>
                <textarea
                  value={yaml}
                  onChange={(e) => setYaml(e.target.value)}
                  onScroll={handleScroll}
                  spellCheck={false}
                  style={{
                    position: 'absolute',
                    top: 0,
                    left: 0,
                    right: 0,
                    bottom: 0,
                    width: '100%',
                    height: '100%',
                    margin: 0,
                    padding: '16px',
                    background: 'transparent',
                    border: 'none',
                    outline: 'none',
                    resize: 'none',
                    fontFamily: 'monospace',
                    fontSize: '14px',
                    lineHeight: '1.5',
                    color: 'transparent',
                    caretColor: tokens.accent.primary,
                    boxSizing: 'border-box',
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-all',
                    overflowY: 'auto',
                  }}
                />
              </Box>
            </Box>
          </Box>
        )}
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
          disabled={!name || !yaml || updateEngine.isPending || loading}
          variant="contained"
          startIcon={<Save size={16} />}
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
          {updateEngine.isPending ? 'SYNCHRONIZING...' : 'COMMIT CHANGES'}
        </Button>
      </DialogActions>
      <EngineConfigReferenceModal open={refOpen} onClose={() => setRefOpen(false)} />
    </Dialog>
  );
};
