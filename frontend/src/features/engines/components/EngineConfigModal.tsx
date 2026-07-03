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
  alpha,
  useTheme,
} from '@mui/material';
import { X, Cpu } from 'lucide-react';
import { useEngineConfig } from '../hooks/useEngineConfig';
import type { UseEngineConfigReturn } from '../hooks/useEngineConfig';
import { useCreateEngine, useUpdateEngine, fetchEngineDetails } from '../api';
import { TemplatePicker } from './TemplatePicker';
import { EngineConfigTabs } from './EngineConfigTabs';
import { EngineConfigWizard } from './EngineConfigWizard';
import { getDialogPaperSx, getFieldSx } from '../../../theme/semanticColors';
import { useThemeTokens } from '../../../theme/useThemeTokens';

// ─── Types ────────────────────────────────────────────────────────────────────

export type EngineConfigModalMode = 'create' | 'edit';

interface EngineConfigModalProps {
  open: boolean;
  onClose: () => void;
  mode: EngineConfigModalMode;
  /** Required when mode === 'edit'. The engine ID to load and update. */
  engineId?: number;
  /** Pre-fill the engine name field (edit mode). */
  engineName?: string;
  /**
   * Optional pre-loaded YAML string (edit mode).
   * When omitted the modal fetches from the API on open.
   */
  initialYaml?: string;
}

// ─── Component ────────────────────────────────────────────────────────────────

export const EngineConfigModal: React.FC<EngineConfigModalProps> = ({
  open,
  onClose,
  mode,
  engineId,
  engineName: initialName = '',
  initialYaml = '',
}) => {
  const theme = useTheme();
  const { tokens } = useThemeTokens();
  const isLight = tokens.mode === 'light';

  const [name, setName] = useState(initialName);
  const [fetchLoading, setFetchLoading] = useState(false);
  const [fetchError, setFetchError] = useState<string | null>(null);

  const createEngine = useCreateEngine();
  const updateEngine = useUpdateEngine();

  // Pass initialYaml only when open so the hook initialises with it.
  // The hook's own useEffect re-parses whenever initialYaml changes.
  const engineConfigState: UseEngineConfigReturn = useEngineConfig(
    open ? initialYaml || undefined : undefined,
  );

  // In edit mode, if no initialYaml was provided, fetch from the API on open.
  useEffect(() => {
    if (!open || mode !== 'edit' || !engineId || initialYaml) return;

    setFetchLoading(true);
    setFetchError(null);

    fetchEngineDetails(engineId)
      .then((data: { engine_name: string; yaml_configuration: string }) => {
        engineConfigState.loadTemplate(data.yaml_configuration);
        setName(data.engine_name);
      })
      .catch((err: unknown) => {
        setFetchError(err instanceof Error ? err.message : 'Failed to load engine');
      })
      .finally(() => {
        setFetchLoading(false);
      });

    // loadTemplate is a stable callback from useCallback inside useEngineConfig.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, engineId]);

  // Reset name to blank when opening in create mode.
  useEffect(() => {
    if (open && mode === 'create') {
      setName('');
    }
  }, [open, mode]);

  // When engineName prop changes (e.g. parent re-opens for a different engine),
  // sync the local state for edit mode.
  useEffect(() => {
    if (mode === 'edit' && initialName) {
      setName(initialName);
    }
  }, [mode, initialName]);

  // ─── Save handler ──────────────────────────────────────────────────────────

  const handleSave = async () => {
    if (!name.trim() || engineConfigState.yamlError) return;
    const yaml = engineConfigState.yaml;

    try {
      if (mode === 'create') {
        await createEngine.mutateAsync({ engine_name: name.trim(), yaml_configuration: yaml });
      } else if (engineId !== undefined) {
        await updateEngine.mutateAsync({
          engine_id: engineId,
          engine_name: name.trim(),
          yaml_configuration: yaml,
        });
      }
      onClose();
    } catch {
      // Mutation errors are surfaced via createEngine.error / updateEngine.error;
      // we intentionally do not rethrow so the dialog stays open for correction.
    }
  };

  // ─── Derived state ─────────────────────────────────────────────────────────

  const isSaving = createEngine.isPending || updateEngine.isPending;
  const isDisabled =
    !name.trim() || !!engineConfigState.yamlError || isSaving || fetchLoading;

  // ─── Styling ───────────────────────────────────────────────────────────────

  const paperSx = {
    ...getDialogPaperSx(isLight, theme, tokens),
    backgroundImage: isLight
      ? 'none'
      : `linear-gradient(${alpha(tokens.accent.primary, 0.05)} 1px, transparent 1px), ` +
        `linear-gradient(90deg, ${alpha(tokens.accent.primary, 0.05)} 1px, transparent 1px)`,
    backgroundSize: '20px 20px',
    border: `1px solid ${alpha(tokens.accent.primary, 0.2)}`,
    boxShadow: isLight ? 'none' : `0 0 30px ${alpha(tokens.accent.primary, 0.1)}`,
  };

  const mutationError =
    (createEngine.error instanceof Error ? createEngine.error.message : null) ||
    (updateEngine.error instanceof Error ? updateEngine.error.message : null);

  // ─── Render ────────────────────────────────────────────────────────────────

  return (
    <Dialog
      open={open}
      onClose={onClose}
      maxWidth="lg"
      fullWidth
      slotProps={{ paper: { sx: paperSx } }}
    >
      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <DialogTitle
        sx={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          borderBottom: '1px solid',
          borderColor: 'divider',
          pb: 2,
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
          <Cpu size={20} style={{ color: tokens.accent.primary }} />
          <Typography
            sx={{
              fontFamily: 'Orbitron',
              fontWeight: 800,
              letterSpacing: 1,
              color: tokens.text.primary,
            }}
          >
            {mode === 'create' ? 'NEW ENGINE' : 'EDIT ENGINE'}
          </Typography>
        </Box>

        <IconButton
          onClick={onClose}
          size="small"
          sx={{
            color: tokens.text.muted,
            '&:hover': { color: tokens.accent.error },
          }}
        >
          <X size={20} />
        </IconButton>
      </DialogTitle>

      {/* ── Body ───────────────────────────────────────────────────────────── */}
      <DialogContent sx={{ mt: 2, minHeight: 480 }}>
        {fetchLoading ? (
          <Box
            sx={{
              display: 'flex',
              justifyContent: 'center',
              alignItems: 'center',
              height: 480,
            }}
          >
            <CircularProgress size={40} sx={{ color: tokens.accent.primary }} />
          </Box>
        ) : (
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
            {/* Engine name field */}
            <TextField
              label="Engine Name"
              placeholder="e.g. Full Recon Suite"
              fullWidth
              size="small"
              value={name}
              onChange={(e) => setName(e.target.value)}
              sx={getFieldSx(isLight, tokens)}
            />

            {/* Fetch or mutation error banner */}
            {(fetchError || mutationError) && (
              <Typography
                variant="caption"
                sx={{
                  color: tokens.accent.error,
                  bgcolor: alpha(tokens.accent.error, 0.08),
                  border: `1px solid ${alpha(tokens.accent.error, 0.25)}`,
                  borderRadius: 1,
                  px: 2,
                  py: 1,
                  display: 'block',
                }}
              >
                {fetchError ?? mutationError}
              </Typography>
            )}

            {/* Create mode — template picker above wizard */}
            {mode === 'create' && (
              <>
                <TemplatePicker onSelect={engineConfigState.loadTemplate} />
                <EngineConfigWizard state={engineConfigState} />
              </>
            )}

            {/* Edit mode — full tab layout */}
            {mode === 'edit' && (
              <EngineConfigTabs state={engineConfigState} />
            )}
          </Box>
        )}
      </DialogContent>

      {/* ── Footer ─────────────────────────────────────────────────────────── */}
      <DialogActions
        sx={{
          p: 3,
          borderTop: '1px solid',
          borderColor: 'divider',
          gap: 1,
        }}
      >
        <Button
          onClick={onClose}
          sx={{
            color: tokens.text.secondary,
            fontFamily: 'Orbitron',
            fontSize: '0.7rem',
            '&:hover': { color: tokens.text.primary },
          }}
        >
          CANCEL
        </Button>

        <Button
          onClick={handleSave}
          disabled={isDisabled}
          variant="contained"
          sx={{
            bgcolor: tokens.accent.primary,
            color: theme.palette.getContrastText(tokens.accent.primary),
            fontFamily: 'Orbitron',
            fontWeight: 900,
            fontSize: '0.75rem',
            px: 4,
            '&:hover': { bgcolor: alpha(tokens.accent.primary, 0.85) },
            '&.Mui-disabled': {
              bgcolor: alpha(tokens.text.primary, 0.1),
              color: tokens.text.disabled,
            },
          }}
        >
          {isSaving
            ? 'SAVING...'
            : mode === 'create'
              ? 'CREATE ENGINE'
              : 'SAVE CHANGES'}
        </Button>
      </DialogActions>
    </Dialog>
  );
};
