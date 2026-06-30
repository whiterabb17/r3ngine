import React, { useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControlLabel,
  MenuItem,
  Stack,
  Switch,
  TextField,
  Typography,
} from '@mui/material';
import { Brain, Download, Loader2 } from 'lucide-react';

import { useThemeTokens } from '../../../theme/useThemeTokens';
import { useDownloadAiExport } from '../api';


interface AiExportModalProps {
  open: boolean;
  onClose: () => void;
  projectSlug: string;
  scanId: number;
  targetName: string;
}


export const AiExportModal: React.FC<AiExportModalProps> = ({
  open,
  onClose,
  projectSlug,
  scanId,
  targetName,
}) => {
  const { tokens, isLight } = useThemeTokens();
  const downloadMutation = useDownloadAiExport(projectSlug, scanId);
  const [preset, setPreset] = useState<'analyst_assist'>('analyst_assist');
  const [includeRawOutputs, setIncludeRawOutputs] = useState(false);
  const [includeTimeline, setIncludeTimeline] = useState(true);
  const [includeSidecars, setIncludeSidecars] = useState(true);

  const handleDownload = async () => {
    try {
      await downloadMutation.mutateAsync({
        preset,
        include_raw_outputs: includeRawOutputs,
        include_timeline: includeTimeline,
        include_sidecars: includeSidecars,
      });
      onClose();
    } catch {
      // Error is surfaced in the alert below.
    }
  };

  return (
    <Dialog
      open={open}
      onClose={downloadMutation.isPending ? undefined : onClose}
      maxWidth="sm"
      fullWidth
      slotProps={{
        paper: {
          sx: {
            bgcolor: isLight ? 'background.paper' : 'rgba(10, 10, 18, 0.98)',
            border: `1px solid ${tokens.accent.primary}33`,
            backgroundImage: 'none',
          }
        }
      }}
    >
      <DialogTitle sx={{ borderBottom: `1px solid ${tokens.accent.primary}22` }}>
        <Stack direction="row" spacing={1.5} sx={{ alignItems: 'center' }}>
          <Brain size={18} color={tokens.accent.primary} />
          <Box>
            <Typography sx={{ fontSize: '0.95rem', fontWeight: 900, fontFamily: 'Orbitron', letterSpacing: 1 }}>
              EXPORT FOR AI
            </Typography>
            <Typography sx={{ fontSize: '0.7rem', color: 'text.secondary' }}>
              Best for external LLM-assisted analysis on {targetName}
            </Typography>
          </Box>
        </Stack>
      </DialogTitle>

      <DialogContent sx={{ pt: 3 }}>
        <Stack spacing={2.5}>
          <Alert
            severity="info"
            sx={{
              bgcolor: `${tokens.accent.primary}12`,
              color: 'text.primary',
              border: `1px solid ${tokens.accent.primary}33`,
              '& .MuiAlert-icon': { color: tokens.accent.primary }
            }}
          >
            Not a substitute for manual validation. Large raw outputs stay out of the main markdown bundle and move into sidecar files when enabled.
          </Alert>

          {downloadMutation.isError && (
            <Alert severity="error">
              {downloadMutation.error instanceof Error ? downloadMutation.error.message : 'Failed to export AI bundle.'}
            </Alert>
          )}

          <TextField
            select
            label="Preset"
            value={preset}
            onChange={(event) => setPreset(event.target.value as 'analyst_assist')}
            size="small"
            fullWidth
          >
            <MenuItem value="analyst_assist">Analyst Assist</MenuItem>
          </TextField>

          <Stack spacing={1}>
            <FormControlLabel
              control={<Switch checked={includeRawOutputs} onChange={(e) => setIncludeRawOutputs(e.target.checked)} />}
              label="Include raw command outputs"
            />
            <FormControlLabel
              control={<Switch checked={includeTimeline} onChange={(e) => setIncludeTimeline(e.target.checked)} />}
              label="Include timeline"
            />
            <FormControlLabel
              control={<Switch checked={includeSidecars} onChange={(e) => setIncludeSidecars(e.target.checked)} />}
              label="Include sidecar files"
            />
          </Stack>

          <Box
            sx={{
              p: 1.5,
              borderRadius: 1.5,
              bgcolor: 'action.hover',
              border: `1px solid ${tokens.accent.primary}1F`
            }}
          >
            <Typography sx={{ fontSize: '0.72rem', color: 'text.secondary', lineHeight: 1.6 }}>
              {'Bundle contents: '}
              <code>ai_bundle.md</code>{', '}
              <code>ai_bundle.json</code>{', '}
              <code>findings.ndjson</code>{', '}
              <code>prompt.txt</code>{', '}
              <code>manifest.json</code>
              {includeSidecars ? <>{', '}<code>assets.ndjson</code></> : ''}
              {includeRawOutputs ? <>{', '}<code>commands.ndjson</code></> : ''}{'.'}
            </Typography>
          </Box>
        </Stack>
      </DialogContent>

      <DialogActions sx={{ px: 3, py: 2, borderTop: `1px solid ${tokens.accent.primary}22` }}>
        <Button onClick={onClose} disabled={downloadMutation.isPending}>
          Cancel
        </Button>
        <Button
          variant="contained"
          onClick={handleDownload}
          disabled={downloadMutation.isPending}
          startIcon={downloadMutation.isPending ? <Loader2 size={14} className="spin" /> : <Download size={14} />}
          sx={{
            bgcolor: `${tokens.accent.primary}15`,
            color: tokens.accent.primary,
            border: `1px solid ${tokens.accent.primary}4D`,
            fontFamily: 'Orbitron',
            fontSize: '0.7rem',
            fontWeight: 900,
            '&:hover': { bgcolor: `${tokens.accent.primary}33` }
          }}
        >
          {downloadMutation.isPending ? 'BUILDING BUNDLE...' : 'DOWNLOAD AI BUNDLE'}
        </Button>
      </DialogActions>
    </Dialog>
  );
};
