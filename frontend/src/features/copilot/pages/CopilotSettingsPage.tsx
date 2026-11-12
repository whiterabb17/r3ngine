import React, { useEffect, useState } from 'react';
import {
  Alert,
  Box,
  FormControl,
  FormControlLabel,
  InputLabel,
  MenuItem,
  Select,
  Switch,
  TextField,
  Typography,
  Button,
  Paper,
} from '@mui/material';
import { useParams } from '@tanstack/react-router';
import { useTheme } from '@mui/material/styles';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import { getSurfaceSx } from '../../../theme/semanticColors';
import {
  useCopilotSettings,
  useCopilotStatus,
  useUpdateCopilotSettings,
} from '../api';

export const CopilotSettingsPage: React.FC = () => {
  const { projectSlug = '' } = useParams({ strict: false }) as { projectSlug?: string };
  const theme = useTheme();
  const { tokens, isLight } = useThemeTokens();
  const { data: settings } = useCopilotSettings(projectSlug);
  const { data: status } = useCopilotStatus(projectSlug);
  const update = useUpdateCopilotSettings(projectSlug);

  const [enabled, setEnabled] = useState(true);
  const [memoryScope, setMemoryScope] = useState('project');
  const [modelId, setModelId] = useState('');
  const [orgId, setOrgId] = useState('');

  useEffect(() => {
    if (!settings) return;
    setEnabled(settings.enabled);
    setMemoryScope(settings.memory_scope);
    setModelId(settings.model_id || '');
    setOrgId(settings.org_id || '');
  }, [settings]);

  const save = () => {
    update.mutate({
      project_slug: projectSlug,
      enabled,
      memory_scope: memoryScope as 'project' | 'org' | 'global' | 'tiered',
      model_id: modelId,
      org_id: orgId,
    });
  };

  return (
    <Box sx={{ p: 3, maxWidth: 720 }}>
      <Typography
        variant="h5"
        sx={{ fontFamily: 'var(--r3-heading-font)', fontWeight: 700, mb: 1 }}
      >
        Assessment Copilot
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
        Separate from AI Hub / LLM Toolkit. Local pentest co-pilot for validation, SAFE PoC
        proposals, follow-ups, and remediations. Start with <code>make up-copilot</code>.
      </Typography>

      {status?.health?.hint && (
        <Alert severity={status.health.reachable ? 'success' : 'warning'} sx={{ mb: 2 }}>
          {status.health.hint || `Status: ${status.health.status}`}
        </Alert>
      )}

      <Paper sx={{ ...getSurfaceSx(isLight, tokens, theme), p: 3 }}>
        <FormControlLabel
          control={<Switch checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />}
          label="Enable Assessment Copilot for this project"
        />

        <FormControl fullWidth sx={{ mt: 2 }}>
          <InputLabel id="memory-scope-label">Memory scope</InputLabel>
          <Select
            labelId="memory-scope-label"
            label="Memory scope"
            value={memoryScope}
            onChange={(e) => setMemoryScope(e.target.value)}
          >
            <MenuItem value="project">Per project</MenuItem>
            <MenuItem value="org">Per organization</MenuItem>
            <MenuItem value="global">Global (local corpus)</MenuItem>
            <MenuItem value="tiered">Tiered (project + curated global)</MenuItem>
          </Select>
        </FormControl>

        <TextField
          fullWidth
          sx={{ mt: 2 }}
          label="Model id (assessment-ollama)"
          placeholder={status?.health?.model_default || 'qwen2.5:7b-instruct'}
          value={modelId}
          onChange={(e) => setModelId(e.target.value)}
          helperText="Leave blank to use COPILOT_MODEL_DEFAULT. Prefer WhiteRabbitNeo / Deep Hat or qwen2.5 instruct — not the AI Hub coder path."
        />

        <TextField
          fullWidth
          sx={{ mt: 2 }}
          label="Organization id (optional)"
          value={orgId}
          onChange={(e) => setOrgId(e.target.value)}
          helperText="Used when memory scope is org."
        />

        <Button
          variant="contained"
          sx={{ mt: 3 }}
          onClick={save}
          disabled={update.isPending}
        >
          Save
        </Button>
      </Paper>
    </Box>
  );
};

export default CopilotSettingsPage;
