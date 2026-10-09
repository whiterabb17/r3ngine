import React, { useState, useEffect, useRef } from 'react';
import { 
  Box, 
  Typography, 
  Grid, 
  Button, 
  Stack, 
  TextField, 
  Switch, 
  FormControlLabel, 
  MenuItem, 
  CircularProgress,
  Alert,
  IconButton,
  InputAdornment,
  Divider,
  Paper,
  Tooltip,
  Snackbar
} from '@mui/material';
import {
  Cpu,
  Settings,
  Save,
  Download,
  Eye,
  EyeOff,
  Info,
  Terminal as TerminalIcon,
  CheckCircle2,
  AlertCircle,
  Brain,
  Zap,
  Globe,
  Ghost,
  Shield,
  ChevronRight,
  Database,
  Wifi,
  XCircle,
  Power,
  Link2,
} from 'lucide-react';
import { useParams } from '@tanstack/react-router';
import {
  useLlmToolkit,
  useLlmModels,
  useUpdateLlmSettings,
  useToggleLlmEnabled,
  useOllamaPullStatus,
  useTestLlmConnection,
  useOllamaServiceStatus,
} from '../api';
import { OPENAI_COMPATIBLE_PROVIDER } from '../api';
import type { LLMConfig, LLMModel, TestLlmConnectionResult } from '../api';
import { OpenAiCompatibleFields } from './OpenAiCompatibleFields';

import { TacticalPanel } from '../../../components/TacticalPanel';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import type { ApiErrorLike } from '../../../types/errors';

export const LlmToolkitPage: React.FC = () => {
  const { tokens } = useThemeTokens();
  const { projectSlug = 'default' } = useParams({ strict: false });
  const { data: toolkit, isLoading: isToolkitLoading } = useLlmToolkit(projectSlug);
  const updateSettings = useUpdateLlmSettings(projectSlug);
  const toggleLlmEnabled = useToggleLlmEnabled(projectSlug);
  const testConnection = useTestLlmConnection(projectSlug);
  const { data: ollamaStatus } = useOllamaServiceStatus(projectSlug);

  const [selectedProvider, setSelectedProvider] = useState<string>('ollama');
  const [showKey, setShowKey] = useState(false);
  const [form, setForm] = useState({
    api_key: '',
    base_url: '',
    selected_model: '',
    is_active: false
  });
  const [llmEnabled, setLlmEnabled] = useState(false);
  const [testResult, setTestResult] = useState<TestLlmConnectionResult | null>(null);
  const [pullingModel, setPullingModel] = useState<string | null>(null);
  const [snackbar, setSnackbar] = useState<{
    open: boolean;
    message: string;
    severity: 'success' | 'error' | 'info' | 'warning';
  }>({
    open: false,
    message: '',
    severity: 'success',
  });
  
  const { data: models, isLoading: isModelsLoading } = useLlmModels(
    projectSlug, 
    selectedProvider,
    form.api_key,
    form.base_url
  );
  
  const { data: pullStatus } = useOllamaPullStatus(projectSlug, pullingModel);
  const terminalRef = useRef<HTMLDivElement>(null);

  // Initialize form when toolkit data is loaded or provider changes
  useEffect(() => {
    if (toolkit?.llm_configs) {
      const config = toolkit.llm_configs.find(c => c.provider === selectedProvider);
      if (config) {
        setForm({
          api_key: config.api_key || '',
          base_url: config.base_url || '',
          selected_model: config.selected_model || '',
          is_active: config.is_active
        });
      } else {
        setForm({
          api_key: selectedProvider === 'ollama' ? 'http://ollama:11434' : '',
          base_url: '',
          selected_model: '',
          is_active: false
        });
      }
    }
  }, [toolkit, selectedProvider]);

  useEffect(() => {
    if (typeof toolkit?.llm_enabled === 'boolean') {
      setLlmEnabled(toolkit.llm_enabled);
    }
  }, [toolkit?.llm_enabled]);

  // Set default provider on first load
  useEffect(() => {
    if (toolkit?.active_provider) {
      setSelectedProvider(toolkit.active_provider);
    }
  }, [toolkit?.active_provider]);

  // Scroll terminal to bottom
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [pullStatus?.log]);

  // Handle pull completion
  useEffect(() => {
    if (pullStatus?.status === 'success') {
      setSnackbar({
        open: true,
        message: `Model ${pullingModel} downloaded successfully.`,
        severity: 'success',
      });
      setTimeout(() => setPullingModel(null), 5000);
    } else if (pullStatus?.status === 'failed') {
      setSnackbar({
        open: true,
        message: `Failed to download model ${pullingModel}.`,
        severity: 'error',
      });
      setTimeout(() => setPullingModel(null), 5000);
    }
  }, [pullStatus?.status]);

  const handleCloseSnackbar = () => {
    setSnackbar({ ...snackbar, open: false });
  };

  // Clear test result when the user changes provider, model, or key
  useEffect(() => {
    setTestResult(null);
  }, [selectedProvider, form.api_key, form.base_url, form.selected_model]);

  const handleMasterToggle = (enabled: boolean) => {
    setLlmEnabled(enabled);
    toggleLlmEnabled.mutate(enabled, {
      onSuccess: (data) => {
        setLlmEnabled(Boolean(data.llm_enabled));
        setSnackbar({
          open: true,
          message: data.message || (enabled ? 'LLM features enabled.' : 'LLM features disabled.'),
          severity: 'success',
        });
      },
      onError: (caught) => {
        const error = caught as ApiErrorLike;
        setLlmEnabled(!enabled);
        setSnackbar({
          open: true,
          message: `Failed to update LLM switch: ${error?.response?.data?.message || error?.message || 'Unknown error'}`,
          severity: 'error',
        });
      },
    });
  };

  const handleProviderChange = (provider: string) => {
    setSelectedProvider(provider);
    setShowKey(false);
  };

  const handleTest = () => {
    testConnection.mutate(
      { provider: selectedProvider, api_key: form.api_key, model: form.selected_model, base_url: form.base_url },
      { onSuccess: (data) => setTestResult(data) }
    );
  };

  const handleSave = (action: 'save' | 'pull') => {
    updateSettings.mutate({
      provider: selectedProvider,
      api_key: form.api_key,
      base_url: form.base_url,
      selected_model: form.selected_model,
      is_active: form.is_active,
      action
    }, {
      onSuccess: (data) => {
        if (data.status === 'pulling') {
          setPullingModel(form.selected_model);
          setSnackbar({
            open: true,
            message: `Initiating download for ${form.selected_model}...`,
            severity: 'info',
          });
        } else {
          setSnackbar({
            open: true,
            message: `${selectedProvider.toUpperCase()} configuration saved successfully.`,
            severity: 'success',
          });
        }
      },
      onError: (caught) => {
        const error = caught as ApiErrorLike;
        setSnackbar({
          open: true,
          message: `Failed to update LLM settings: ${error?.response?.data?.message || error?.message || 'Unknown error'}`,
          severity: 'error',
        });
      },
    });
  };

  const currentModel = models?.find(m => m.name === form.selected_model);
  const providers = [
    { id: 'ollama', name: 'Ollama (Local)', icon: <Database size={18} /> },
    { id: 'openai', name: 'OpenAI', icon: <Zap size={18} /> },
    { id: OPENAI_COMPATIBLE_PROVIDER, name: 'OpenAI-compatible', icon: <Link2 size={18} /> },
    { id: 'anthropic', name: 'Anthropic', icon: <Shield size={18} /> },
    { id: 'gemini', name: 'Google Gemini', icon: <Globe size={18} /> },
  ];

  if (isToolkitLoading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', p: 10 }}>
        <CircularProgress sx={{ color: tokens.accent.primary }} />
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" sx={{ 
          fontFamily: 'Orbitron', 
          fontWeight: 900, 
          color: 'text.primary', 
          textShadow: `0 0 20px ${tokens.accent.primary}80`,
          mb: 1 
        }}>
          AI_HUB
        </Typography>
        <Typography variant="body2" sx={{ color: 'text.secondary', letterSpacing: 1 }}>
          CENTRALIZED LLM ORCHESTRATION & CONFIGURATION
        </Typography>
      </Box>

      <TacticalPanel title="GLOBAL CONTROL" icon={<Power size={18} />} sx={{ mb: 3 }}>
        <Box sx={{ p: 1 }}>
          <FormControlLabel
            control={
              <Switch
                checked={llmEnabled}
                disabled={toggleLlmEnabled.isPending}
                onChange={(e) => handleMasterToggle(e.target.checked)}
                sx={{
                  '& .MuiSwitch-switchBase.Mui-checked': { color: tokens.accent.primary },
                  '& .MuiSwitch-switchBase.Mui-checked + .MuiSwitch-track': { bgcolor: tokens.accent.primary }
                }}
              />
            }
            label={
              <Typography sx={{ color: 'text.primary', fontFamily: 'Orbitron', fontSize: '0.9rem', fontWeight: 700 }}>
                ENABLE LLM FEATURES
              </Typography>
            }
          />
          <Typography variant="caption" sx={{ display: 'block', color: 'text.secondary', mt: 1 }}>
            Master switch for AI impact assessment, GPT vulnerability reports, and other LLM calls during scans.
            Configure a provider below, then turn this on.
          </Typography>
        </Box>
        {!llmEnabled && (
          <Alert
            severity="warning"
            sx={{
              mt: 1,
              bgcolor: `${tokens.accent.warning}14`,
              color: 'text.primary',
              border: `1px solid ${tokens.accent.warning}4D`,
              '& .MuiAlert-icon': { color: tokens.accent.warning }
            }}
          >
            LLM is off. Scans will skip AI impact assessment instead of calling a provider.
          </Alert>
        )}
      </TacticalPanel>

      <Grid container spacing={3}>
        {/* Provider Sidebar */}
        <Grid size={{xs: 12, lg: 3}} >
          <TacticalPanel title="LLM PROVIDERS" icon={<Brain size={18} />}>
            <Stack spacing={1}>
              {providers.map((p) => (
                <Button
                  key={p.id}
                  variant={selectedProvider === p.id ? 'contained' : 'text'}
                  startIcon={p.icon}
                  onClick={() => handleProviderChange(p.id)}
                  sx={{
                    justifyContent: 'flex-start',
                    fontFamily: 'Orbitron',
                    fontSize: '0.75rem',
                    py: 1.5,
                    px: 2,
                    borderRadius: '12px',
                    bgcolor: selectedProvider === p.id ? `${tokens.accent.primary}26` : 'transparent',
                    color: selectedProvider === p.id ? tokens.accent.primary : 'text.secondary',
                    border: 1,
                    borderColor: selectedProvider === p.id ? `${tokens.accent.primary}4D` : 'transparent',
                    '&:hover': {
                      bgcolor: 'action.hover',
                      color: tokens.accent.primary
                    }
                  }}
                >
                  {p.name}
                  {toolkit?.llm_configs.find(c => c.provider === p.id)?.is_active && (
                    <Box sx={{ ml: 'auto', display: 'flex' }}>
                      <CheckCircle2 size={14} color={tokens.accent.primary} />
                    </Box>
                  )}
                </Button>
              ))}
            </Stack>
            <Box sx={{ mt: 4, pt: 3, borderTop: 1, borderColor: 'divider' }}>
              <Typography variant="caption" sx={{ color: 'text.secondary', lineHeight: 1.6, display: 'block' }}>
                reNgine uses LLMs for intelligent reporting, vulnerability analysis, and attack path suggestions.
              </Typography>
            </Box>
          </TacticalPanel>
        </Grid>

        {/* Main Config Area */}
        <Grid size={{xs: 12, lg: selectedProvider === 'ollama' ? 6 : 9}} >
          <TacticalPanel 
            title={`${selectedProvider.toUpperCase()} CONFIGURATION`}
            icon={<Settings size={18} />}
            headerAction={
              <Box sx={{ 
                px: 1.5, 
                py: 0.5, 
                borderRadius: '20px', 
                bgcolor: form.is_active ? `${tokens.accent.primary}1A` : 'action.hover',
                border: 1,
                borderColor: form.is_active ? `${tokens.accent.primary}4D` : 'divider'
              }}>
                <Typography sx={{ 
                  fontSize: '10px', 
                  fontFamily: 'Orbitron', 
                  color: form.is_active ? tokens.accent.primary : 'text.disabled',
                  fontWeight: 700
                }}>
                  {form.is_active ? 'ACTIVE DEFAULT' : 'INACTIVE'}
                </Typography>
              </Box>
            }
          >
            <Stack spacing={4}>
              {/* Ollama Service Controls */}
              {selectedProvider === 'ollama' && (
                <Box sx={{ 
                  p: 2, 
                  borderRadius: '12px', 
                  bgcolor: 'background.paper', 
                  border: 1,
                  borderColor: 'divider',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  flexWrap: 'wrap',
                  gap: 2
                }}>
                  <Box>
                    <Typography sx={{ color: 'text.secondary', fontSize: '0.75rem', mb: 0.5, fontFamily: 'Orbitron' }}>
                      OLLAMA SERVICE STATUS
                    </Typography>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      {ollamaStatus?.running ? (
                        <CheckCircle2 size={16} color={tokens.accent.primary} />
                      ) : (
                        <AlertCircle size={16} color="#ff3131" />
                      )}
                      <Typography sx={{
                        fontSize: '0.85rem',
                        fontWeight: 600,
                        color: ollamaStatus?.running ? tokens.accent.primary : '#ff3131'
                      }}>
                        {ollamaStatus?.running
                          ? `RUNNING${ollamaStatus.version ? ` (v${ollamaStatus.version})` : ''}`
                          : 'STOPPED'}
                      </Typography>
                    </Box>
                  </Box>
                  {/* The service is started from the host (compose profile), not from here. */}
                  <Typography sx={{ color: 'text.secondary', fontSize: '0.8rem', flexBasis: '100%' }}>
                    {ollamaStatus?.running
                      ? `Compose service reachable at ${ollamaStatus.url ?? 'http://ollama:11434'}.`
                      : (ollamaStatus?.hint ?? 'Ollama is an optional compose service; enable the "ollama" profile and run make up.')}
                  </Typography>
                </Box>
              )}

              {/* API Key / Host URL */}
              <Box>
                <Typography sx={{ color: 'text.secondary', fontSize: '0.75rem', mb: 1, fontFamily: 'Orbitron' }}>
                  {selectedProvider === 'ollama' ? 'HOST_URL' : 'API_KEY'}
                </Typography>
                <TextField
                  fullWidth
                  type={showKey ? 'text' : 'password'}
                  value={form.api_key}
                  onChange={(e) => setForm({ ...form, api_key: e.target.value })}
                  placeholder={selectedProvider === 'ollama' ? 'http://ollama:11434' : 'sk-...'}
                  slotProps={{
                    input: {
                      startAdornment: (
                        <InputAdornment position="start">
                          <Box sx={{ color: `${tokens.accent.primary}80` }}>
                            {selectedProvider === 'ollama' ? <Globe size={18} /> : <Eye size={18} />}
                          </Box>
                        </InputAdornment>
                      ),
                      endAdornment: (
                        <InputAdornment position="end">
                          <IconButton onClick={() => setShowKey(!showKey)} edge="end" sx={{ color: 'text.disabled' }}>
                            {showKey ? <EyeOff size={18} /> : <Eye size={18} />}
                          </IconButton>
                        </InputAdornment>
                      )
                    }
                  }}
                  sx={{
                    '& .MuiOutlinedInput-root': {
                      color: 'text.primary',
                      bgcolor: 'action.hover',
                      fontFamily: 'monospace',
                      '& fieldset': { borderColor: 'divider' },
                      '&:hover fieldset': { borderColor: `${tokens.accent.primary}4D` },
                      '&.Mui-focused fieldset': { borderColor: tokens.accent.primary },
                    }
                  }}
                />
                <Typography variant="caption" sx={{ color: 'text.disabled', mt: 1, display: 'block' }}>
                  {selectedProvider === 'ollama'
                    ? 'Internal URL for Ollama service. Default is http://ollama:11434'
                    : selectedProvider === OPENAI_COMPATIBLE_PROVIDER
                      ? 'The key the gateway issued you. For a local server without auth, any value works.'
                      : `Enter your ${selectedProvider} API key to fetch available models.`}
                </Typography>
              </Box>

              {selectedProvider === OPENAI_COMPATIBLE_PROVIDER ? (
                <OpenAiCompatibleFields
                  baseUrl={form.base_url}
                  model={form.selected_model}
                  models={models}
                  isModelsLoading={isModelsLoading}
                  onBaseUrlChange={(base_url) => setForm((f) => ({ ...f, base_url }))}
                  onModelChange={(selected_model) => setForm((f) => ({ ...f, selected_model }))}
                />
              ) : (
              /* Model Selection */
              <Box>
                <Typography sx={{ color: 'text.secondary', fontSize: '0.75rem', mb: 1, fontFamily: 'Orbitron' }}>
                  SELECT MODEL
                </Typography>
                <TextField
                  select
                  fullWidth
                  value={form.selected_model}
                  onChange={(e) => setForm({ ...form, selected_model: e.target.value })}
                  disabled={isModelsLoading || (selectedProvider === 'ollama' && !ollamaStatus?.running)}
                  sx={{
                    '& .MuiOutlinedInput-root': {
                      color: 'text.primary',
                      bgcolor: 'action.hover',
                      '& fieldset': { borderColor: 'divider' },
                      '&.Mui-focused fieldset': { borderColor: tokens.accent.primary },
                    },
                    '& .MuiSelect-icon': { color: 'text.secondary' }
                  }}
                >
                  {isModelsLoading ? (
                    <MenuItem disabled value="">
                      <CircularProgress size={20} sx={{ mr: 2 }} /> Loading models...
                    </MenuItem>
                  ) : models && models.length > 0 ? (
                    models.map((m) => (
                      <MenuItem key={m.name} value={m.name} sx={{ 
                        fontFamily: 'monospace',
                        color: 'text.primary',
                        bgcolor: 'background.paper',
                        '&:hover': { bgcolor: 'action.hover' },
                        '&.Mui-selected': { bgcolor: `${tokens.accent.primary}33` }
                      }}>
                        {m.name} {m.is_local && '(Local)'}
                      </MenuItem>
                    ))
                  ) : (
                    <MenuItem disabled value="">
                      No models found. Check your {selectedProvider === 'ollama' ? 'host' : 'API key'}.
                    </MenuItem>
                  )}
                </TextField>
              </Box>
              )}

              {/* Default Toggle */}
              <FormControlLabel
                control={
                  <Switch 
                    checked={form.is_active} 
                    onChange={(e) => setForm({ ...form, is_active: e.target.checked })}
                    sx={{
                      '& .MuiSwitch-switchBase.Mui-checked': { color: tokens.accent.primary },
                      '& .MuiSwitch-switchBase.Mui-checked + .MuiSwitch-track': { bgcolor: tokens.accent.primary }
                    }}
                  />
                }
                label={
                  <Typography sx={{ color: 'text.primary', fontSize: '0.85rem', fontFamily: 'Orbitron' }}>
                    SET AS DEFAULT LLM
                  </Typography>
                }
              />

              {/* Actions */}
              <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 2, pt: 2 }}>
                <Button
                  variant="contained"
                  startIcon={<Save size={20} />}
                  onClick={() => handleSave('save')}
                  disabled={updateSettings.isPending}
                  sx={{
                    bgcolor: `${tokens.accent.primary}1A`,
                    color: tokens.accent.primary,
                    border: `1px solid ${tokens.accent.primary}4D`,
                    fontFamily: 'Orbitron',
                    fontWeight: 800,
                    px: 4,
                    '&:hover': { bgcolor: `${tokens.accent.primary}33` }
                  }}
                >
                  {updateSettings.isPending ? 'SAVING...' : 'SAVE CONFIG'}
                </Button>

                <Button
                  variant="outlined"
                  startIcon={testConnection.isPending ? <CircularProgress size={16} sx={{ color: '#a78bfa' }} /> : <Wifi size={20} />}
                  onClick={handleTest}
                  disabled={testConnection.isPending || (selectedProvider === 'ollama' && !ollamaStatus?.running)}
                  sx={{
                    borderColor: 'rgba(167, 139, 250, 0.3)',
                    color: '#a78bfa',
                    fontFamily: 'Orbitron',
                    fontWeight: 800,
                    px: 4,
                    '&:hover': { borderColor: '#a78bfa', bgcolor: 'rgba(167, 139, 250, 0.05)' }
                  }}
                >
                  {testConnection.isPending ? 'TESTING...' : 'TEST CONNECTION'}
                </Button>

                {selectedProvider === 'ollama' && currentModel && !currentModel.is_local && (
                  <Button
                    variant="outlined"
                    startIcon={<Download size={20} />}
                    onClick={() => handleSave('pull')}
                    disabled={updateSettings.isPending || !!pullingModel}
                    sx={{
                      borderColor: 'rgba(255, 214, 0, 0.3)',
                      color: '#ffd600',
                      fontFamily: 'Orbitron',
                      fontWeight: 800,
                      px: 4,
                      '&:hover': { borderColor: '#ffd600', bgcolor: 'rgba(255, 214, 0, 0.05)' }
                    }}
                  >
                    DOWNLOAD MODEL
                  </Button>
                )}
              </Box>

              {/* Test Connection Result */}
              {testResult && (
                <Box sx={{
                  mt: 1,
                  p: 2,
                  borderRadius: '12px',
                  bgcolor: testResult.status === 'success'
                    ? `${tokens.accent.primary}0D`
                    : 'rgba(255, 49, 49, 0.05)',
                  border: `1px solid ${testResult.status === 'success' ? `${tokens.accent.primary}33` : 'rgba(255, 49, 49, 0.2)'}`,
                }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: testResult.response ? 1.5 : 0 }}>
                    {testResult.status === 'success'
                      ? <CheckCircle2 size={16} color={tokens.accent.primary} />
                      : <XCircle size={16} color="#ff3131" />
                    }
                    <Typography sx={{
                      fontSize: '0.8rem',
                      fontFamily: 'Orbitron',
                      fontWeight: 700,
                      color: testResult.status === 'success' ? tokens.accent.primary : '#ff3131',
                    }}>
                      {testResult.message}
                    </Typography>
                  </Box>
                  {testResult.response && (
                    <Box sx={{
                      mt: 1,
                      p: 1.5,
                      borderRadius: '8px',
                      bgcolor: 'background.default',
                      fontFamily: 'monospace',
                      fontSize: '0.78rem',
                      color: 'text.secondary',
                      wordBreak: 'break-word',
                    }}>
                      <Typography component="span" sx={{ color: `${tokens.accent.primary}80`, fontSize: '10px', fontFamily: 'Orbitron', mr: 1 }}>
                        RESPONSE:
                      </Typography>
                      {testResult.response}
                    </Box>
                  )}
                </Box>
              )}

              {/* Terminal */}
              {(pullingModel || pullStatus) && (
                <Box sx={{ mt: 4 }}>
                  <Paper sx={{ 
                    bgcolor: 'background.default', 
                    borderRadius: '12px', 
                    border: 1,
                    borderColor: 'divider',
                    overflow: 'hidden'
                  }}>
                    <Box sx={{ 
                      px: 2, 
                      py: 1, 
                      bgcolor: 'background.paper', 
                      display: 'flex', 
                      justifyContent: 'space-between', 
                      alignItems: 'center' 
                    }}>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <TerminalIcon size={14} color={tokens.accent.primary} />
                        <Typography sx={{ color: 'text.primary', fontSize: '10px', fontFamily: 'monospace' }}>
                          OLLAMA PULL: {pullingModel}
                        </Typography>
                      </Box>
                      <Typography sx={{ 
                        fontSize: '10px', 
                        fontFamily: 'Orbitron', 
                        color: pullStatus?.status === 'success' ? tokens.accent.primary : pullStatus?.status === 'failed' ? '#ff3131' : '#ffd600'
                      }}>
                        {pullStatus?.status.toUpperCase() || 'INITIATING'}
                      </Typography>
                    </Box>
                    <Box 
                      ref={terminalRef}
                      sx={{ 
                        p: 2, 
                        height: '200px', 
                        overflowY: 'auto', 
                        fontFamily: 'monospace', 
                        fontSize: '12px', 
                        color: '#10b981',
                        whiteSpace: 'pre-wrap',
                        '&::-webkit-scrollbar': { width: '4px' },
                        '&::-webkit-scrollbar-thumb': { bgcolor: `${tokens.accent.primary}33` }
                      }}
                    >
                      {pullStatus?.log || 'Preparing environment...'}
                    </Box>
                  </Paper>
                </Box>
              )}
            </Stack>
          </TacticalPanel>
        </Grid>

        {/* Model Info Sidebar (Ollama only) */}
        {selectedProvider === 'ollama' && (
          <Grid size={{xs: 12, lg: 3}} >
            <TacticalPanel title="MODEL INSIGHTS" icon={<Info size={18} />}>
              {!currentModel ? (
                <Box sx={{ textAlign: 'center', py: 4 }}>
                  <Ghost size={40} color="rgba(255,255,255,0.1)" />
                  <Typography variant="body2" sx={{ color: 'text.disabled', mt: 2 }}>
                    Select a model to view technical specifications.
                  </Typography>
                </Box>
              ) : (
                <Stack spacing={3}>
                  <Typography variant="body2" sx={{ color: 'text.secondary', fontSize: '0.8rem', lineHeight: 1.6 }}>
                    {currentModel.description || 'No detailed description available for this model variant.'}
                  </Typography>
                  
                  <Box>
                    <Typography sx={{ color: `${tokens.accent.primary}80`, fontSize: '10px', fontFamily: 'Orbitron', mb: 0.5 }}>EXPERTISE</Typography>
                    <Typography sx={{ color: 'text.primary', fontSize: '0.9rem', fontWeight: 600 }}>{currentModel.expertise || 'General Purpose'}</Typography>
                  </Box>

                  <Box>
                    <Typography sx={{ color: `${tokens.accent.primary}80`, fontSize: '10px', fontFamily: 'Orbitron', mb: 0.5 }}>DISK FOOTPRINT</Typography>
                    <Typography sx={{ color: 'text.primary', fontSize: '0.9rem', fontWeight: 600 }}>{currentModel.size || 'N/A'}</Typography>
                  </Box>

                  <Box>
                    <Typography sx={{ color: `${tokens.accent.primary}80`, fontSize: '10px', fontFamily: 'Orbitron', mb: 0.5 }}>SUGGESTED RAM</Typography>
                    <Typography sx={{ color: 'text.primary', fontSize: '0.9rem', fontWeight: 600 }}>{currentModel.suggested_ram || 'N/A'}</Typography>
                  </Box>

                  <Alert 
                    severity="warning" 
                    icon={<AlertCircle size={20} />}
                    sx={{ 
                      bgcolor: 'rgba(255, 214, 0, 0.05)', 
                      color: '#ffd600',
                      border: '1px solid rgba(255, 214, 0, 0.2)',
                      fontSize: '11px',
                      '& .MuiAlert-icon': { color: '#ffd600' }
                    }}
                  >
                    Local models perform significantly better with GPU acceleration. CPU inference may result in high latency.
                  </Alert>
                </Stack>
              )}
            </TacticalPanel>
          </Grid>
        )}
      </Grid>

      <Snackbar 
        open={snackbar.open} 
        autoHideDuration={6000} 
        onClose={handleCloseSnackbar}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        <Alert 
          onClose={handleCloseSnackbar} 
          severity={snackbar.severity} 
          variant="filled"
          sx={{ 
            fontFamily: 'Orbitron', 
            fontSize: '0.8rem',
            fontWeight: 700,
            bgcolor: snackbar.severity === 'success' ? `${tokens.accent.primary}E6` : snackbar.severity === 'info' ? `${tokens.accent.primary}B3` : 'rgba(255, 0, 85, 0.9)',
            color: '#000',
            '& .MuiAlert-icon': { color: '#000' }
          }}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
};
