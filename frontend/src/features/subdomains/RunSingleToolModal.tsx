import React, { startTransition, useEffect, useId, useMemo, useState } from 'react';
import {
  Box,
  Button,
  Checkbox,
  Chip,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControl,
  FormControlLabel,
  InputLabel,
  MenuItem,
  Select,
  TextField,
  Typography,
} from '@mui/material';
import { RefreshCw, Wrench } from 'lucide-react';
import { alpha } from '@mui/material/styles';
import { useThemeTokens } from '../../theme/useThemeTokens';
import { getDialogPaperSx, getFieldSx } from '../../theme/semanticColors';
import {
  useCapabilities,
  useRunTool,
  useToolArgs,
  type CapabilityTool,
  type ToolArgField,
} from './api';
import { useQueryClient } from '@tanstack/react-query';
import axios from '../../api/axiosConfig';

export interface RunSingleToolModalProps {
  open: boolean;
  onClose: () => void;
  subdomainId: number;
  subdomainName: string;
  scanHistoryId: number;
  onSuccess?: (message: string) => void;
  onError?: (message: string) => void;
}

function riskAccent(
  risk: string | undefined,
  tokens: ReturnType<typeof useThemeTokens>['tokens'],
): string {
  if (risk === 'vuln') return tokens.accent.error;
  if (risk === 'active') return tokens.accent.warning;
  if (risk === 'recon') return tokens.accent.info;
  return tokens.text.secondary;
}

function buildToolArgs(
  schema: ToolArgField[],
  values: Record<string, unknown>,
): Record<string, unknown> | undefined {
  const tool_args: Record<string, unknown> = {};
  for (const field of schema) {
    const key = field.name;
    if (!(key in values)) continue;
    const v = values[key];
    if (v === '' || v === undefined || v === null) continue;
    if (field.type === 'bool' && v === false) continue;
    tool_args[key] = v;
  }
  return Object.keys(tool_args).length ? tool_args : undefined;
}

export const RunSingleToolModal: React.FC<RunSingleToolModalProps> = ({
  open,
  onClose,
  subdomainId,
  subdomainName,
  scanHistoryId,
  onSuccess,
  onError,
}) => {
  const titleId = useId();
  const descId = useId();
  const { tokens, isLight, theme } = useThemeTokens();
  const queryClient = useQueryClient();
  const { data: caps, isLoading: capsLoading, isError: capsError } = useCapabilities();
  const [selectedTool, setSelectedTool] = useState('');
  const {
    data: argsPayload,
    isLoading: argsLoading,
    isFetching,
    isError: argsError,
  } = useToolArgs(selectedTool || null);
  const [schemaRefreshing, setSchemaRefreshing] = useState(false);
  const runTool = useRunTool();
  const [values, setValues] = useState<Record<string, unknown>>({});

  const subdomainTools = useMemo(() => {
    const tasks = caps?.pipeline_tasks || [];
    return [...tasks]
      .filter((t: CapabilityTool) => (t.asset_kinds || []).includes('subdomain'))
      .sort((a, b) => a.title.localeCompare(b.title));
  }, [caps]);

  const selectedMeta = useMemo(
    () => subdomainTools.find((t) => t.name === selectedTool),
    [subdomainTools, selectedTool],
  );

  useEffect(() => {
    if (!open) {
      setSelectedTool('');
      setValues({});
      setSchemaRefreshing(false);
    }
  }, [open]);

  useEffect(() => {
    startTransition(() => {
      setValues({});
    });
  }, [selectedTool]);

  const schema: ToolArgField[] = argsPayload?.schema || [];
  const canRun = Boolean(selectedTool && scanHistoryId && !runTool.isPending && !argsLoading);

  const handleRun = async () => {
    if (!canRun) return;
    try {
      const res = await runTool.mutateAsync({
        tool: selectedTool,
        asset_type: 'subdomain',
        asset_id: subdomainId,
        scan_history_id: scanHistoryId,
        tool_args: buildToolArgs(schema, values),
      });
      onSuccess?.(
        `Started ${selectedMeta?.title || selectedTool} on ${subdomainName}` +
          (res?.activity_id ? ` · activity #${res.activity_id}` : ''),
      );
      onClose();
    } catch (err: unknown) {
      onError?.(err instanceof Error ? err.message : 'Could not start tool');
    }
  };

  const borderSubtle = tokens.border.subtle;
  const accentSoft = alpha(tokens.accent.primary, isLight ? 0.08 : 0.12);
  const accentBorder = alpha(tokens.accent.primary, isLight ? 0.28 : 0.35);
  const stripBg = alpha(tokens.accent.primary, isLight ? 0.04 : 0.08);
  const chipSx = {
    height: 22,
    fontSize: '0.65rem',
    fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
    bgcolor: alpha(tokens.text.primary, isLight ? 0.04 : 0.08),
    color: tokens.text.secondary,
    border: `1px solid ${borderSubtle}`,
  };
  const riskColor = riskAccent(selectedMeta?.risk, tokens);

  return (
    <Dialog
      open={open}
      onClose={onClose}
      maxWidth="sm"
      fullWidth
      aria-labelledby={titleId}
      aria-describedby={descId}
      slotProps={{
        paper: {
          sx: {
            ...getDialogPaperSx(isLight, theme, tokens),
            border: `1px solid ${borderSubtle}`,
            overflow: 'hidden',
          },
        },
      }}
    >
      <DialogTitle
        id={titleId}
        sx={{
          color: tokens.accent.primary,
          fontFamily: 'Orbitron',
          fontSize: '0.85rem',
          letterSpacing: 2,
          display: 'flex',
          alignItems: 'center',
          gap: 1,
          pb: 1,
        }}
      >
        <Wrench size={16} aria-hidden color={tokens.accent.primary} />
        RUN SINGLE TOOL
      </DialogTitle>

      <DialogContent sx={{ pt: '8px !important' }}>
        <Box
          id={descId}
          sx={{
            mb: 2.5,
            px: 1.5,
            py: 1.25,
            borderRadius: 1,
            border: `1px solid ${borderSubtle}`,
            bgcolor: stripBg,
            fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
          }}
        >
          <Typography sx={{ fontSize: '0.65rem', color: 'text.secondary', letterSpacing: 1, mb: 0.5 }}>
            TARGET
          </Typography>
          <Typography sx={{ fontSize: '0.85rem', fontWeight: 700, color: 'text.primary', wordBreak: 'break-all' }}>
            {subdomainName}
          </Typography>
          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.75, mt: 1 }}>
            <Chip size="small" label={`scan #${scanHistoryId}`} sx={chipSx} />
            {selectedTool && argsPayload?.binary_name && (
              <Chip
                size="small"
                label={argsPayload.binary_name}
                sx={{
                  ...chipSx,
                  bgcolor: accentSoft,
                  color: tokens.accent.primary,
                  border: `1px solid ${accentBorder}`,
                }}
              />
            )}
            {argsPayload?.version && (
              <Chip size="small" label={argsPayload.version} sx={chipSx} />
            )}
            {argsPayload?.source && (
              <Chip
                size="small"
                label={argsPayload.source === 'help' ? 'live help' : 'seed schema'}
                sx={chipSx}
              />
            )}
            {selectedMeta?.risk && (
              <Chip
                size="small"
                label={selectedMeta.risk}
                sx={{
                  ...chipSx,
                  bgcolor: alpha(riskColor, isLight ? 0.1 : 0.16),
                  color: riskColor,
                  border: `1px solid ${alpha(riskColor, 0.35)}`,
                  textTransform: 'uppercase',
                }}
              />
            )}
          </Box>
          <Typography sx={{ mt: 1, fontSize: '0.7rem', color: 'text.secondary', lineHeight: 1.4 }}>
            One pipeline tool on this host. Args come from the binary installed here — not a global template.
          </Typography>
        </Box>

        {capsError && (
          <Typography role="alert" sx={{ color: tokens.accent.error, fontSize: '0.75rem', mb: 2 }}>
            Could not load tools. Check your session and try again.
          </Typography>
        )}

        <FormControl fullWidth size="small" sx={{ mb: 2 }}>
          <InputLabel id={`${titleId}-tool-label`} sx={{ color: 'text.secondary', fontSize: '0.8rem' }}>
            Tool
          </InputLabel>
          <Select
            labelId={`${titleId}-tool-label`}
            value={selectedTool}
            label="Tool"
            disabled={capsLoading || !!capsError}
            onChange={(e) => setSelectedTool(String(e.target.value))}
            sx={{ color: 'text.primary', ...getFieldSx(isLight, tokens) }}
          >
            {subdomainTools.map((t) => (
              <MenuItem key={t.name} value={t.name}>
                <Box sx={{ display: 'flex', alignItems: 'baseline', gap: 1, width: '100%' }}>
                  <Typography component="span" sx={{ fontSize: '0.85rem', fontWeight: 600 }}>
                    {t.title}
                  </Typography>
                  <Typography component="span" sx={{ fontSize: '0.7rem', color: 'text.secondary', fontFamily: 'monospace' }}>
                    {t.name}
                  </Typography>
                </Box>
              </MenuItem>
            ))}
          </Select>
        </FormControl>

        {selectedTool && (
          <Box>
            <Box
              sx={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                gap: 1,
                mb: 1.25,
              }}
            >
              <Typography
                component="h3"
                sx={{
                  color: tokens.accent.primary,
                  fontSize: '0.65rem',
                  fontWeight: 900,
                  fontFamily: 'Orbitron',
                  letterSpacing: 1.5,
                  m: 0,
                }}
              >
                ARGUMENTS
              </Typography>
              <Button
                size="small"
                disabled={schemaRefreshing || !selectedTool}
                startIcon={
                  schemaRefreshing ? (
                    <CircularProgress size={12} sx={{ color: 'inherit' }} />
                  ) : (
                    <RefreshCw size={12} aria-hidden color={tokens.accent.primary} />
                  )
                }
                onClick={() => {
                  if (!selectedTool) return;
                  setSchemaRefreshing(true);
                  void axios
                    .get(`/api/action/tool/${encodeURIComponent(selectedTool)}/args/`, {
                      params: { refresh: 1 },
                    })
                    .then((res: { data: unknown }) => {
                      queryClient.setQueryData(['tool-args', selectedTool], res.data);
                    })
                    .catch(() => {
                      onError?.('Could not refresh argument schema from host');
                    })
                    .finally(() => setSchemaRefreshing(false));
                }}
                aria-label="Refresh argument schema from installed binary"
                sx={{ fontSize: '0.65rem', color: tokens.accent.primary, minWidth: 0 }}
              >
                Refresh from host
              </Button>
            </Box>

            {argsError && (
              <Typography role="alert" sx={{ color: tokens.accent.error, fontSize: '0.75rem', mb: 1.5 }}>
                Could not load args for this tool. Refresh or pick another tool.
              </Typography>
            )}

            {(argsLoading || (isFetching && !argsPayload)) && (
              <Box
                sx={{ display: 'flex', alignItems: 'center', gap: 1.5, py: 2 }}
                aria-busy="true"
                aria-live="polite"
              >
                <CircularProgress size={20} sx={{ color: tokens.accent.primary }} />
                <Typography sx={{ fontSize: '0.75rem', color: 'text.secondary' }}>
                  Reading installed binary help…
                </Typography>
              </Box>
            )}

            {!argsLoading && !argsError && schema.length === 0 && (
              <Typography sx={{ fontSize: '0.75rem', color: 'text.secondary', mb: 1 }}>
                No configurable flags on this host. You can still run with engine defaults.
              </Typography>
            )}

            {!argsLoading &&
              schema.map((field) => {
                const key = field.name;
                const label = field.long_flag || key;
                if (field.type === 'bool') {
                  return (
                    <FormControlLabel
                      key={key}
                      sx={{ display: 'flex', alignItems: 'flex-start', ml: 0, mb: 0.75 }}
                      control={
                        <Checkbox
                          size="small"
                          checked={Boolean(values[key])}
                          onChange={(e) =>
                            setValues((prev) => ({ ...prev, [key]: e.target.checked }))
                          }
                          slotProps={{
                            input: {
                              'aria-describedby': field.description ? `${titleId}-${key}-help` : undefined,
                            },
                          }}
                          sx={{
                            color: alpha(tokens.accent.primary, 0.35),
                            '&.Mui-checked': { color: tokens.accent.primary },
                            mt: -0.25,
                          }}
                        />
                      }
                      label={
                        <Box>
                          <Typography sx={{ fontSize: '0.8rem', color: 'text.primary', fontFamily: 'monospace' }}>
                            {label}
                          </Typography>
                          {field.description ? (
                            <Typography
                              id={`${titleId}-${key}-help`}
                              sx={{ fontSize: '0.7rem', color: 'text.secondary', lineHeight: 1.35 }}
                            >
                              {field.description}
                            </Typography>
                          ) : null}
                        </Box>
                      }
                    />
                  );
                }
                return (
                  <TextField
                    key={key}
                    fullWidth
                    size="small"
                    type={field.type === 'int' || field.type === 'float' ? 'number' : 'text'}
                    label={label}
                    helperText={field.description}
                    value={values[key] ?? ''}
                    onChange={(e) => {
                      const raw = e.target.value;
                      setValues((prev) => ({
                        ...prev,
                        [key]:
                          field.type === 'int'
                            ? raw === ''
                              ? ''
                              : Number.parseInt(raw, 10)
                            : field.type === 'float'
                              ? raw === ''
                                ? ''
                                : Number.parseFloat(raw)
                              : raw,
                      }));
                    }}
                    sx={{ mb: 1.5, ...getFieldSx(isLight, tokens) }}
                    slotProps={{
                      inputLabel: { sx: { fontFamily: 'monospace', fontSize: '0.85rem' } },
                      formHelperText: { sx: { fontSize: '0.7rem' } },
                    }}
                  />
                );
              })}
          </Box>
        )}
      </DialogContent>

      <DialogActions sx={{ p: 2, borderTop: '1px solid', borderColor: 'divider', gap: 1 }}>
        <Button onClick={onClose} sx={{ color: 'text.secondary', fontSize: '0.7rem' }}>
          Cancel
        </Button>
        <Button
          variant="contained"
          disabled={!canRun}
          onClick={() => void handleRun()}
          aria-busy={runTool.isPending}
          sx={{
            bgcolor: accentSoft,
            color: tokens.accent.primary,
            border: `1px solid ${accentBorder}`,
            fontFamily: 'Orbitron',
            fontSize: '0.7rem',
            fontWeight: 900,
            letterSpacing: 1,
            boxShadow: 'none',
            '&:hover': {
              bgcolor: alpha(tokens.accent.primary, isLight ? 0.14 : 0.22),
              boxShadow: 'none',
            },
            '&.Mui-disabled': { opacity: 0.45 },
          }}
        >
          {runTool.isPending ? 'Starting…' : 'Run tool'}
        </Button>
      </DialogActions>
    </Dialog>
  );
};
