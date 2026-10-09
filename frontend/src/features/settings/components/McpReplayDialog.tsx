import React from 'react';
import {
  Alert,
  Box,
  Button,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Link,
  Stack,
  Typography,
} from '@mui/material';
import type { McpAuditEvent } from '../api/mcp';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import { getDialogPaperSx, getHttpStatusColor } from '../../../theme/semanticColors';

export function McpJsonBlock({
  value,
  tokens,
  maxHeight = 240,
}: {
  value: unknown;
  tokens: ReturnType<typeof useThemeTokens>['tokens'];
  maxHeight?: number;
}) {
  return (
    <Box
      component="pre"
      sx={{
        m: 0,
        p: 1.5,
        fontSize: 12,
        overflow: 'auto',
        maxHeight,
        color: tokens.text.primary,
        bgcolor: tokens.surface.elevated,
        border: `1px solid ${tokens.border.subtle}`,
        borderRadius: 1,
      }}
    >
      {JSON.stringify(value ?? null, null, 2)}
    </Box>
  );
}

function shortAgentId(agentId: string) {
  if (agentId.length <= 16) return agentId;
  return `${agentId.slice(0, 8)}…${agentId.slice(-4)}`;
}

export const McpReplayDialog: React.FC<{
  event: McpAuditEvent | null;
  onClose: () => void;
  onFocusKey?: (keyId: number) => void;
}> = ({ event, onClose, onFocusKey }) => {
  const { tokens, isLight, theme } = useThemeTokens();
  const provider = event?.provider || event?.client_name || '';
  const host = event?.hostname || '';
  const agentLabel = provider
    ? host
      ? `${provider} @ ${host}`
      : provider
    : host || 'Unknown agent';

  return (
    <Dialog
      open={!!event}
      onClose={onClose}
      fullWidth
      maxWidth="md"
      sx={{ zIndex: (muiTheme) => muiTheme.zIndex.modal }}
      slotProps={{ paper: { sx: getDialogPaperSx(isLight, theme, tokens) } }}
    >
      <DialogTitle>Replay MCP request</DialogTitle>
      {event && (
        <DialogContent>
          <Alert severity="info" sx={{ mb: 2 }}>
            Stored replay — this does not call r3ngine again.
          </Alert>

          <Typography variant="overline" sx={{ color: theme.palette.text.secondary }}>
            Agent
          </Typography>
          <Stack direction="row" spacing={1} useFlexGap sx={{ flexWrap: 'wrap', mb: 2, mt: 0.5 }}>
            <Chip size="small" label={agentLabel} />
            {(event.ide || event.os_name) && (
              <Chip size="small" variant="outlined" label={[event.ide, event.os_name].filter(Boolean).join(' / ')} />
            )}
            {event.agent_username && (
              <Chip size="small" variant="outlined" label={event.agent_username} />
            )}
            {event.transport && (
              <Chip size="small" variant="outlined" label={event.transport} />
            )}
          </Stack>
          {event.agent_id && (
            <Typography
              variant="caption"
              sx={{ display: 'block', color: theme.palette.text.secondary, fontFamily: 'monospace', mb: 1 }}
            >
              {shortAgentId(event.agent_id)}
            </Typography>
          )}
          {event.key_id ? (
            <Link
              component="button"
              type="button"
              onClick={() => {
                onFocusKey?.(event.key_id as number);
                onClose();
              }}
              sx={{ color: tokens.accent.primary, fontFamily: 'monospace', display: 'block', mb: 2 }}
            >
              {event.key_name || 'key'} ({event.key_prefix})
            </Link>
          ) : (
            event.key_name && (
              <Typography variant="caption" sx={{ display: 'block', mb: 2, fontFamily: 'monospace' }}>
                {event.key_name} {event.key_prefix}
              </Typography>
            )
          )}

          <Typography variant="overline" sx={{ color: theme.palette.text.secondary }}>
            Request
          </Typography>
          <Stack direction="row" spacing={1} useFlexGap sx={{ flexWrap: 'wrap', mb: 1, mt: 0.5 }}>
            <Typography variant="body2">{event.tool_name || event.path}</Typography>
            <Chip size="small" variant="outlined" label={`${event.method} ${event.path}`} />
            {event.created_at && (
              <Typography variant="caption" sx={{ color: theme.palette.text.secondary, alignSelf: 'center' }}>
                {new Date(event.created_at).toLocaleString()}
              </Typography>
            )}
          </Stack>
          <McpJsonBlock value={event.request_body} tokens={tokens} maxHeight={280} />

          <Typography variant="overline" sx={{ color: theme.palette.text.secondary, mt: 2, display: 'block' }}>
            Response
          </Typography>
          <Stack direction="row" spacing={1} useFlexGap sx={{ flexWrap: 'wrap', mb: 1, mt: 0.5 }}>
            <Chip
              size="small"
              label={event.status_code}
              variant="outlined"
              sx={{
                color: getHttpStatusColor(event.status_code, tokens),
                borderColor: getHttpStatusColor(event.status_code, tokens),
              }}
            />
            <Chip size="small" variant="outlined" label={`${event.duration_ms}ms`} />
            {event.truncated && <Chip size="small" label="truncated" />}
          </Stack>
          {event.error_message && (
            <Alert severity="error" sx={{ mb: 1 }}>
              {event.error_message}
            </Alert>
          )}
          <McpJsonBlock value={event.response_body} tokens={tokens} maxHeight={280} />
        </DialogContent>
      )}
      <DialogActions>
        <Button onClick={onClose}>Close</Button>
      </DialogActions>
    </Dialog>
  );
};
