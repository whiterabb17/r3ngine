import React, { useState } from 'react';
import {
  Box,
  Chip,
  FormControlLabel,
  Stack,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  ToggleButton,
  ToggleButtonGroup,
  Typography,
} from '@mui/material';
import { Cable, KeyRound } from 'lucide-react';
import { useAuth } from '../../../context/AuthContext';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import { getFieldSx, getHttpStatusColor } from '../../../theme/semanticColors';
import { TacticalPanel } from '../../../components/TacticalPanel';
import {
  useMcpAudit,
  useMcpSettings,
  useUpdateMcpSettings,
  type McpAuditEvent,
  type McpTransportMode,
} from '../api/mcp';
import { McpKeysPanel } from './McpKeysPanel';
import { McpConnectedAgentsPanel } from './McpConnectedAgentsPanel';
import { McpFollowupsPanel } from './McpFollowupsPanel';
import { McpReplayDialog } from './McpReplayDialog';

export const McpAccessPage: React.FC = () => {
  const { user } = useAuth();
  const { tokens, isLight, theme } = useThemeTokens();
  const { data: settings } = useMcpSettings();
  const updateSettings = useUpdateMcpSettings();
  const isAdmin = user?.role === 'sys_admin';
  const [toolName, setToolName] = useState('');
  const [statusCode, setStatusCode] = useState('');
  const [allUsers, setAllUsers] = useState(false);
  const [focusKeyId, setFocusKeyId] = useState<number | null>(null);
  const [replay, setReplay] = useState<McpAuditEvent | null>(null);
  const { data: audit } = useMcpAudit({
    tool_name: toolName,
    status_code: statusCode,
    all: isAdmin && allUsers,
  });
  const fieldSx = getFieldSx(isLight, tokens);

  return (
    <Box>
      <Box sx={{ mb: 3 }}>
        <Typography
          variant="h5"
          sx={{ color: theme.palette.text.primary, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 1 }}
        >
          <KeyRound size={24} color={tokens.accent.primary} />
          MCP Access
        </Typography>
        <Typography variant="body2" sx={{ color: theme.palette.text.secondary, mt: 0.5 }}>
          Connect IDE agents with a named API key. Sessions and the audit chain stay in this page.
        </Typography>
      </Box>

      {isAdmin && (
        <TacticalPanel title="Transport" icon={<Cable size={20} />}>
          <Typography variant="body2" sx={{ mb: 2, color: theme.palette.text.secondary }}>
            stdio is a local IDE process. HTTP exposes `/mcp`. Both enables either client.
          </Typography>
          <ToggleButtonGroup
            exclusive
            value={settings?.transport_mode || 'stdio'}
            onChange={(_, value: McpTransportMode | null) => {
              if (value) updateSettings.mutate(value);
            }}
          >
            <ToggleButton value="stdio">stdio</ToggleButton>
            <ToggleButton value="http">HTTP</ToggleButton>
            <ToggleButton value="both">Both</ToggleButton>
          </ToggleButtonGroup>
        </TacticalPanel>
      )}

      <Box sx={{ mt: 3 }}>
        <McpKeysPanel focusKeyId={focusKeyId} />
      </Box>
      <Box sx={{ mt: 3 }}>
        <McpConnectedAgentsPanel
          isAdmin={isAdmin}
          onFocusKey={(keyId) => {
            setFocusKeyId(keyId);
            document.getElementById(`mcp-key-${keyId}`)?.scrollIntoView({ behavior: 'smooth', block: 'center' });
          }}
        />
      </Box>
      <Box sx={{ mt: 3 }}>
        <McpFollowupsPanel />
      </Box>

      <Box sx={{ mt: 3 }}>
        <TacticalPanel title="Audit">
          <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} sx={{ mb: 2 }}>
            <TextField
              size="small"
              label="Tool"
              value={toolName}
              onChange={(event) => setToolName(event.target.value)}
              sx={fieldSx}
            />
            <TextField
              size="small"
              label="Status"
              value={statusCode}
              onChange={(event) => setStatusCode(event.target.value)}
              sx={fieldSx}
            />
            {isAdmin && (
              <FormControlLabel
                control={
                  <Switch checked={allUsers} onChange={(event) => setAllUsers(event.target.checked)} />
                }
                label="All users"
              />
            )}
          </Stack>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Time</TableCell>
                <TableCell>Tool</TableCell>
                <TableCell>Agent</TableCell>
                <TableCell>Path</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Duration</TableCell>
                <TableCell />
              </TableRow>
            </TableHead>
            <TableBody>
              {(audit?.items || []).map((row) => {
                const agentLabel = row.provider
                  ? row.hostname
                    ? `${row.provider} @ ${row.hostname}`
                    : row.provider
                  : row.hostname || 'Unknown agent';
                return (
                  <TableRow
                    key={row.id}
                    hover
                    tabIndex={0}
                    role="button"
                    aria-label={`Replay ${row.tool_name || row.path}`}
                    sx={{ cursor: 'pointer' }}
                    onClick={() => setReplay(row)}
                    onKeyDown={(event) => {
                      if (event.key === 'Enter' || event.key === ' ') {
                        event.preventDefault();
                        setReplay(row);
                      }
                    }}
                  >
                    <TableCell>
                      {row.created_at ? new Date(row.created_at).toLocaleString() : ''}
                    </TableCell>
                    <TableCell>{row.tool_name}</TableCell>
                    <TableCell>{agentLabel}</TableCell>
                    <TableCell>{row.path}</TableCell>
                    <TableCell>
                      <Chip
                        size="small"
                        label={row.status_code}
                        variant="outlined"
                        sx={{
                          color: getHttpStatusColor(row.status_code, tokens),
                          borderColor: getHttpStatusColor(row.status_code, tokens),
                        }}
                      />
                    </TableCell>
                    <TableCell>{row.duration_ms}ms</TableCell>
                    <TableCell>Replay</TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
          {!audit?.items?.length && (
            <Typography variant="body2" sx={{ color: theme.palette.text.secondary, p: 2 }}>
              No MCP round-trips yet.
            </Typography>
          )}
        </TacticalPanel>
      </Box>
      <McpReplayDialog
        event={replay}
        onClose={() => setReplay(null)}
        onFocusKey={(keyId) => {
          setFocusKeyId(keyId);
          document.getElementById(`mcp-key-${keyId}`)?.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }}
      />
    </Box>
  );
};
