import React, { useState } from 'react';
import {
  Alert,
  Button,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControl,
  FormControlLabel,
  IconButton,
  Link,
  Radio,
  RadioGroup,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  Tooltip,
  Typography,
} from '@mui/material';
import { Ban, Trash2 } from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import {
  useDeleteMcpAgent,
  useMcpSessions,
  useRevokeMcpSession,
  type McpSession,
} from '../api/mcp';
import { McpAuditChainDrawer } from './McpAuditChainDrawer';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import { getDialogPaperSx } from '../../../theme/semanticColors';
import { TacticalPanel } from '../../../components/TacticalPanel';

export const McpConnectedAgentsPanel: React.FC<{
  isAdmin?: boolean;
  onFocusKey?: (keyId: number) => void;
}> = ({ isAdmin = false, onFocusKey }) => {
  const { tokens, isLight, theme } = useThemeTokens();
  const { data } = useMcpSessions();
  const revokeSession = useRevokeMcpSession();
  const deleteAgent = useDeleteMcpAgent();
  const [auditId, setAuditId] = useState<string | null>(null);
  const [pending, setPending] = useState<McpSession | null>(null);
  const [deleting, setDeleting] = useState<McpSession | null>(null);
  const [persistBan, setPersistBan] = useState(true);

  const statusColor = (status: McpSession['status']) => {
    if (status === 'connected') return tokens.accent.success;
    if (status === 'idle') return tokens.accent.warning;
    if (status === 'revoked') return tokens.accent.error;
    return tokens.text.disabled;
  };

  const agentLabel = (row: McpSession) => {
    const provider = row.provider || row.client_name || 'unknown';
    const host = row.hostname || row.device_id || '';
    return host ? `${provider} @ ${host}` : provider;
  };

  return (
    <>
      <TacticalPanel title="Connected agents">
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Agent</TableCell>
              <TableCell>Key</TableCell>
              <TableCell>IDE / OS</TableCell>
              <TableCell>User</TableCell>
              <TableCell>Requests</TableCell>
              <TableCell>Last seen</TableCell>
              <TableCell>Status</TableCell>
              <TableCell />
            </TableRow>
          </TableHead>
          <TableBody>
            {(data?.items || []).map((row) => (
              <TableRow
                key={row.agent_id || row.session_id}
                hover
                sx={{ cursor: 'pointer' }}
                onClick={() => setAuditId(row.session_id)}
              >
                <TableCell>
                  {agentLabel(row)}
                  {row.banned && (
                    <Chip size="small" label="banned" sx={{ ml: 1 }} color="error" variant="outlined" />
                  )}
                </TableCell>
                <TableCell sx={{ fontFamily: 'monospace' }}>
                  <Link
                    component="button"
                    type="button"
                    onClick={(event) => {
                      event.stopPropagation();
                      onFocusKey?.(row.key_id);
                    }}
                    sx={{ color: tokens.accent.primary, fontFamily: 'inherit' }}
                  >
                    {row.key_name}
                  </Link>
                  <Typography variant="caption" sx={{ display: 'block', color: theme.palette.text.secondary }}>
                    {row.key_prefix}
                  </Typography>
                </TableCell>
                <TableCell>
                  {row.ide || '—'}
                  <Typography variant="caption" sx={{ display: 'block', color: theme.palette.text.secondary }}>
                    {row.os_name || '—'}
                  </Typography>
                </TableCell>
                <TableCell>{row.agent_username || '—'}</TableCell>
                <TableCell>{row.request_count ?? '—'}</TableCell>
                <TableCell>
                  {row.last_seen_at
                    ? formatDistanceToNow(new Date(row.last_seen_at), { addSuffix: true })
                    : '—'}
                </TableCell>
                <TableCell>
                  <Chip
                    size="small"
                    label={row.status}
                    sx={{ color: statusColor(row.status), borderColor: statusColor(row.status) }}
                    variant="outlined"
                  />
                </TableCell>
                <TableCell>
                  <Tooltip title="Ban agent (blocks reconnect from this device + provider)">
                    <span>
                      <IconButton
                        size="small"
                        disabled={!!row.revoked_at || row.banned}
                        onClick={(event) => {
                          event.stopPropagation();
                          setPending(row);
                        }}
                      >
                        <Ban size={16} />
                      </IconButton>
                    </span>
                  </Tooltip>
                  {isAdmin && (
                    <Tooltip title="Delete agent and audit logs">
                      <IconButton
                        size="small"
                        onClick={(event) => {
                          event.stopPropagation();
                          setPersistBan(true);
                          setDeleting(row);
                        }}
                      >
                        <Trash2 size={16} />
                      </IconButton>
                    </Tooltip>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        {!data?.items?.length && (
          <Typography variant="body2" sx={{ color: theme.palette.text.secondary, p: 2 }}>
            No agent sessions yet.
          </Typography>
        )}
      </TacticalPanel>

      <Dialog
        open={!!pending}
        onClose={() => setPending(null)}
        slotProps={{ paper: { sx: getDialogPaperSx(isLight, theme, tokens) } }}
      >
        <DialogTitle>Ban this agent?</DialogTitle>
        <DialogContent>
          The API key stays valid. This device + provider fingerprint cannot open a new session
          until a sys-admin deletes the agent and chooses to unban it.
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setPending(null)}>Cancel</Button>
          <Button
            color="error"
            onClick={async () => {
              if (!pending) return;
              await revokeSession.mutateAsync(pending.session_id);
              setPending(null);
            }}
          >
            Ban
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog
        open={!!deleting}
        onClose={() => setDeleting(null)}
        slotProps={{ paper: { sx: getDialogPaperSx(isLight, theme, tokens) } }}
      >
        <DialogTitle>Delete agent?</DialogTitle>
        <DialogContent>
          <Alert severity="warning" sx={{ mb: 2 }}>
            This permanently removes all audit logs for this agent. That cannot be undone.
          </Alert>
          <FormControl>
            <RadioGroup
              value={persistBan ? 'persist' : 'unban'}
              onChange={(event) => setPersistBan(event.target.value === 'persist')}
            >
              <FormControlLabel
                value="persist"
                control={<Radio />}
                label="Delete and keep the ban (this device + provider cannot reconnect)"
              />
              <FormControlLabel
                value="unban"
                control={<Radio />}
                label="Delete and unban (does not disconnect a live session; they may reconnect)"
              />
            </RadioGroup>
          </FormControl>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleting(null)}>Cancel</Button>
          <Button
            color="error"
            disabled={deleteAgent.isPending}
            onClick={async () => {
              if (!deleting?.agent_id) return;
              await deleteAgent.mutateAsync({ agentId: deleting.agent_id, persistBan });
              setDeleting(null);
            }}
          >
            Delete
          </Button>
        </DialogActions>
      </Dialog>

      <McpAuditChainDrawer
        sessionId={auditId}
        onClose={() => setAuditId(null)}
        onFocusKey={onFocusKey}
      />
    </>
  );
};
