import React, { useState } from 'react';
import {
  Box,
  Button,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  IconButton,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  Tooltip,
  Typography,
} from '@mui/material';
import { Copy, KeyRound, RefreshCw, Ban } from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import {
  httpSnippet,
  stdioSnippet,
  useCreateMcpKey,
  useMcpKeys,
  useMcpSettings,
  useRegenerateMcpKey,
  useRevokeMcpKey,
  type McpKey,
} from '../api/mcp';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import { getDialogPaperSx, getFieldSx } from '../../../theme/semanticColors';
import { TacticalPanel } from '../../../components/TacticalPanel';

export const McpKeysPanel: React.FC<{
  focusKeyId?: number | null;
  onFocusAgent?: () => void;
}> = ({ focusKeyId = null }) => {
  const { tokens, isLight, theme } = useThemeTokens();
  const { data } = useMcpKeys();
  const { data: settings } = useMcpSettings();
  const createKey = useCreateMcpKey();
  const regenerateKey = useRegenerateMcpKey();
  const revokeKey = useRevokeMcpKey();
  const [name, setName] = useState('');
  const [nameOpen, setNameOpen] = useState(false);
  const [secretKey, setSecretKey] = useState<McpKey | null>(null);
  const [confirm, setConfirm] = useState<{ type: 'regen' | 'revoke'; key: McpKey } | null>(null);

  const mode = settings?.transport_mode || 'stdio';
  const origin = window.location.origin;
  const fieldSx = getFieldSx(isLight, tokens);

  const copy = async (text: string) => {
    await navigator.clipboard.writeText(text);
  };

  return (
    <>
      <TacticalPanel
        title="API keys"
        icon={<KeyRound size={20} />}
        headerAction={
          <Button size="small" variant="contained" onClick={() => setNameOpen(true)}>
            Generate key
          </Button>
        }
      >
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Name</TableCell>
              <TableCell>Prefix</TableCell>
              <TableCell>Agents</TableCell>
              <TableCell>Created</TableCell>
              <TableCell>Last used</TableCell>
              <TableCell>Status</TableCell>
              <TableCell />
            </TableRow>
          </TableHead>
          <TableBody>
            {(data?.items || []).map((row) => (
              <TableRow
                key={row.id}
                id={`mcp-key-${row.id}`}
                selected={focusKeyId === row.id}
                sx={focusKeyId === row.id ? { outline: `1px solid ${tokens.accent.primary}` } : undefined}
              >
                <TableCell>{row.name}</TableCell>
                <TableCell sx={{ fontFamily: 'monospace' }}>{row.prefix}</TableCell>
                <TableCell>
                  {(row.agents || []).length
                    ? (row.agents || []).map((agent) => (
                        <Chip
                          key={agent.agent_id}
                          size="small"
                          label={`${agent.provider || 'agent'} @ ${agent.hostname || 'device'}`}
                          sx={{ mr: 0.5, mb: 0.5 }}
                          variant="outlined"
                        />
                      ))
                    : '—'}
                </TableCell>
                <TableCell>
                  {row.created_at
                    ? formatDistanceToNow(new Date(row.created_at), { addSuffix: true })
                    : '—'}
                </TableCell>
                <TableCell>
                  {row.last_used_at
                    ? formatDistanceToNow(new Date(row.last_used_at), { addSuffix: true })
                    : '—'}
                </TableCell>
                <TableCell>
                  <Chip
                    size="small"
                    label={row.status}
                    variant="outlined"
                    sx={{
                      color: row.status === 'active' ? tokens.accent.success : tokens.accent.error,
                      borderColor: row.status === 'active' ? tokens.accent.success : tokens.accent.error,
                    }}
                  />
                </TableCell>
                <TableCell>
                  <Tooltip title="Regenerate">
                    <IconButton size="small" onClick={() => setConfirm({ type: 'regen', key: row })}>
                      <RefreshCw size={16} />
                    </IconButton>
                  </Tooltip>
                  <Tooltip title="Revoke">
                    <span>
                      <IconButton
                        size="small"
                        disabled={row.status === 'revoked'}
                        onClick={() => setConfirm({ type: 'revoke', key: row })}
                      >
                        <Ban size={16} />
                      </IconButton>
                    </span>
                  </Tooltip>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TacticalPanel>

      <Dialog
        open={nameOpen}
        onClose={() => setNameOpen(false)}
        slotProps={{ paper: { sx: getDialogPaperSx(isLight, theme, tokens) } }}
      >
        <DialogTitle>Generate MCP key</DialogTitle>
        <DialogContent>
          <TextField
            autoFocus
            fullWidth
            label="Key name"
            value={name}
            onChange={(event) => setName(event.target.value)}
            sx={{ mt: 1, ...fieldSx }}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setNameOpen(false)}>Cancel</Button>
          <Button
            variant="contained"
            disabled={!name.trim() || createKey.isPending}
            onClick={async () => {
              const created = await createKey.mutateAsync(name.trim());
              setName('');
              setNameOpen(false);
              setSecretKey(created);
            }}
          >
            Generate
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog
        open={!!confirm}
        onClose={() => setConfirm(null)}
        slotProps={{ paper: { sx: getDialogPaperSx(isLight, theme, tokens) } }}
      >
        <DialogTitle>
          {confirm?.type === 'regen' ? 'Regenerate this key?' : 'Revoke this key?'}
        </DialogTitle>
        <DialogContent>
          {confirm?.type === 'regen'
            ? 'The current secret stops working immediately. Copy the new secret once.'
            : 'Existing sessions using this key will be revoked.'}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setConfirm(null)}>Cancel</Button>
          <Button
            color="error"
            onClick={async () => {
              if (!confirm) return;
              if (confirm.type === 'regen') {
                const next = await regenerateKey.mutateAsync(confirm.key.id);
                setSecretKey(next);
              } else {
                await revokeKey.mutateAsync(confirm.key.id);
              }
              setConfirm(null);
            }}
          >
            Confirm
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog
        open={!!secretKey?.secret}
        onClose={() => setSecretKey(null)}
        slotProps={{ paper: { sx: getDialogPaperSx(isLight, theme, tokens) } }}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>Copy this secret now</DialogTitle>
        <DialogContent>
          <Typography variant="body2" sx={{ mb: 1 }}>
            It will not be shown again. Prefix later: {secretKey?.prefix}
          </Typography>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
            <TextField
              fullWidth
              value={secretKey?.secret || ''}
              slotProps={{ input: { readOnly: true } }}
              sx={fieldSx}
            />
            <IconButton onClick={() => copy(secretKey?.secret || '')}>
              <Copy size={16} />
            </IconButton>
          </Box>
          {(mode === 'stdio' || mode === 'both') && (
            <Box sx={{ mb: 2 }}>
              <Typography variant="subtitle2">stdio snippet</Typography>
              <Box component="pre" sx={{ fontSize: 12, overflow: 'auto' }}>
                {stdioSnippet(origin, secretKey?.secret || '')}
              </Box>
              <Button
                size="small"
                onClick={() => copy(stdioSnippet(origin, secretKey?.secret || ''))}
              >
                Copy snippet
              </Button>
            </Box>
          )}
          {(mode === 'http' || mode === 'both') && (
            <Box>
              <Typography variant="subtitle2">HTTP</Typography>
              <Box component="pre" sx={{ fontSize: 12 }}>
                {httpSnippet(origin, secretKey?.secret || '')}
              </Box>
              <Button
                size="small"
                onClick={() => copy(httpSnippet(origin, secretKey?.secret || ''))}
              >
                Copy HTTP
              </Button>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setSecretKey(null)}>Done</Button>
        </DialogActions>
      </Dialog>
    </>
  );
};
