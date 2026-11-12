import React, { useState } from 'react';
import {
  Box,
  Typography,
  Tabs,
  Tab,
  TextField,
  IconButton,
  List,
  Button,
  Chip,
  CircularProgress,
  Divider,
  Select,
  MenuItem,
  FormControl,
  Alert,
  alpha,
} from '@mui/material';
import { Plus, Send, Check, X } from 'lucide-react';
import { useTheme } from '@mui/material/styles';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import { getSurfaceSx } from '../../../theme/semanticColors';
import {
  useApproveCopilotProposal,
  useCopilotChat,
  useCopilotProposals,
  useCopilotSession,
  useCopilotSessions,
  useCopilotStatus,
  useCreateCopilotSession,
  useRejectCopilotProposal,
  type CopilotProposal,
} from '../api';

type Props = {
  projectSlug: string;
  scanId?: number | null;
  assessmentId?: number | null;
  compact?: boolean;
  defaultTab?: 'chat' | 'proposals';
  onClose?: () => void;
};

export const CopilotSupportBox: React.FC<Props> = ({
  projectSlug,
  scanId = null,
  assessmentId = null,
  compact = false,
  defaultTab = 'chat',
  onClose,
}) => {
  const theme = useTheme();
  const { tokens, isLight } = useThemeTokens();
  const [tab, setTab] = useState<'chat' | 'proposals'>(defaultTab);
  const [sessionId, setSessionId] = useState<number | null>(null);
  const [draft, setDraft] = useState('');

  const { data: status } = useCopilotStatus(projectSlug);
  const { data: sessions } = useCopilotSessions(projectSlug);
  // Prefer an explicit selection; otherwise fall back to the newest session
  // without syncing into state from an effect (react-hooks/set-state-in-effect).
  const activeSessionId = sessionId ?? sessions?.[0]?.id ?? null;
  const { data: session } = useCopilotSession(projectSlug, activeSessionId);
  const createSession = useCreateCopilotSession(projectSlug);
  const chat = useCopilotChat(projectSlug);
  const { data: proposals } = useCopilotProposals(projectSlug, 'pending');
  const approve = useApproveCopilotProposal(projectSlug);
  const reject = useRejectCopilotProposal(projectSlug);

  const sessionDefaults = {
    title: 'New conversation' as const,
    ...(scanId != null ? { scan_id: scanId } : {}),
    ...(assessmentId != null ? { assessment_id: assessmentId } : {}),
  };

  const ensureSession = async () => {
    if (activeSessionId) return activeSessionId;
    const created = await createSession.mutateAsync(sessionDefaults);
    setSessionId(created.id);
    return created.id;
  };

  const send = async () => {
    const text = draft.trim();
    if (!text) return;
    const sid = await ensureSession();
    setDraft('');
    await chat.mutateAsync({ session_id: sid, content: text });
  };

  const surface = getSurfaceSx(isLight, tokens, theme);

  return (
    <Box
      sx={{
        ...surface,
        display: 'flex',
        flexDirection: 'column',
        height: compact ? 460 : '100%',
        minHeight: compact ? 460 : 360,
        overflow: 'hidden',
      }}
    >
      <Box sx={{ px: 2, pt: 1.5, pb: 1, display: 'flex', alignItems: 'center', gap: 1 }}>
        <Typography sx={{ fontFamily: 'var(--r3-heading-font)', fontWeight: 700, fontSize: '0.85rem', flex: 1 }}>
          Assessment Copilot
        </Typography>
        {status?.health?.reachable === false && (
          <Chip size="small" label="offline" color="warning" />
        )}
        {onClose && (
          <IconButton size="small" onClick={onClose} aria-label="Close copilot">
            <X size={16} />
          </IconButton>
        )}
      </Box>

      {status?.health?.hint && status.health.reachable === false && (
        <Alert severity="info" sx={{ mx: 2, mb: 1, py: 0 }}>
          {status.health.hint}
        </Alert>
      )}

      <Tabs
        value={tab}
        onChange={(_, v) => setTab(v)}
        sx={{ px: 1, minHeight: 36, borderBottom: `1px solid ${alpha(theme.palette.divider, 0.2)}` }}
      >
        <Tab value="chat" label="Chat" sx={{ minHeight: 36, fontSize: '0.7rem' }} />
        <Tab
          value="proposals"
          label={`Proposals${proposals?.length ? ` (${proposals.length})` : ''}`}
          sx={{ minHeight: 36, fontSize: '0.7rem' }}
        />
      </Tabs>

      {tab === 'chat' ? (
        <Box sx={{ display: 'flex', flexDirection: 'column', flex: 1, minHeight: 0 }}>
          <Box sx={{ px: 1.5, py: 1, display: 'flex', gap: 1, alignItems: 'center' }}>
            <FormControl size="small" sx={{ flex: 1, minWidth: 0 }}>
              <Select
                value={activeSessionId ?? ''}
                displayEmpty
                onChange={(e) => setSessionId(Number(e.target.value) || null)}
                sx={{ fontSize: '0.75rem' }}
              >
                <MenuItem value="">
                  <em>Select conversation</em>
                </MenuItem>
                {(sessions || []).map((s) => (
                  <MenuItem key={s.id} value={s.id}>
                    {s.title || `Conversation ${s.id}`}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
            <IconButton
              size="small"
              onClick={async () => {
                const created = await createSession.mutateAsync(sessionDefaults);
                setSessionId(created.id);
              }}
              aria-label="New conversation"
            >
              <Plus size={16} />
            </IconButton>
          </Box>
          <Box sx={{ flex: 1, overflowY: 'auto', px: 2, py: 1 }}>
            {(session?.messages || []).map((m, idx) => (
              <Box
                key={m.id ?? idx}
                sx={{
                  mb: 1.25,
                  alignSelf: m.role === 'user' ? 'flex-end' : 'flex-start',
                  ml: m.role === 'user' ? 4 : 0,
                  mr: m.role === 'user' ? 0 : 4,
                  p: 1.25,
                  borderRadius: 1.5,
                  bgcolor:
                    m.role === 'user'
                      ? alpha(tokens.accent.primary, 0.15)
                      : alpha(theme.palette.text.primary, 0.04),
                  whiteSpace: 'pre-wrap',
                  fontSize: '0.8rem',
                }}
              >
                {m.content}
              </Box>
            ))}
            {chat.isPending && (
              <Box sx={{ display: 'flex', justifyContent: 'center', py: 1 }}>
                <CircularProgress size={18} />
              </Box>
            )}
          </Box>
          <Divider />
          <Box sx={{ p: 1.5, display: 'flex', gap: 1 }}>
            <TextField
              size="small"
              fullWidth
              placeholder="Ask about findings, SAFE PoCs, remediations…"
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                  e.preventDefault();
                  void send();
                }
              }}
              multiline
              maxRows={3}
            />
            <IconButton
              color="primary"
              onClick={() => void send()}
              disabled={chat.isPending || !draft.trim()}
              aria-label="Send"
            >
              <Send size={16} />
            </IconButton>
          </Box>
        </Box>
      ) : (
        <Box sx={{ flex: 1, overflowY: 'auto', p: 1.5 }}>
          {!proposals?.length && (
            <Typography variant="body2" color="text.secondary" sx={{ p: 1 }}>
              No pending proposals.
            </Typography>
          )}
          <List dense disablePadding>
            {(proposals || []).map((p) => (
              <ProposalRow
                key={p.id}
                proposal={p}
                onApprove={() => approve.mutate(p.id)}
                onReject={() => reject.mutate(p.id)}
                busy={approve.isPending || reject.isPending}
              />
            ))}
          </List>
        </Box>
      )}
    </Box>
  );
};

const ProposalRow: React.FC<{
  proposal: CopilotProposal;
  onApprove: () => void;
  onReject: () => void;
  busy: boolean;
}> = ({ proposal, onApprove, onReject, busy }) => {
  const theme = useTheme();
  return (
    <Box
      sx={{
        mb: 1,
        p: 1.25,
        borderRadius: 1.5,
        border: `1px solid ${alpha(theme.palette.divider, 0.25)}`,
      }}
    >
      <Box sx={{ display: 'flex', gap: 1, alignItems: 'center', mb: 0.5 }}>
        <Chip size="small" label={proposal.action_type} />
        {proposal.vulnerability_id != null && (
          <Typography variant="caption" color="text.secondary">
            vuln #{proposal.vulnerability_id}
          </Typography>
        )}
      </Box>
      <Typography sx={{ fontSize: '0.8rem', fontWeight: 600 }}>{proposal.summary}</Typography>
      {proposal.rationale && (
        <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 0.5 }}>
          {proposal.rationale.slice(0, 240)}
        </Typography>
      )}
      <Box sx={{ display: 'flex', gap: 1, mt: 1 }}>
        <Button
          size="small"
          variant="contained"
          startIcon={<Check size={14} />}
          onClick={onApprove}
          disabled={busy}
        >
          Approve
        </Button>
        <Button
          size="small"
          variant="outlined"
          color="inherit"
          startIcon={<X size={14} />}
          onClick={onReject}
          disabled={busy}
        >
          Reject
        </Button>
      </Box>
    </Box>
  );
};
