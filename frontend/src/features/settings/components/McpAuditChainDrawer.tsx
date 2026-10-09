import React, { useState } from 'react';
import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Box,
  Button,
  Chip,
  Drawer,
  Typography,
} from '@mui/material';
import { ChevronDown } from 'lucide-react';
import { useMcpSessionEvents, type McpAuditEvent } from '../api/mcp';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import { getHttpStatusColor, getSurfaceSx } from '../../../theme/semanticColors';
import { McpJsonBlock, McpReplayDialog } from './McpReplayDialog';

export const McpAuditChainDrawer: React.FC<{
  sessionId: string | null;
  onClose: () => void;
  onFocusKey?: (keyId: number) => void;
}> = ({ sessionId, onClose, onFocusKey }) => {
  const { tokens, isLight, theme } = useThemeTokens();
  const { data } = useMcpSessionEvents(sessionId);
  const [replay, setReplay] = useState<McpAuditEvent | null>(null);

  return (
    <>
      <Drawer
        anchor="right"
        open={!!sessionId}
        onClose={onClose}
        slotProps={{
          paper: {
            sx: {
              width: { xs: '100%', sm: 480 },
              px: 2,
              pb: 2,
              pt: 12,
              overflowY: 'auto',
              ...getSurfaceSx(isLight, tokens, theme),
            },
          },
        }}
      >
        <Typography variant="h6" sx={{ mb: 2 }}>
          Audit chain
        </Typography>
        {(data?.items || []).map((event: McpAuditEvent) => (
          <Accordion
            key={event.id}
            disableGutters
            sx={{
              mb: 1,
              bgcolor: 'transparent',
              border: `1px solid ${tokens.border.subtle}`,
              '&:before': { display: 'none' },
            }}
          >
            <AccordionSummary expandIcon={<ChevronDown size={16} />}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap', width: '100%', pr: 1 }}>
                <Typography variant="caption" sx={{ color: theme.palette.text.secondary }}>
                  {event.created_at ? new Date(event.created_at).toLocaleString() : ''}
                </Typography>
                <Typography variant="body2">{event.tool_name || event.path}</Typography>
                <Chip
                  size="small"
                  label={event.status_code}
                  sx={{
                    color: getHttpStatusColor(event.status_code, tokens),
                    borderColor: getHttpStatusColor(event.status_code, tokens),
                  }}
                  variant="outlined"
                />
                {event.truncated && <Chip size="small" label="truncated" />}
                <Button
                  size="small"
                  type="button"
                  onMouseDown={(clickEvent) => clickEvent.stopPropagation()}
                  onClick={(clickEvent) => {
                    clickEvent.stopPropagation();
                    setReplay(event);
                  }}
                  sx={{ ml: 'auto' }}
                >
                  Replay
                </Button>
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <Typography variant="caption">Request</Typography>
              <McpJsonBlock value={event.request_body} tokens={tokens} />
              <Typography variant="caption" sx={{ mt: 1, display: 'block' }}>
                Response
              </Typography>
              <McpJsonBlock value={event.response_body} tokens={tokens} />
            </AccordionDetails>
          </Accordion>
        ))}
      </Drawer>
      <McpReplayDialog event={replay} onClose={() => setReplay(null)} onFocusKey={onFocusKey} />
    </>
  );
};
