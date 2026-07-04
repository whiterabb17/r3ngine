import React from 'react';
import {
  Dialog, DialogTitle, DialogContent, DialogActions, Button,
  Box, Typography, Chip, Divider, Stack, IconButton, Tooltip,
  List, ListItem, ListItemText, TextField
} from '@mui/material';
import { ShieldCheck, ShieldAlert, Download, Archive, X, Plus } from 'lucide-react';
import { useVerifyEvidence, useAddAnnotation } from '../api';
import type { Evidence } from '../types';

export function EvidenceDetailDialog({
  item,
  open,
  onClose,
}: {
  item: Evidence;
  open: boolean;
  onClose: () => void;
}) {
  const [annotationText, setAnnotationText] = React.useState('');
  const verifyMutation = useVerifyEvidence();
  const addAnnotation = useAddAnnotation(item.uuid);
  const [verifyResult, setVerifyResult] = React.useState<boolean | null>(null);

  const handleVerify = async () => {
    const result = await verifyMutation.mutateAsync(item.uuid);
    setVerifyResult(result.passed);
  };

  const handleAddNote = async () => {
    if (!annotationText.trim()) return;
    await addAnnotation.mutateAsync({ annotation_type: 'Note', content: annotationText });
    setAnnotationText('');
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      maxWidth="md"
      fullWidth
      slotProps={{
        paper: {
          sx: {
            bgcolor: '#0a0e1a',
            border: '1px solid rgba(0,243,255,0.15)',
            backgroundImage: 'none',
          }
        }
      }}
    >
      <DialogTitle sx={{
        fontFamily: 'Orbitron',
        color: '#00f3ff',
        fontSize: '0.85rem',
        letterSpacing: 2,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        borderBottom: '1px solid rgba(255,255,255,0.06)',
        pb: 1.5,
      }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <ShieldCheck size={16} />
          EVIDENCE DETAIL
        </Box>
        <IconButton onClick={onClose} size="small" sx={{ color: 'rgba(255,255,255,0.4)' }}>
          <X size={16} />
        </IconButton>
      </DialogTitle>

      <DialogContent sx={{ pt: 2 }}>
        {/* Header info */}
        <Stack spacing={1.5}>
          <Box>
            <Typography variant="h6" sx={{ color: '#fff', fontWeight: 600, fontSize: '1rem' }}>
              {item.title}
            </Typography>
            <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.4)', fontFamily: 'monospace' }}>
              UUID: {item.uuid}
            </Typography>
          </Box>

          {/* Chips */}
          <Stack direction="row" spacing={1} sx={{ flexWrap: 'wrap' }}>
            <Chip label={item.evidence_type} size="small" sx={{ bgcolor: 'rgba(0,243,255,0.1)', color: '#00f3ff', border: '1px solid rgba(0,243,255,0.2)', fontSize: '0.65rem' }} />
            <Chip label={item.status} size="small" color={item.status === 'Active' ? 'success' : 'default'} sx={{ fontSize: '0.65rem' }} />
            {item.mime_type && (
              <Chip label={item.mime_type} size="small" sx={{ bgcolor: 'rgba(255,255,255,0.05)', color: 'rgba(255,255,255,0.5)', fontSize: '0.6rem', fontFamily: 'monospace' }} />
            )}
          </Stack>

          {/* Description */}
          {item.description && (
            <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.6)', fontSize: '0.8rem', lineHeight: 1.6 }}>
              {item.description}
            </Typography>
          )}

          <Divider sx={{ borderColor: 'rgba(255,255,255,0.06)' }} />

          {/* Integrity block */}
          <Box sx={{ p: 1.5, bgcolor: 'rgba(0,0,0,0.3)', borderRadius: 1, border: '1px solid rgba(255,255,255,0.06)' }}>
            <Typography variant="caption" sx={{ fontFamily: 'Orbitron', color: 'rgba(255,255,255,0.4)', fontSize: '0.6rem', letterSpacing: 1 }}>
              INTEGRITY / CHAIN OF CUSTODY
            </Typography>
            <Box sx={{ mt: 1 }}>
              <Typography variant="caption" sx={{ fontFamily: 'monospace', color: 'rgba(255,255,255,0.5)', display: 'block', fontSize: '0.65rem', wordBreak: 'break-all' }}>
                SHA-256: {item.sha256_hash ?? 'Not computed'}
              </Typography>
              <Typography variant="caption" sx={{ fontFamily: 'monospace', color: 'rgba(255,255,255,0.4)', display: 'block', fontSize: '0.65rem' }}>
                Size: {item.file_size_mb} MB · Collected: {new Date(item.collected_at).toLocaleString()}
                {item.collected_by_username && ` · By: ${item.collected_by_username}`}
              </Typography>
            </Box>
            {verifyResult !== null && (
              <Box sx={{ mt: 1, display: 'flex', alignItems: 'center', gap: 0.5 }}>
                {verifyResult
                  ? <><ShieldCheck size={14} color="#00e676" /><Typography variant="caption" sx={{ color: '#00e676', fontSize: '0.7rem' }}>Integrity PASSED</Typography></>
                  : <><ShieldAlert size={14} color="#ff1744" /><Typography variant="caption" sx={{ color: '#ff1744', fontSize: '0.7rem' }}>Integrity FAILED — possible tampering!</Typography></>
                }
              </Box>
            )}
          </Box>

          {/* Chain of custody events */}
          {item.events.length > 0 && (
            <Box>
              <Typography variant="caption" sx={{ fontFamily: 'Orbitron', color: 'rgba(255,255,255,0.4)', fontSize: '0.6rem', letterSpacing: 1 }}>
                CUSTODY EVENTS ({item.events.length})
              </Typography>
              <List dense disablePadding sx={{ mt: 0.5 }}>
                {item.events.slice(-6).map(evt => (
                  <ListItem key={evt.id} sx={{ py: 0.25, px: 0 }}>
                    <ListItemText
                      primary={
                        <Typography variant="caption" sx={{ fontFamily: 'monospace', color: 'rgba(255,255,255,0.6)', fontSize: '0.65rem' }}>
                          [{evt.event_type}] {new Date(evt.timestamp).toLocaleString()} · {evt.actor_username ?? 'system'}
                          {evt.note && <> — {evt.note}</>}
                        </Typography>
                      }
                    />
                  </ListItem>
                ))}
              </List>
            </Box>
          )}

          {/* Annotations */}
          <Box>
            <Typography variant="caption" sx={{ fontFamily: 'Orbitron', color: 'rgba(255,255,255,0.4)', fontSize: '0.6rem', letterSpacing: 1 }}>
              ANALYST NOTES
            </Typography>
            {item.annotations.map(ann => (
              <Box key={ann.id} sx={{ mt: 0.75, p: 1, bgcolor: 'rgba(255,255,255,0.03)', borderRadius: 1, border: '1px solid rgba(255,255,255,0.05)' }}>
                <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.6)', fontSize: '0.75rem', display: 'block' }}>
                  {ann.content}
                </Typography>
                <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.3)', fontSize: '0.6rem', fontFamily: 'monospace' }}>
                  {ann.author_username ?? 'unknown'} · {new Date(ann.created_at).toLocaleDateString()}
                </Typography>
              </Box>
            ))}
            <Box sx={{ display: 'flex', gap: 1, mt: 1 }}>
              <TextField
                size="small"
                placeholder="Add note…"
                value={annotationText}
                onChange={e => setAnnotationText(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter') handleAddNote(); }}
                sx={{
                  flex: 1,
                  '& .MuiInputBase-root': { bgcolor: 'rgba(255,255,255,0.03)', color: '#fff', fontSize: '0.75rem' },
                  '& .MuiOutlinedInput-notchedOutline': { borderColor: 'rgba(255,255,255,0.1)' },
                }}
              />
              <IconButton
                size="small"
                onClick={handleAddNote}
                disabled={!annotationText.trim() || addAnnotation.isPending}
                sx={{ color: '#00f3ff', border: '1px solid rgba(0,243,255,0.3)' }}
              >
                <Plus size={14} />
              </IconButton>
            </Box>
          </Box>
        </Stack>
      </DialogContent>

      <DialogActions sx={{ borderTop: '1px solid rgba(255,255,255,0.06)', px: 2, py: 1.5, gap: 1 }}>
        <Button
          size="small"
          startIcon={<ShieldCheck size={12} />}
          onClick={handleVerify}
          disabled={verifyMutation.isPending}
          sx={{ color: '#00f3ff', fontSize: '0.7rem', borderColor: 'rgba(0,243,255,0.3)', border: '1px solid' }}
        >
          {verifyMutation.isPending ? 'Verifying…' : 'Verify Integrity'}
        </Button>
        {item.download_url && (
          <Button
            size="small"
            startIcon={<Download size={12} />}
            onClick={() => window.open(item.download_url, '_blank')}
            sx={{ color: 'rgba(255,255,255,0.7)', fontSize: '0.7rem' }}
          >
            Download
          </Button>
        )}
        <Box sx={{ flex: 1 }} />
        <Button onClick={onClose} size="small" sx={{ color: 'rgba(255,255,255,0.4)', fontSize: '0.7rem' }}>
          Close
        </Button>
      </DialogActions>
    </Dialog>
  );
}
