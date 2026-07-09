import React, { useState, useCallback } from 'react';
import {
  Box, Typography, Paper, Chip, IconButton, Tooltip,
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
  Button, CircularProgress, Alert, Divider, Dialog, DialogTitle,
  DialogContent, DialogActions, TextField, Select, MenuItem,
  FormControl, InputLabel, LinearProgress, Badge, Stack
} from '@mui/material';
import {
  Shield, ShieldCheck, ShieldAlert, Archive, Trash2,
  Download, Eye, Upload, RefreshCw, FileImage, FileText,
  Globe, Terminal, CheckCircle, XCircle, Clock, Lock
} from 'lucide-react';
import { useEvidenceCollections, useCollectionItems, useVerifyEvidence,
         useArchiveEvidence, useUploadEvidence } from '../api';
import type { Evidence, EvidenceCollection } from '../types';
import { EvidenceDetailDialog } from './EvidenceDetailDialog';
import { EvidenceUploadDialog } from './EvidenceUploadDialog';

// -------------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------------
const EVIDENCE_TYPE_ICONS: Record<string, React.ReactNode> = {
  Screenshot:      <FileImage size={14} />,
  NetworkCapture:  <Globe size={14} />,
  RequestResponse: <Globe size={14} />,
  CommandOutput:   <Terminal size={14} />,
  Log:             <FileText size={14} />,
  Report:          <FileText size={14} />,
  Other:           <FileText size={14} />,
};

const STATUS_CHIP_COLOR: Record<string, 'success' | 'warning' | 'error' | 'default'> = {
  Active:   'success',
  Draft:    'warning',
  Archived: 'default',
  Purged:   'error',
};

// -------------------------------------------------------------------------
// EvidenceStatusBadge
// -------------------------------------------------------------------------
function IntegrityBadge({ verified }: { verified: boolean | null }) {
  if (verified === null) return null;
  return verified
    ? <ShieldCheck size={14} color="#00e676" />
    : <ShieldAlert size={14} color="#ff1744" />;
}

// -------------------------------------------------------------------------
// EvidenceCollectionHeader
// -------------------------------------------------------------------------
function CollectionHeader({
  collection,
  onUpload,
}: {
  collection: EvidenceCollection;
  onUpload: () => void;
}) {
  return (
    <Box sx={{
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      mb: 2,
      p: 2,
      background: 'linear-gradient(135deg, rgba(0,243,255,0.05) 0%, rgba(0,243,255,0) 100%)',
      border: '1px solid rgba(0,243,255,0.1)',
      borderRadius: 2,
    }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
        <Shield size={20} color="#00f3ff" />
        <Box>
          <Typography variant="subtitle1" sx={{ fontFamily: 'Orbitron', fontWeight: 700, color: '#fff', fontSize: '0.85rem' }}>
            {collection.name}
          </Typography>
          <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.5)' }}>
            {collection.item_count} items · {collection.status}
            {collection.retention_policy && (
              <> · Retention: {collection.retention_policy.archive_after_days}d</>
            )}
          </Typography>
        </Box>
      </Box>
      <Box sx={{ display: 'flex', gap: 1 }}>
        <Chip
          label={collection.status}
          color={STATUS_CHIP_COLOR[collection.status] ?? 'default'}
          size="small"
          sx={{ fontSize: '0.65rem', fontFamily: 'monospace' }}
        />
        {collection.status === 'Active' && (
          <Button
            size="small"
            variant="outlined"
            startIcon={<Upload size={12} />}
            onClick={onUpload}
            sx={{
              borderColor: 'rgba(0,243,255,0.4)',
              color: '#00f3ff',
              fontSize: '0.7rem',
              px: 1.5,
              '&:hover': { borderColor: '#00f3ff', bgcolor: 'rgba(0,243,255,0.05)' },
            }}
          >
            Upload Evidence
          </Button>
        )}
      </Box>
    </Box>
  );
}

// -------------------------------------------------------------------------
// EvidenceRow
// -------------------------------------------------------------------------
function EvidenceRow({
  item,
  onView,
  onVerify,
  onArchive,
}: {
  item: Evidence;
  onView: (item: Evidence) => void;
  onVerify: (uuid: string) => void;
  onArchive: (uuid: string) => void;
}) {
  const isActive = item.status === 'Active';

  return (
    <TableRow
      hover
      sx={{
        cursor: 'pointer',
        '&:hover': { background: 'rgba(0,243,255,0.03)' },
        borderBottom: '1px solid rgba(255,255,255,0.04)',
      }}
      onClick={() => onView(item)}
    >
      <TableCell sx={{ py: 1 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Box sx={{ color: 'rgba(0,243,255,0.6)' }}>
            {EVIDENCE_TYPE_ICONS[item.evidence_type] ?? <FileText size={14} />}
          </Box>
          <Box>
            <Typography variant="body2" sx={{ color: '#fff', fontWeight: 500, fontSize: '0.8rem' }}>
              {item.title}
            </Typography>
            {item.file_name && (
              <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.4)', fontFamily: 'monospace', fontSize: '0.65rem' }}>
                {item.file_name}
              </Typography>
            )}
          </Box>
        </Box>
      </TableCell>
      <TableCell sx={{ py: 1 }}>
        <Chip
          label={item.evidence_type}
          size="small"
          sx={{
            fontSize: '0.6rem',
            bgcolor: 'rgba(0,243,255,0.08)',
            color: '#00f3ff',
            border: '1px solid rgba(0,243,255,0.2)',
          }}
        />
      </TableCell>
      <TableCell sx={{ py: 1 }}>
        <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.5)', fontFamily: 'monospace' }}>
          {item.file_size_mb > 0 ? `${item.file_size_mb} MB` : '—'}
        </Typography>
      </TableCell>
      <TableCell sx={{ py: 1 }}>
        <Chip
          label={item.status}
          color={STATUS_CHIP_COLOR[item.status] ?? 'default'}
          size="small"
          sx={{ fontSize: '0.6rem' }}
        />
      </TableCell>
      <TableCell sx={{ py: 1 }}>
        <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.4)', fontFamily: 'monospace', fontSize: '0.65rem' }}>
          {new Date(item.collected_at).toLocaleDateString()}
        </Typography>
      </TableCell>
      <TableCell sx={{ py: 1 }} onClick={(e) => e.stopPropagation()}>
        <Stack direction="row" spacing={0.5}>
          <Tooltip title="View details">
            <IconButton size="small" onClick={() => onView(item)} sx={{ color: 'rgba(255,255,255,0.5)' }}>
              <Eye size={14} />
            </IconButton>
          </Tooltip>
          {isActive && (
            <>
              <Tooltip title="Download evidence">
                <IconButton
                  size="small"
                  onClick={() => window.open(item.download_url, '_blank')}
                  sx={{ color: 'rgba(255,255,255,0.5)' }}
                >
                  <Download size={14} />
                </IconButton>
              </Tooltip>
              <Tooltip title="Verify integrity">
                <IconButton
                  size="small"
                  onClick={() => onVerify(item.uuid)}
                  sx={{ color: 'rgba(0,243,255,0.6)' }}
                >
                  <ShieldCheck size={14} />
                </IconButton>
              </Tooltip>
              <Tooltip title="Archive">
                <IconButton
                  size="small"
                  onClick={() => onArchive(item.uuid)}
                  sx={{ color: 'rgba(255,255,255,0.3)' }}
                >
                  <Archive size={14} />
                </IconButton>
              </Tooltip>
            </>
          )}
        </Stack>
      </TableCell>
    </TableRow>
  );
}

// -------------------------------------------------------------------------
// EvidenceTable — main component for a single collection's items
// -------------------------------------------------------------------------
export function EvidenceTable({
  collectionUuid,
  collection,
}: {
  collectionUuid: string;
  collection: EvidenceCollection;
}) {
  const [selectedItem, setSelectedItem] = useState<Evidence | null>(null);
  const [uploadOpen, setUploadOpen] = useState(false);
  const [verifyResult, setVerifyResult] = useState<{ uuid: string; passed: boolean } | null>(null);

  const { data: items = [], isLoading, refetch } = useCollectionItems(collectionUuid);
  const verifyMutation = useVerifyEvidence();
  const archiveMutation = useArchiveEvidence();

  const handleVerify = useCallback(async (uuid: string) => {
    try {
      const result = await verifyMutation.mutateAsync(uuid);
      setVerifyResult({ uuid, passed: result.passed });
      setTimeout(() => setVerifyResult(null), 4000);
    } catch (_) { /* ignore */ }
  }, [verifyMutation]);

  const handleArchive = useCallback(async (uuid: string) => {
    if (window.confirm('Archive this evidence item? It will no longer be editable.')) {
      await archiveMutation.mutateAsync({ uuid });
      refetch();
    }
  }, [archiveMutation, refetch]);

  return (
    <Box>
      <CollectionHeader collection={collection} onUpload={() => setUploadOpen(true)} />

      {verifyResult && (
        <Alert
          severity={verifyResult.passed ? 'success' : 'error'}
          icon={verifyResult.passed ? <ShieldCheck size={16} /> : <ShieldAlert size={16} />}
          sx={{ mb: 2, fontSize: '0.75rem' }}
          onClose={() => setVerifyResult(null)}
        >
          Integrity check {verifyResult.passed ? 'PASSED — SHA-256 matches.' : 'FAILED — evidence may have been tampered with!'}
        </Alert>
      )}

      {isLoading ? (
        <Box sx={{ py: 4, textAlign: 'center' }}>
          <CircularProgress size={24} sx={{ color: '#00f3ff' }} />
        </Box>
      ) : items.length === 0 ? (
        <Box sx={{
          py: 6,
          textAlign: 'center',
          border: '1px dashed rgba(255,255,255,0.1)',
          borderRadius: 2,
        }}>
          <Shield size={40} color="rgba(255,255,255,0.1)" style={{ marginBottom: 12 }} />
          <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.3)' }}>
            No evidence items collected yet.
          </Typography>
          {collection.status === 'Active' && (
            <Button
              size="small"
              startIcon={<Upload size={14} />}
              onClick={() => setUploadOpen(true)}
              sx={{ mt: 2, color: '#00f3ff', fontSize: '0.75rem' }}
            >
              Upload First Evidence
            </Button>
          )}
        </Box>
      ) : (
        <TableContainer component={Paper} sx={{ bgcolor: 'transparent', boxShadow: 'none' }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                {['Title / File', 'Type', 'Size', 'Status', 'Collected', 'Actions'].map(h => (
                  <TableCell key={h} sx={{
                    color: 'rgba(255,255,255,0.4)',
                    fontFamily: 'Orbitron',
                    fontSize: '0.6rem',
                    letterSpacing: 1,
                    py: 0.75,
                    borderBottom: '1px solid rgba(255,255,255,0.06)',
                  }}>
                    {h}
                  </TableCell>
                ))}
              </TableRow>
            </TableHead>
            <TableBody>
              {items.map(item => (
                <EvidenceRow
                  key={item.uuid}
                  item={item}
                  onView={setSelectedItem}
                  onVerify={handleVerify}
                  onArchive={handleArchive}
                />
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      {/* Detail dialog */}
      {selectedItem && (
        <EvidenceDetailDialog
          item={selectedItem}
          open={Boolean(selectedItem)}
          onClose={() => setSelectedItem(null)}
        />
      )}

      {/* Upload dialog */}
      <EvidenceUploadDialog
        open={uploadOpen}
        onClose={() => setUploadOpen(false)}
        collectionUuid={collectionUuid}
      />
    </Box>
  );
}
