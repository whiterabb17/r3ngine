import React, { useState } from 'react';
import {
  Box, Typography, Tabs, Tab, CircularProgress, Alert, Chip, Button, Stack
} from '@mui/material';
import { Shield, Archive, RefreshCw } from 'lucide-react';
import { useEvidenceCollections, useCollectionItems } from '../api';
import { EvidenceTable } from '../components/EvidenceTable';
import type { EvidenceCollection } from '../types';

// -------------------------------------------------------------------------
// EvidencePage — top-level evidence management page
// Typically embedded inside the Assessment Execution Dashboard
// -------------------------------------------------------------------------
export function EvidencePage({ assessmentUuid }: { assessmentUuid?: string }) {
  const [selectedCollection, setSelectedCollection] = useState<EvidenceCollection | null>(null);

  const {
    data: collections = [],
    isLoading,
    isError,
    refetch,
  } = useEvidenceCollections(assessmentUuid);

  // Auto-select first Active collection
  React.useEffect(() => {
    if (!selectedCollection && collections.length > 0) {
      setSelectedCollection(collections.find(c => c.status === 'Active') ?? collections[0]);
    }
  }, [collections, selectedCollection]);

  if (isLoading) {
    return (
      <Box sx={{ py: 4, textAlign: 'center' }}>
        <CircularProgress size={24} sx={{ color: '#00f3ff' }} />
        <Typography variant="caption" sx={{ display: 'block', mt: 1, color: 'rgba(255,255,255,0.4)', fontFamily: 'Orbitron', fontSize: '0.65rem', letterSpacing: 1 }}>
          LOADING EVIDENCE VAULT…
        </Typography>
      </Box>
    );
  }

  if (isError) {
    return (
      <Alert severity="error" action={<Button size="small" onClick={() => refetch()}>Retry</Button>}>
        Failed to load evidence collections.
      </Alert>
    );
  }

  if (collections.length === 0) {
    return (
      <Box sx={{
        py: 8,
        textAlign: 'center',
        border: '1px dashed rgba(255,255,255,0.06)',
        borderRadius: 2,
      }}>
        <Shield size={48} color="rgba(255,255,255,0.08)" style={{ marginBottom: 16 }} />
        <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.3)', fontFamily: 'Orbitron', fontSize: '0.75rem', letterSpacing: 1 }}>
          NO EVIDENCE COLLECTIONS
        </Typography>
        <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.2)', display: 'block', mt: 0.5 }}>
          Evidence collections are created automatically when an assessment runs.
        </Typography>
      </Box>
    );
  }

  return (
    <Box>
      {/* Collection tabs */}
      {collections.length > 1 && (
        <Box sx={{ mb: 2, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
          <Tabs
            value={selectedCollection?.uuid ?? collections[0].uuid}
            onChange={(_, uuid) => setSelectedCollection(collections.find(c => c.uuid === uuid) ?? null)}
            slotProps={{ indicator: { sx: { bgcolor: '#00f3ff' } } }}
            sx={{ minHeight: 36 }}
          >
            {collections.map(c => (
              <Tab
                key={c.uuid}
                value={c.uuid}
                label={
                  <Stack direction="row" spacing={0.75} sx={{ alignItems: 'center' }}>
                    <span style={{ fontSize: '0.7rem', fontFamily: 'Orbitron' }}>
                      {c.name.length > 30 ? c.name.slice(0, 30) + '…' : c.name}
                    </span>
                    <Chip
                      label={c.item_count}
                      size="small"
                      sx={{ height: 16, fontSize: '0.55rem', bgcolor: 'rgba(0,243,255,0.15)', color: '#00f3ff' }}
                    />
                  </Stack>
                }
                sx={{ minHeight: 36, py: 0, color: 'rgba(255,255,255,0.4)', '&.Mui-selected': { color: '#00f3ff' } }}
              />
            ))}
          </Tabs>
        </Box>
      )}

      {/* Evidence table for selected collection */}
      {selectedCollection && (
        <EvidenceTable
          key={selectedCollection.uuid}
          collectionUuid={selectedCollection.uuid}
          collection={selectedCollection}
        />
      )}
    </Box>
  );
}
