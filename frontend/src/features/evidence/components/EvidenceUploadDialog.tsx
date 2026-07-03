import React, { useState, useRef } from 'react';
import {
  Dialog, DialogTitle, DialogContent, DialogActions,
  Button, Box, Typography, TextField, Select, MenuItem,
  FormControl, InputLabel, LinearProgress, IconButton, Stack, Alert
} from '@mui/material';
import { Upload, X, File } from 'lucide-react';
import { useUploadEvidence } from '../api';

const EVIDENCE_TYPES = [
  { value: 'Screenshot',      label: 'Screenshot' },
  { value: 'NetworkCapture',  label: 'Network Capture (PCAP/HAR)' },
  { value: 'RequestResponse', label: 'HTTP Request/Response' },
  { value: 'CommandOutput',   label: 'Command Output' },
  { value: 'Log',             label: 'Log File' },
  { value: 'Report',          label: 'Report Document' },
  { value: 'Other',           label: 'Other' },
];

export function EvidenceUploadDialog({
  open,
  onClose,
  collectionUuid,
}: {
  open: boolean;
  onClose: () => void;
  collectionUuid: string;
}) {
  const fileRef = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [evidenceType, setEvidenceType] = useState('Screenshot');
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const uploadMutation = useUploadEvidence(collectionUuid);

  const handleFileDrop = (f: File) => {
    setFile(f);
    if (!title) setTitle(f.name.replace(/\.[^/.]+$/, ''));

    // Auto-detect type from extension
    const ext = f.name.split('.').pop()?.toLowerCase() ?? '';
    if (['png', 'jpg', 'jpeg', 'gif', 'webp'].includes(ext)) setEvidenceType('Screenshot');
    else if (['pcap', 'pcapng', 'har', 'cap'].includes(ext)) setEvidenceType('NetworkCapture');
    else if (['log'].includes(ext)) setEvidenceType('Log');
    else if (['pdf', 'docx'].includes(ext)) setEvidenceType('Report');
    else if (['txt', 'json'].includes(ext)) setEvidenceType('CommandOutput');
  };

  const handleUpload = async () => {
    if (!file || !title || !evidenceType) return;
    setError(null);
    const formData = new FormData();
    formData.append('file', file);
    formData.append('title', title);
    formData.append('description', description);
    formData.append('evidence_type', evidenceType);
    formData.append('collection_uuid', collectionUuid);

    try {
      await uploadMutation.mutateAsync(formData);
      setSuccess(true);
      setTimeout(() => {
        setSuccess(false);
        setFile(null);
        setTitle('');
        setDescription('');
        onClose();
      }, 1500);
    } catch (e: any) {
      setError(e?.response?.data?.error ?? 'Upload failed. Check file size and type.');
    }
  };

  const handleClose = () => {
    if (!uploadMutation.isPending) {
      setFile(null);
      setTitle('');
      setDescription('');
      setError(null);
      setSuccess(false);
      onClose();
    }
  };

  return (
    <Dialog
      open={open}
      onClose={handleClose}
      maxWidth="sm"
      fullWidth
      PaperProps={{
        sx: {
          bgcolor: '#0a0e1a',
          border: '1px solid rgba(0,243,255,0.15)',
          backgroundImage: 'none',
        }
      }}
    >
      <DialogTitle sx={{
        fontFamily: 'Orbitron',
        color: '#00f3ff',
        fontSize: '0.8rem',
        letterSpacing: 2,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        borderBottom: '1px solid rgba(255,255,255,0.06)',
        pb: 1.5,
      }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Upload size={14} />
          UPLOAD EVIDENCE
        </Box>
        <IconButton onClick={handleClose} size="small" sx={{ color: 'rgba(255,255,255,0.4)' }}>
          <X size={14} />
        </IconButton>
      </DialogTitle>

      <DialogContent sx={{ pt: 2 }}>
        {uploadMutation.isPending && <LinearProgress sx={{ mb: 2, bgcolor: 'rgba(0,243,255,0.1)', '& .MuiLinearProgress-bar': { bgcolor: '#00f3ff' } }} />}
        {success && <Alert severity="success" sx={{ mb: 2, fontSize: '0.75rem' }}>Evidence uploaded successfully!</Alert>}
        {error && <Alert severity="error" sx={{ mb: 2, fontSize: '0.75rem' }}>{error}</Alert>}

        <Stack spacing={2}>
          {/* Drop Zone */}
          <Box
            sx={{
              border: `2px dashed ${file ? 'rgba(0,243,255,0.4)' : 'rgba(255,255,255,0.1)'}`,
              borderRadius: 2,
              p: 3,
              textAlign: 'center',
              cursor: 'pointer',
              transition: 'all 0.2s',
              '&:hover': { borderColor: 'rgba(0,243,255,0.4)', bgcolor: 'rgba(0,243,255,0.02)' },
            }}
            onClick={() => fileRef.current?.click()}
            onDragOver={e => e.preventDefault()}
            onDrop={e => {
              e.preventDefault();
              const f = e.dataTransfer.files[0];
              if (f) handleFileDrop(f);
            }}
          >
            <input
              ref={fileRef}
              type="file"
              style={{ display: 'none' }}
              onChange={e => { if (e.target.files?.[0]) handleFileDrop(e.target.files[0]); }}
            />
            {file ? (
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 1 }}>
                <File size={20} color="#00f3ff" />
                <Box sx={{ textAlign: 'left' }}>
                  <Typography variant="body2" sx={{ color: '#fff', fontWeight: 500, fontSize: '0.8rem' }}>{file.name}</Typography>
                  <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.4)', fontFamily: 'monospace', fontSize: '0.65rem' }}>
                    {(file.size / (1024 * 1024)).toFixed(2)} MB
                  </Typography>
                </Box>
              </Box>
            ) : (
              <>
                <Upload size={32} color="rgba(255,255,255,0.2)" />
                <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.4)', mt: 1, fontSize: '0.8rem' }}>
                  Drop file here or click to browse
                </Typography>
                <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.25)', fontSize: '0.65rem' }}>
                  Max 50 MB · Screenshots, PCAPs, HAR, logs, reports
                </Typography>
              </>
            )}
          </Box>

          {/* Fields */}
          <FormControl fullWidth size="small">
            <InputLabel sx={{ color: 'rgba(255,255,255,0.4)', fontSize: '0.8rem' }}>Evidence Type</InputLabel>
            <Select
              value={evidenceType}
              onChange={e => setEvidenceType(e.target.value)}
              label="Evidence Type"
              sx={{ color: '#fff', fontSize: '0.8rem', '& .MuiOutlinedInput-notchedOutline': { borderColor: 'rgba(255,255,255,0.1)' } }}
            >
              {EVIDENCE_TYPES.map(t => (
                <MenuItem key={t.value} value={t.value} sx={{ fontSize: '0.8rem' }}>{t.label}</MenuItem>
              ))}
            </Select>
          </FormControl>

          <TextField
            label="Title"
            value={title}
            onChange={e => setTitle(e.target.value)}
            size="small"
            fullWidth
            required
            InputProps={{ sx: { color: '#fff', fontSize: '0.8rem' } }}
            InputLabelProps={{ sx: { color: 'rgba(255,255,255,0.4)', fontSize: '0.8rem' } }}
            sx={{ '& .MuiOutlinedInput-notchedOutline': { borderColor: 'rgba(255,255,255,0.1)' } }}
          />

          <TextField
            label="Description (optional)"
            value={description}
            onChange={e => setDescription(e.target.value)}
            size="small"
            fullWidth
            multiline
            rows={2}
            InputProps={{ sx: { color: '#fff', fontSize: '0.8rem' } }}
            InputLabelProps={{ sx: { color: 'rgba(255,255,255,0.4)', fontSize: '0.8rem' } }}
            sx={{ '& .MuiOutlinedInput-notchedOutline': { borderColor: 'rgba(255,255,255,0.1)' } }}
          />
        </Stack>
      </DialogContent>

      <DialogActions sx={{ borderTop: '1px solid rgba(255,255,255,0.06)', px: 2, py: 1.5, gap: 1 }}>
        <Button onClick={handleClose} size="small" sx={{ color: 'rgba(255,255,255,0.4)', fontSize: '0.7rem' }}>
          Cancel
        </Button>
        <Button
          variant="contained"
          size="small"
          startIcon={<Upload size={12} />}
          onClick={handleUpload}
          disabled={!file || !title || uploadMutation.isPending}
          sx={{
            bgcolor: '#00f3ff',
            color: '#000',
            fontSize: '0.7rem',
            fontFamily: 'Orbitron',
            '&:hover': { bgcolor: '#00c8d4' },
            '&:disabled': { bgcolor: 'rgba(0,243,255,0.2)', color: 'rgba(0,0,0,0.4)' },
          }}
        >
          {uploadMutation.isPending ? 'Uploading…' : 'Upload Evidence'}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
