import React, { useState, useCallback } from 'react';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import Tab from '@mui/material/Tab';
import Tabs from '@mui/material/Tabs';
import TextField from '@mui/material/TextField';
import Typography from '@mui/material/Typography';
import Alert from '@mui/material/Alert';
import { Upload } from 'lucide-react';
import { useThemeTokens } from '../../../../theme/useThemeTokens';
import { useManualAddEmails } from '../../api';

interface EmailImportModalProps {
  open: boolean;
  onClose: () => void;
  scanId: number;
  onSuccess: () => void;
}

const EMAIL_REGEX = /^[a-zA-Z0-9.+\-_]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/;

function parseAddresses(raw: string): string[] {
  return raw
    .split(/[\n,;]+/)
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

function partitionAddresses(raw: string): { valid: string[]; invalid: string[] } {
  const all = parseAddresses(raw);
  const valid: string[] = [];
  const invalid: string[] = [];
  for (const addr of all) {
    (EMAIL_REGEX.test(addr) ? valid : invalid).push(addr);
  }
  return { valid, invalid };
}

export const EmailImportModal: React.FC<EmailImportModalProps> = ({
  open, onClose, scanId, onSuccess,
}) => {
  const { tokens } = useThemeTokens();
  const [tab, setTab] = useState(0);
  const [pasteText, setPasteText] = useState('');
  const [fileText, setFileText] = useState('');
  const [fileName, setFileName] = useState('');
  const [fileError, setFileError] = useState('');
  const addMutation = useManualAddEmails();

  const rawText = tab === 0 ? pasteText : fileText;
  const { valid, invalid } = partitionAddresses(rawText);

  const handleFileChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (!file.name.match(/\.(txt|csv)$/i)) {
      setFileError('Only .txt and .csv files are supported.');
      return;
    }
    setFileError('');
    setFileName(file.name);
    const reader = new FileReader();
    reader.onload = (ev) => {
      try {
        setFileText((ev.target?.result as string) ?? '');
      } catch {
        setFileError('Could not parse file — ensure it is plain text or CSV.');
      }
    };
    reader.onerror = () => setFileError('Could not read file.');
    reader.readAsText(file);
  }, []);

  const handleSubmit = async () => {
    if (valid.length === 0) return;
    try {
      await addMutation.mutateAsync({ scanId, addresses: valid });
      onSuccess();
      onClose();
      setPasteText('');
      setFileText('');
      setFileName('');
    } catch {
      // mutation.isError is now true; MUI shows error via addMutation.isError state
      // No additional action needed — TanStack Query sets error state automatically
    }
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>Add / Import Email Addresses</DialogTitle>
      <DialogContent>
        <Tabs value={tab} onChange={(_, v) => setTab(v as number)} sx={{ mb: 2 }}>
          <Tab label="Paste List" />
          <Tab label="Upload File" />
        </Tabs>

        {tab === 0 && (
          <TextField
            multiline
            rows={8}
            fullWidth
            placeholder={'one@example.com\ntwo@example.com, three@example.com'}
            value={pasteText}
            onChange={(e) => setPasteText(e.target.value)}
            helperText="Accepts comma, semicolon, or newline-separated addresses"
          />
        )}

        {tab === 1 && (
          <Box>
            <Button
              variant="outlined"
              component="label"
              startIcon={<Upload size={16} />}
              sx={{ mb: 2 }}
            >
              {fileName ? `Change file (${fileName})` : 'Choose .txt or .csv file'}
              <input
                type="file"
                accept=".txt,.csv"
                hidden
                onChange={handleFileChange}
              />
            </Button>
            {fileError && <Alert severity="error" sx={{ mb: 1 }}>{fileError}</Alert>}
            {fileName && !fileError && (
              <Typography variant="body2" sx={{ color: tokens.text.secondary }}>
                Loaded: {fileName}
              </Typography>
            )}
          </Box>
        )}

        {rawText && (
          <Box sx={{ mt: 2 }}>
            <Typography variant="caption" sx={{ color: tokens.text.secondary }}>
              {valid.length} valid
              {invalid.length > 0 && (
                <span style={{ color: tokens.accent.warning }}>
                  {' '}· {invalid.length} invalid
                </span>
              )}
            </Typography>
          </Box>
        )}
        {addMutation.isError && (
          <Alert severity="error" sx={{ mt: 1 }}>
            Failed to add emails. Please try again.
          </Alert>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button
          variant="contained"
          onClick={handleSubmit}
          disabled={valid.length === 0 || addMutation.isPending}
        >
          {addMutation.isPending ? 'Adding...' : `Add ${valid.length} Email${valid.length !== 1 ? 's' : ''}`}
        </Button>
      </DialogActions>
    </Dialog>
  );
};
