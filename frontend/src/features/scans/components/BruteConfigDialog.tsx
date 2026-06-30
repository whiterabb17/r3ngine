import React, { useState } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  TextField,
  Box,
  Typography,
  IconButton,
  MenuItem,
  Select,
  FormControl,
  InputLabel,
  CircularProgress,
  Collapse,
  Paper,
  Stack
} from '@mui/material';
import { X, Upload, Play, Key, ChevronDown, ChevronRight } from 'lucide-react';
import { useWordlists, useUploadWordlist } from '../../engines/api';
import { useThemeTokens } from '../../../theme/useThemeTokens';

interface BruteConfigDialogProps {
  open: boolean;
  onClose: () => void;
  onSubmit: (params: {
    tool: string;
    wordlist_user: string;
    wordlist_pass: string;
    threads: number;
    additional_flags: string;
  }) => void;
  targetUrl: string;
  isPending?: boolean;
}

export const BruteConfigDialog: React.FC<BruteConfigDialogProps> = ({
  open,
  onClose,
  onSubmit,
  targetUrl,
  isPending = false
}) => {
  const { tokens, isLight, theme } = useThemeTokens();
  const { data: wordlists, isLoading: isWlLoading } = useWordlists();
  const uploadWordlist = useUploadWordlist();

  // Brute force configuration state
  const [tool, setTool] = useState('brutus');
  const [wordlistUser, setWordlistUser] = useState('');
  const [wordlistPass, setWordlistPass] = useState('');
  const [threads, setThreads] = useState(5);
  const [additionalFlags, setAdditionalFlags] = useState('');

  // Inline upload state
  const [showUpload, setShowUpload] = useState(false);
  const [uploadName, setUploadName] = useState('');
  const [uploadShortName, setUploadShortName] = useState('');
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [uploadTarget, setUploadTarget] = useState<'both' | 'user' | 'pass'>('both');
  const [uploadError, setUploadError] = useState('');
  const [uploadSuccess, setUploadSuccess] = useState('');

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setUploadFile(e.target.files[0]);
    }
  };

  const handleUploadSubmit = async (e: React.MouseEvent) => {
    e.preventDefault();
    if (!uploadName || !uploadShortName || !uploadFile) {
      setUploadError('All upload fields are required');
      return;
    }
    setUploadError('');
    setUploadSuccess('');

    const formData = new FormData();
    formData.append('name', uploadName);
    formData.append('short_name', uploadShortName);
    formData.append('upload_file', uploadFile);

    try {
      const response = await uploadWordlist.mutateAsync(formData);
      setUploadSuccess('Wordlist uploaded successfully!');
      
      // Auto select the new wordlist
      const shortNameValue = uploadShortName;
      if (uploadTarget === 'both' || uploadTarget === 'user') {
        setWordlistUser(shortNameValue);
      }
      if (uploadTarget === 'both' || uploadTarget === 'pass') {
        setWordlistPass(shortNameValue);
      }

      // Reset upload fields
      setUploadName('');
      setUploadShortName('');
      setUploadFile(null);
      // Wait a little bit then hide the upload panel
      setTimeout(() => {
        setShowUpload(false);
        setUploadSuccess('');
      }, 1500);
    } catch (err: any) {
      setUploadError(err.message || 'Failed to upload wordlist');
    }
  };

  const handleSubmitClick = () => {
    onSubmit({
      tool,
      wordlist_user: wordlistUser,
      wordlist_pass: wordlistPass,
      threads,
      additional_flags: additionalFlags
    });
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      maxWidth="sm"
      fullWidth
      slotProps={{
        paper: {
          sx: {
            bgcolor: isLight ? 'background.paper' : '#0a0a0c',
            border: `1px solid ${isLight ? 'rgba(0,0,0,0.1)' : `${tokens.accent.primary}33`}`,
            boxShadow: isLight ? '0 10px 40px rgba(0,0,0,0.08)' : `0 0 30px ${tokens.accent.primary}1A`,
          }
        }
      }}
    >
      <DialogTitle sx={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        borderBottom: '1px solid',
        borderColor: 'divider',
        pb: 2
      }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
          <Play size={20} style={{ color: tokens.accent.primary }} />
          <Typography sx={{ fontFamily: 'Orbitron', fontWeight: 800, color: 'text.primary', letterSpacing: 1 }}>
            BRUTE TEST TARGET CONFIG
          </Typography>
        </Box>
        <IconButton onClick={onClose} size="small" sx={{ color: 'text.secondary' }}>
          <X size={20} />
        </IconButton>
      </DialogTitle>

      <DialogContent sx={{ mt: 3, display: 'flex', flexDirection: 'column', gap: 2.5 }}>
        <Box>
          <Typography variant="caption" sx={{ color: 'text.secondary', fontWeight: 700, letterSpacing: 0.5 }}>
            TARGET URL
          </Typography>
          <Typography sx={{ fontSize: '12px', fontFamily: 'monospace', color: tokens.accent.primary, wordBreak: 'break-all' }}>
            {targetUrl}
          </Typography>
        </Box>

        {/* Tool Dropdown */}
        <FormControl fullWidth variant="filled">
          <InputLabel sx={{ fontFamily: 'Orbitron', fontSize: '0.7rem', color: isLight ? 'text.secondary' : `${tokens.accent.primary}aa` }}>
            SELECT BRUTE TOOL
          </InputLabel>
          <Select
            value={tool}
            onChange={(e) => setTool(e.target.value)}
            sx={{
              '&:before, &:after': { display: 'none' },
              border: '1px solid',
              borderColor: 'divider',
              borderRadius: 0.5,
              bgcolor: isLight ? 'rgba(0,0,0,0.01)' : 'rgba(255,255,255,0.02)',
              fontSize: '13px',
              fontFamily: 'monospace'
            }}
          >
            <MenuItem value="brutus">Brutus (Default HTTP Web Bruting)</MenuItem>
            <MenuItem value="netexec">NetExec (Active Directory SMB/Service Spraying)</MenuItem>
            <MenuItem value="kerbrute">Kerbrute (AD User Enumeration & Spraying)</MenuItem>
            <MenuItem value="hashcat">Hashcat (Offline Hash Cracking)</MenuItem>
          </Select>
        </FormControl>

        <Stack direction="row" spacing={2}>
          {/* User Wordlist Dropdown */}
          <FormControl fullWidth variant="filled">
            <InputLabel sx={{ fontFamily: 'Orbitron', fontSize: '0.7rem', color: isLight ? 'text.secondary' : `${tokens.accent.primary}aa` }}>
              USERNAME WORDLIST
            </InputLabel>
            <Select
              value={wordlistUser}
              onChange={(e) => setWordlistUser(e.target.value)}
              disabled={isWlLoading}
              sx={{
                '&:before, &:after': { display: 'none' },
                border: '1px solid',
                borderColor: 'divider',
                borderRadius: 0.5,
                bgcolor: isLight ? 'rgba(0,0,0,0.01)' : 'rgba(255,255,255,0.02)',
                fontSize: '13px',
                fontFamily: 'monospace'
              }}
            >
              <MenuItem value="">System Default (default_users.txt)</MenuItem>
              {wordlists?.map(wl => (
                <MenuItem key={`user-${wl.id}`} value={wl.short_name}>
                  {wl.name} ({wl.count} entries)
                </MenuItem>
              ))}
            </Select>
          </FormControl>

          {/* Pass Wordlist Dropdown */}
          <FormControl fullWidth variant="filled">
            <InputLabel sx={{ fontFamily: 'Orbitron', fontSize: '0.7rem', color: isLight ? 'text.secondary' : `${tokens.accent.primary}aa` }}>
              PASSWORD WORDLIST
            </InputLabel>
            <Select
              value={wordlistPass}
              onChange={(e) => setWordlistPass(e.target.value)}
              disabled={isWlLoading}
              sx={{
                '&:before, &:after': { display: 'none' },
                border: '1px solid',
                borderColor: 'divider',
                borderRadius: 0.5,
                bgcolor: isLight ? 'rgba(0,0,0,0.01)' : 'rgba(255,255,255,0.02)',
                fontSize: '13px',
                fontFamily: 'monospace'
              }}
            >
              <MenuItem value="">System Default (default_passwords.txt)</MenuItem>
              {wordlists?.map(wl => (
                <MenuItem key={`pass-${wl.id}`} value={wl.short_name}>
                  {wl.name} ({wl.count} entries)
                </MenuItem>
              ))}
            </Select>
          </FormControl>
        </Stack>

        <Stack direction="row" spacing={2}>
          {/* Threads Input */}
          <TextField
            label="THREAD COUNT"
            type="number"
            value={threads}
            onChange={(e) => setThreads(Math.max(1, parseInt(e.target.value) || 1))}
            variant="filled"
            sx={{
              width: '120px',
              '& .MuiFilledInput-root': {
                bgcolor: isLight ? 'rgba(0,0,0,0.01)' : 'rgba(255,255,255,0.02)',
                '&:before, &:after': { display: 'none' },
                border: '1px solid',
                borderColor: 'divider',
                color: 'text.primary',
                fontFamily: 'monospace'
              },
              '& .MuiInputLabel-root': { color: isLight ? 'text.secondary' : `${tokens.accent.primary}aa`, fontFamily: 'Orbitron', fontSize: '0.7rem' }
            }}
          />

          {/* Additional Flags */}
          <TextField
            label="ADDITIONAL CLI FLAGS"
            placeholder="e.g. -f --safe"
            value={additionalFlags}
            onChange={(e) => setAdditionalFlags(e.target.value)}
            fullWidth
            variant="filled"
            sx={{
              '& .MuiFilledInput-root': {
                bgcolor: isLight ? 'rgba(0,0,0,0.01)' : 'rgba(255,255,255,0.02)',
                '&:before, &:after': { display: 'none' },
                border: '1px solid',
                borderColor: 'divider',
                color: 'text.primary',
                fontFamily: 'monospace'
              },
              '& .MuiInputLabel-root': { color: isLight ? 'text.secondary' : `${tokens.accent.primary}aa`, fontFamily: 'Orbitron', fontSize: '0.7rem' }
            }}
          />
        </Stack>

        {/* Inline Wordlist Upload Collapse */}
        <Box sx={{ mt: 1 }}>
          <Button
            size="small"
            onClick={() => setShowUpload(!showUpload)}
            endIcon={showUpload ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
            sx={{
              fontFamily: 'Orbitron',
              fontSize: '10px',
              fontWeight: 800,
              color: tokens.accent.primary,
              p: 0,
              '&:hover': { bgcolor: 'transparent', opacity: 0.8 }
            }}
          >
            UPLOAD NEW WORDLIST PAYLOAD INLINE
          </Button>

          <Collapse in={showUpload} sx={{ mt: 1.5 }}>
            <Paper sx={{
              p: 2,
              border: `1px dashed ${tokens.accent.primary}44`,
              bgcolor: isLight ? 'rgba(0,0,0,0.01)' : 'rgba(255,255,255,0.01)',
              display: 'flex',
              flexDirection: 'column',
              gap: 2
            }}>
              <Stack direction="row" spacing={2}>
                <TextField
                  label="WORDLIST NAME"
                  placeholder="e.g. Custom Admin Passlist"
                  value={uploadName}
                  onChange={(e) => setUploadName(e.target.value)}
                  fullWidth
                  variant="filled"
                  sx={{
                    '& .MuiFilledInput-root': {
                      bgcolor: isLight ? 'rgba(0,0,0,0.02)' : 'rgba(255,255,255,0.03)',
                      '&:before, &:after': { display: 'none' },
                      border: '1px solid',
                      borderColor: 'divider',
                      color: 'text.primary',
                      fontSize: '11px',
                    },
                    '& .MuiInputLabel-root': { color: 'text.secondary', fontFamily: 'Orbitron', fontSize: '0.65rem' }
                  }}
                />

                <TextField
                  label="SHORT IDENTIFIER"
                  placeholder="e.g. custom_admin_pass"
                  value={uploadShortName}
                  onChange={(e) => setUploadShortName(e.target.value)}
                  fullWidth
                  variant="filled"
                  sx={{
                    '& .MuiFilledInput-root': {
                      bgcolor: isLight ? 'rgba(0,0,0,0.02)' : 'rgba(255,255,255,0.03)',
                      '&:before, &:after': { display: 'none' },
                      border: '1px solid',
                      borderColor: 'divider',
                      color: 'text.primary',
                      fontSize: '11px',
                    },
                    '& .MuiInputLabel-root': { color: 'text.secondary', fontFamily: 'Orbitron', fontSize: '0.65rem' }
                  }}
                />
              </Stack>

              <Stack direction="row" spacing={2} sx={{ justifyContent: 'space-between', alignItems: 'center' }}>
                <Box>
                  <input
                    type="file"
                    accept=".txt"
                    id="brute-wordlist-file-input"
                    onChange={handleFileChange}
                    style={{ display: 'none' }}
                  />
                  <label htmlFor="brute-wordlist-file-input">
                    <Button
                      variant="outlined"
                      component="span"
                      startIcon={<Upload size={12} />}
                      sx={{
                        fontFamily: 'Orbitron',
                        fontSize: '9px',
                        borderColor: tokens.accent.primary,
                        color: tokens.accent.primary,
                        '&:hover': { borderColor: tokens.accent.primary, bgcolor: `${tokens.accent.primary}0D` }
                      }}
                    >
                      {uploadFile ? uploadFile.name : 'SELECT FILE (.TXT)'}
                    </Button>
                  </label>
                </Box>

                <FormControl variant="filled" size="small" sx={{ width: '150px' }}>
                  <InputLabel sx={{ fontFamily: 'Orbitron', fontSize: '0.6rem', color: 'text.secondary' }}>USE AS</InputLabel>
                  <Select
                    value={uploadTarget}
                    onChange={(e) => setUploadTarget(e.target.value as any)}
                    sx={{
                      '&:before, &:after': { display: 'none' },
                      border: '1px solid',
                      borderColor: 'divider',
                      borderRadius: 0.5,
                      bgcolor: isLight ? 'rgba(0,0,0,0.02)' : 'rgba(255,255,255,0.03)',
                      fontSize: '11px',
                    }}
                  >
                    <MenuItem value="both">Both User/Pass</MenuItem>
                    <MenuItem value="user">User list only</MenuItem>
                    <MenuItem value="pass">Pass list only</MenuItem>
                  </Select>
                </FormControl>

                <Button
                  onClick={handleUploadSubmit}
                  disabled={!uploadName || !uploadShortName || !uploadFile || uploadWordlist.isPending}
                  variant="contained"
                  sx={{
                    bgcolor: tokens.accent.primary,
                    color: '#fff',
                    fontFamily: 'Orbitron',
                    fontSize: '9px',
                    fontWeight: 900,
                    height: '32px',
                    px: 3,
                    '&:hover': { opacity: 0.9 },
                    '&.Mui-disabled': { bgcolor: 'action.disabledBackground', color: 'action.disabled' }
                  }}
                >
                  {uploadWordlist.isPending ? 'UPLOADING...' : 'SAVE PAYLOAD'}
                </Button>
              </Stack>

              {uploadError && (
                <Typography sx={{ color: tokens.accent.error, fontSize: '10px', fontWeight: 700 }}>
                  {uploadError}
                </Typography>
              )}
              {uploadSuccess && (
                <Typography sx={{ color: tokens.accent.success, fontSize: '10px', fontWeight: 700 }}>
                  {uploadSuccess}
                </Typography>
              )}
            </Paper>
          </Collapse>
        </Box>
      </DialogContent>

      <DialogActions sx={{ p: 3, borderTop: '1px solid', borderColor: 'divider' }}>
        <Button
          onClick={onClose}
          sx={{ color: 'text.secondary', fontFamily: 'Orbitron', fontSize: '0.7rem' }}
        >
          CANCEL
        </Button>
        <Button
          onClick={handleSubmitClick}
          disabled={isPending}
          variant="contained"
          startIcon={isPending ? <CircularProgress size={12} color="inherit" /> : <Play size={12} />}
          sx={{
            bgcolor: tokens.accent.primary,
            color: '#fff',
            fontFamily: 'Orbitron',
            fontWeight: 900,
            fontSize: '0.75rem',
            px: 4,
            '&:hover': { opacity: 0.9 }
          }}
        >
          {isPending ? 'DISPATCHING...' : 'START BRUTE TEST'}
        </Button>
      </DialogActions>
    </Dialog>
  );
};
