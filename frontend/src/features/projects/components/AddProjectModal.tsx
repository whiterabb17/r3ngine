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
  CircularProgress,
  Alert,
  useTheme,
  type Theme,
} from '@mui/material';
import { X, FolderPlus } from 'lucide-react';
import { useCreateProject } from '../api';

interface AddProjectModalProps {
  open: boolean;
  onClose: () => void;
}

export const AddProjectModal: React.FC<AddProjectModalProps> = ({ open, onClose }) => {
  const [projectName, setProjectName] = useState('');
  const { mutate: createProject, isPending, error, reset } = useCreateProject();
  const theme = useTheme();
  const isLight = theme.palette.mode === 'light';

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!projectName.trim()) return;

    createProject(projectName, {
      onSuccess: () => {
        onClose();
        setProjectName('');
        reset();
      },
    });
  };

  const handleClose = () => {
    onClose();
    reset();
  };

  return (
    <Dialog
      open={open}
      onClose={handleClose}
      slotProps={{
        paper: {
          sx: {
            bgcolor: isLight ? 'background.paper' : 'rgba(10, 10, 20, 0.95)',
            backdropFilter: 'blur(20px)',
            border: isLight ? '1px solid rgba(0, 0, 0, 0.1)' : '1px solid rgba(0, 243, 255, 0.2)',
            borderRadius: 4,
            backgroundImage: isLight ? 'none' : 'radial-gradient(circle at top right, rgba(0, 243, 255, 0.05), transparent)',
            maxWidth: 450,
            width: '100%'
          }
        }
      }}
    >
      <DialogTitle sx={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        borderBottom: '1px solid',
        borderColor: 'divider',
        pb: 2
      }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
          <Box sx={{
            p: 1,
            borderRadius: 2,
            bgcolor: isLight ? 'rgba(2, 132, 199, 0.1)' : 'rgba(0, 243, 255, 0.1)',
            color: isLight ? 'primary.main' : '#00f3ff',
            display: 'flex'
          }}>
            <FolderPlus size={20} />
          </Box>
          <Typography variant="h6" sx={{
            fontFamily: 'Orbitron',
            fontWeight: 800,
            letterSpacing: 1,
            color: 'text.primary'
          }}>
            NEW PROJECT INITIALIZATION
          </Typography>
        </Box>
        <IconButton onClick={handleClose} sx={{ color: 'text.secondary', '&:hover': { color: '#ff003c' } }}>
          <X size={20} />
        </IconButton>
      </DialogTitle>

      <form onSubmit={handleSubmit}>
        <DialogContent sx={{ mt: 3 }}>
          {error && (
            <Alert severity="error" sx={{
              mb: 3,
              bgcolor: 'rgba(255, 0, 60, 0.1)',
              color: '#ff003c',
              border: '1px solid rgba(255, 0, 60, 0.2)',
              '& .MuiAlert-icon': { color: '#ff003c' }
            }}>
              {error.message}
            </Alert>
          )}

          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
            <TextField
              label="PROJECT NAME"
              fullWidth
              autoFocus
              required
              value={projectName}
              onChange={(e) => setProjectName(e.target.value)}
              placeholder="e.g. Cybersec_Audit_2024"
              sx={getFieldStyles(isLight, theme)}
              helperText="A slug will be automatically generated from the project name."
              slotProps={{
                formHelperText: { sx: { color: 'text.secondary' } }
              }}
            />
          </Box>
        </DialogContent>

        <DialogActions sx={{ p: 3, borderTop: '1px solid', borderColor: 'divider' }}>
          <Button
            onClick={handleClose}
            sx={{
              color: 'text.secondary',
              fontFamily: 'Orbitron',
              fontSize: '0.7rem',
              fontWeight: 800
            }}
          >
            ABORT
          </Button>
          <Button
            type="submit"
            variant="contained"
            disabled={isPending || !projectName.trim()}
            sx={{
              bgcolor: isLight ? 'primary.main' : '#00f3ff',
              color: isLight ? '#fff' : '#000',
              fontWeight: 900,
              fontFamily: 'Orbitron',
              letterSpacing: 1,
              px: 4,
              '&:hover': {
                bgcolor: isLight ? 'primary.dark' : '#00d1db',
                boxShadow: isLight ? 'none' : '0 0 20px rgba(0, 243, 255, 0.4)'
              },
              '&.Mui-disabled': {
                bgcolor: isLight ? 'action.disabledBackground' : 'rgba(0, 243, 255, 0.2)',
                color: 'action.disabled'
              }
            }}
          >
            {isPending ? <CircularProgress size={20} sx={{ color: isLight ? '#fff' : '#000' }} /> : 'INITIALIZE PROJECT'}
          </Button>
        </DialogActions>
      </form>
    </Dialog>
  );
};

const getFieldStyles = (isLight: boolean, theme: Theme) => ({
  '& .MuiOutlinedInput-root': {
    color: 'text.primary',
    '& fieldset': { borderColor: isLight ? 'rgba(0,0,0,0.15)' : 'rgba(255,255,255,0.1)' },
    '&:hover fieldset': { borderColor: isLight ? theme.palette.primary.main : 'rgba(0, 243, 255, 0.3)' },
    '&.Mui-focused fieldset': { borderColor: isLight ? theme.palette.primary.main : '#00f3ff' },
    bgcolor: isLight ? 'rgba(0,0,0,0.02)' : 'rgba(255,255,255,0.03)',
  },
  '& .MuiInputLabel-root': {
    color: 'text.secondary',
    '&.Mui-focused': { color: isLight ? theme.palette.primary.main : '#00f3ff' }
  },
});
