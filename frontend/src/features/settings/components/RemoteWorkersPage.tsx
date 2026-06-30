import React, { useState } from 'react';
import {
  Box,
  Typography,
  Stack,
  Button,
  Paper,
  Divider,
  Alert,
  CircularProgress,
  Snackbar,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  IconButton,
  Tooltip,
} from '@mui/material';
import { Trash2, Server, Key, Activity, Clock, Plus } from 'lucide-react';
import {
  useRemoteWorkers,
  useCreateRemoteWorker,
  useDeleteRemoteWorker,
} from '../api';
import { TacticalPanel } from '../../../components/TacticalPanel';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import { formatDistanceToNow } from 'date-fns';

export const RemoteWorkersPage: React.FC = () => {
  const { tokens, theme } = useThemeTokens();
  const { data: workers, isLoading } = useRemoteWorkers();
  const createWorker = useCreateRemoteWorker();
  const deleteWorker = useDeleteRemoteWorker();

  const [newWorkerName, setNewWorkerName] = useState('');
  const [newWorkerToken, setNewWorkerToken] = useState('');
  const [snackbar, setSnackbar] = useState<{
    open: boolean;
    message: string;
    severity: 'success' | 'error' | 'info' | 'warning';
  }>({
    open: false,
    message: '',
    severity: 'success',
  });

  const handleCloseSnackbar = () => {
    setSnackbar({ ...snackbar, open: false });
  };

  const handleCreateWorker = async () => {
    if (!newWorkerName.trim() || !newWorkerToken.trim()) return;
    try {
      await createWorker.mutateAsync({ name: newWorkerName.trim(), auth_token: newWorkerToken.trim() });
      setNewWorkerName('');
      setNewWorkerToken('');
      setSnackbar({
        open: true,
        message: 'Worker created successfully',
        severity: 'success',
      });
    } catch (err: any) {
      setSnackbar({
        open: true,
        message: err.response?.data?.message || 'Failed to create worker',
        severity: 'error',
      });
    }
  };

  const handleDeleteWorker = async (id: number) => {
    if (window.confirm('Are you sure you want to delete this remote worker?')) {
      try {
        await deleteWorker.mutateAsync(id);
        setSnackbar({
          open: true,
          message: 'Worker deleted successfully',
          severity: 'success',
        });
      } catch (err: any) {
        setSnackbar({
          open: true,
          message: err.response?.data?.message || 'Failed to delete worker',
          severity: 'error',
        });
      }
    }
  };

  if (isLoading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
        <CircularProgress sx={{ color: tokens.accent.primary }} />
      </Box>
    );
  }

  return (
    <Box>
      <Box sx={{ mb: 3 }}>
        <Typography variant="h5" sx={{ color: theme.palette.text.primary, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 1 }}>
          <Server size={24} color={tokens.accent.primary} />
          Remote Workers
        </Typography>
        <Typography variant="body2" sx={{ color: theme.palette.text.secondary, mt: 0.5 }}>
          Manage remote Python orchestrator workers for distributed scanning.
        </Typography>
      </Box>

      <TacticalPanel
        title="Add New Worker"
        icon={<Plus size={20} />}
      >
        <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} sx={{ alignItems: 'center' }}>
          <Box sx={{ flexGrow: 1, width: '100%' }}>
            <TextField
              fullWidth
              size="small"
              label="Worker Name"
              value={newWorkerName}
              onChange={(e) => setNewWorkerName(e.target.value)}
              placeholder="e.g., worker-us-east-1"
              sx={{
                '& .MuiOutlinedInput-root': {
                  color: theme.palette.text.primary,
                  '& fieldset': { borderColor: tokens.border.subtle },
                  '&:hover fieldset': { borderColor: tokens.border.strong },
                  '&.Mui-focused fieldset': { borderColor: tokens.accent.primary },
                },
                '& .MuiInputLabel-root': { color: theme.palette.text.secondary },
              }}
            />
          </Box>
          <Box sx={{ flexGrow: 1, width: '100%' }}>
            <TextField
              fullWidth
              size="small"
              label="Auth Token"
              value={newWorkerToken}
              onChange={(e) => setNewWorkerToken(e.target.value)}
              placeholder="e.g., secret-token-123"
              sx={{
                '& .MuiOutlinedInput-root': {
                  color: theme.palette.text.primary,
                  '& fieldset': { borderColor: tokens.border.subtle },
                  '&:hover fieldset': { borderColor: tokens.border.strong },
                  '&.Mui-focused fieldset': { borderColor: tokens.accent.primary },
                },
                '& .MuiInputLabel-root': { color: theme.palette.text.secondary },
              }}
            />
          </Box>
          <Box sx={{ width: { xs: '100%', md: 'auto' }, minWidth: 150 }}>
            <Button
              variant="contained"
              fullWidth
              onClick={handleCreateWorker}
              disabled={!newWorkerName.trim() || !newWorkerToken.trim() || createWorker.isPending}
              sx={{
                bgcolor: tokens.accent.primary,
                color: theme.palette.background.paper,
                '&:hover': { bgcolor: tokens.accent.info },
              }}
            >
              {createWorker.isPending ? <CircularProgress size={24} /> : 'Create Worker'}
            </Button>
          </Box>
        </Stack>
      </TacticalPanel>

      <Box sx={{ mt: 3 }}>
        <TacticalPanel
          title="Active Workers"
          icon={<Activity size={20} />}
        >
          {workers && workers.length > 0 ? (
            <TableContainer component={Paper} sx={{ bgcolor: 'transparent', boxShadow: 'none' }}>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ color: theme.palette.text.secondary, borderBottom: `1px solid ${tokens.border.subtle}` }}>Name</TableCell>
                    <TableCell sx={{ color: theme.palette.text.secondary, borderBottom: `1px solid ${tokens.border.subtle}` }}>Token (Keep Secret)</TableCell>
                    <TableCell sx={{ color: theme.palette.text.secondary, borderBottom: `1px solid ${tokens.border.subtle}` }}>Last IP</TableCell>
                    <TableCell sx={{ color: theme.palette.text.secondary, borderBottom: `1px solid ${tokens.border.subtle}` }}>Last Heartbeat</TableCell>
                    <TableCell sx={{ color: theme.palette.text.secondary, borderBottom: `1px solid ${tokens.border.subtle}`, width: 60 }}>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {workers.map((worker) => (
                    <TableRow key={worker.id} hover sx={{ '&:last-child td, &:last-child th': { border: 0 } }}>
                      <TableCell sx={{ color: theme.palette.text.primary, borderBottom: `1px solid ${tokens.border.subtle}` }}>
                        <Typography variant="body2" sx={{ fontWeight: 500 }}>{worker.name}</Typography>
                      </TableCell>
                      <TableCell sx={{ color: theme.palette.text.primary, borderBottom: `1px solid ${tokens.border.subtle}` }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <Key size={14} color={theme.palette.text.secondary} />
                          <Typography variant="body2" sx={{ fontFamily: 'monospace', bgcolor: theme.palette.background.default, px: 1, py: 0.5, borderRadius: 1 }}>
                            {worker.auth_token}
                          </Typography>
                        </Box>
                      </TableCell>
                      <TableCell sx={{ color: theme.palette.text.primary, borderBottom: `1px solid ${tokens.border.subtle}` }}>
                        {worker.ip_address || 'N/A'}
                      </TableCell>
                      <TableCell sx={{ color: theme.palette.text.primary, borderBottom: `1px solid ${tokens.border.subtle}` }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <Clock size={14} color={theme.palette.text.secondary} />
                          <Typography variant="body2">
                            {worker.last_heartbeat ? formatDistanceToNow(new Date(worker.last_heartbeat), { addSuffix: true }) : 'Never'}
                          </Typography>
                        </Box>
                      </TableCell>
                      <TableCell sx={{ borderBottom: `1px solid ${tokens.border.subtle}` }}>
                        <Tooltip title="Delete Worker">
                          <IconButton
                            size="small"
                            onClick={() => handleDeleteWorker(worker.id)}
                            sx={{ color: tokens.accent.error }}
                          >
                            <Trash2 size={16} />
                          </IconButton>
                        </Tooltip>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          ) : (
            <Alert severity="info" sx={{ bgcolor: 'transparent', color: theme.palette.text.primary, border: `1px solid ${tokens.border.subtle}` }}>
              No remote workers configured. Add one above.
            </Alert>
          )}
        </TacticalPanel>
      </Box>

      <Snackbar
        open={snackbar.open}
        autoHideDuration={6000}
        onClose={handleCloseSnackbar}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert onClose={handleCloseSnackbar} severity={snackbar.severity} sx={{ width: '100%' }}>
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
};
