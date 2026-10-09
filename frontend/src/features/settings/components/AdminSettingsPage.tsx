import React, { useState } from 'react';
import {
  Box,
  Typography,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
  Button,
  Chip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  MenuItem,
  CircularProgress,
  Tooltip,
  Snackbar,
  Alert
} from '@mui/material';
import {
  Edit2 as EditIcon,
  Trash2 as DeleteIcon,
  UserPlus as PersonAddIcon,
  Power as PowerIcon,
} from 'lucide-react';
import { useUsers, useCreateUser, useToggleUserStatus, useUpdateUser, useDeleteUser } from '../api';
import type { User } from '../api';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import type { ApiErrorLike } from '../../../types/errors';


const ROLES = [
  { value: 'sys_admin', label: 'Sys Admin' },
  { value: 'auditor', label: 'Auditor' },
  { value: 'penetration_tester', label: 'Penetration Tester' },
];

export const AdminSettingsPage: React.FC = () => {
  const { tokens } = useThemeTokens();
  const { data: users, isLoading } = useUsers();
  const createUserMutation = useCreateUser();
  const toggleStatusMutation = useToggleUserStatus();
  const updateUserMutation = useUpdateUser();
  const deleteUserMutation = useDeleteUser();

  const textFieldStyle = {
    '& .MuiOutlinedInput-root': {
      '& fieldset': { borderColor: 'divider' },
      '&:hover fieldset': { borderColor: `${tokens.accent.primary}80` },
      '&.Mui-focused fieldset': { borderColor: tokens.accent.primary },
      backgroundColor: 'background.paper',
    },
    '& .MuiInputLabel-root': { color: 'text.secondary' },
    '& .MuiInputBase-input': { color: 'text.primary', fontFamily: 'Inter, sans-serif' },
  };

  const [isModalOpen, setIsModalOpen] = useState(false);
  const [editingUser, setEditingUser] = useState<User | null>(null);
  const [formData, setFormData] = useState({
    username: '',
    password: '',
    role: 'penetration_tester',
  });
  const [snackbar, setSnackbar] = useState<{
    open: boolean;
    message: string;
    severity: 'success' | 'error' | 'info' | 'warning';
  }>({
    open: false,
    message: '',
    severity: 'success',
  });

  const handleOpenModal = (user: User | null = null) => {
    if (user) {
      setEditingUser(user);
      setFormData({
        username: user.username,
        password: '',
        role: user.role,
      });
    } else {
      setEditingUser(null);
      setFormData({
        username: '',
        password: '',
        role: 'penetration_tester',
      });
    }
    setIsModalOpen(true);
  };

  const handleCloseModal = () => {
    setIsModalOpen(false);
    setEditingUser(null);
  };

  const handleCloseSnackbar = () => {
    setSnackbar({ ...snackbar, open: false });
  };

  const handleSubmit = async () => {
    try {
      if (editingUser) {
        await updateUserMutation.mutateAsync({
          userId: editingUser.id,
          data: {
            role: formData.role,
            password: formData.password || undefined,
          },
        });
        setSnackbar({ open: true, message: 'User updated successfully.', severity: 'success' });
      } else {
        await createUserMutation.mutateAsync(formData);
        setSnackbar({ open: true, message: 'User created successfully.', severity: 'success' });
      }
      handleCloseModal();
    } catch (caught) {
      const error = caught as ApiErrorLike;
      setSnackbar({ 
        open: true, 
        message: `Error: ${error?.response?.data?.message || error?.message || 'Action failed'}`, 
        severity: 'error' 
      });
    }
  };

  const handleToggleStatus = (userId: number) => {
    toggleStatusMutation.mutate(userId, {
      onSuccess: () => {
        setSnackbar({ open: true, message: 'User status toggled successfully.', severity: 'success' });
      },
      onError: (caught) => {
        const error = caught as ApiErrorLike;
        setSnackbar({ 
          open: true, 
          message: `Failed to toggle status: ${error?.response?.data?.message || error?.message}`, 
          severity: 'error' 
        });
      }
    });
  };

  const handleDeleteUser = (userId: number) => {
    if (window.confirm('Are you sure you want to delete this user?')) {
      deleteUserMutation.mutate(userId, {
        onSuccess: () => {
          setSnackbar({ open: true, message: 'User deleted successfully.', severity: 'success' });
        },
        onError: (caught) => {
          const error = caught as ApiErrorLike;
          setSnackbar({ 
            open: true, 
            message: `Failed to delete user: ${error?.response?.data?.message || error?.message}`, 
            severity: 'error' 
          });
        }
      });
    }
  };

  if (isLoading) {
    return (
      <Box sx={{ display: "flex", justifyContent: "center", alignItems: "center", height: "400px" }}>
        <CircularProgress sx={{ color: tokens.accent.primary }} />
      </Box>
    );
  }

  return (
    <Box sx={{ p: 4, maxWidth: '1200px', margin: '0 auto' }}>
      <Box sx={{ mb: 4, display: 'flex', alignItems: 'center', gap: 2 }}>
        <Typography
          variant="h4"
          sx={{
            fontFamily: 'Orbitron',
            fontWeight: 900,
            letterSpacing: 2,
            color: 'text.primary',
            textShadow: `0 0 15px ${tokens.accent.primary}4D`
          }}
        >
          USER MANAGEMENT
        </Typography>
        <Box sx={{ flexGrow: 1, height: '1px', background: `linear-gradient(90deg, ${tokens.accent.primary}80, transparent)` }} />
        <Button
          variant="contained"
          startIcon={<PersonAddIcon size={18} />}
          onClick={() => handleOpenModal()}
          sx={{
            bgcolor: tokens.accent.primary,
            color: '#000',
            fontFamily: 'Orbitron',
            fontWeight: 900,
            fontSize: '11px',
            px: 3,
            height: '36px',
            '&:hover': {
              bgcolor: tokens.accent.primary,
              filter: 'brightness(1.1)',
              boxShadow: `0 0 15px ${tokens.accent.primary}66`
            }
          }}
        >
          ADD NEW USER
        </Button>
      </Box>

      <TableContainer component={Paper} sx={{
        background: 'background.paper',
        backdropFilter: 'blur(10px)',
        border: 1,
        borderColor: 'divider',
        borderRadius: '12px',
        boxShadow: '0 8px 32px 0 rgba(0, 0, 0, 0.8)',
      }}>
        <Table>
          <TableHead>
            <TableRow sx={{ backgroundColor: 'action.hover' }}>
              <TableCell sx={{ color: tokens.accent.primary, fontWeight: 'bold', fontFamily: 'Orbitron' }}>USERNAME</TableCell>
              <TableCell sx={{ color: tokens.accent.primary, fontWeight: 'bold', fontFamily: 'Orbitron' }}>NAME</TableCell>
              <TableCell sx={{ color: tokens.accent.primary, fontWeight: 'bold', fontFamily: 'Orbitron' }}>ROLE</TableCell>
              <TableCell sx={{ color: tokens.accent.primary, fontWeight: 'bold', fontFamily: 'Orbitron' }}>CREATED ON</TableCell>
              <TableCell sx={{ color: tokens.accent.primary, fontWeight: 'bold', fontFamily: 'Orbitron' }}>LAST LOGGED IN</TableCell>
              <TableCell sx={{ color: tokens.accent.primary, fontWeight: 'bold', fontFamily: 'Orbitron' }}>STATUS</TableCell>
              <TableCell align="right" sx={{ color: tokens.accent.primary, fontWeight: 'bold', fontFamily: 'Orbitron' }}>ACTIONS</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {users?.map((user) => (
              <TableRow key={user.id} sx={{ '&:hover': { backgroundColor: 'action.hover' } }}>
                <TableCell sx={{ color: 'text.primary' }}>{user.username}</TableCell>
                <TableCell sx={{ color: 'text.primary' }}>{user.full_name}</TableCell>
                <TableCell>
                  <Chip
                    label={user.role.replace('_', ' ').toUpperCase()}
                    size="small"
                    sx={{
                      backgroundColor: `${tokens.accent.secondary}1A`,
                      color: tokens.accent.secondary,
                      border: `1px solid ${tokens.accent.secondary}4D`,
                      fontFamily: 'Orbitron',
                      fontSize: '0.7rem'
                    }}
                  />
                </TableCell>
                <TableCell sx={{ color: 'text.secondary' }}>{user.date_joined_humanized}</TableCell>
                <TableCell sx={{ color: 'text.secondary' }}>{user.last_login_humanized}</TableCell>
                <TableCell>
                  <Chip
                    label={user.is_active ? 'ACTIVE' : 'INACTIVE'}
                    size="small"
                    color={user.is_active ? 'success' : 'error'}
                    variant="outlined"
                    sx={{ fontFamily: 'Orbitron', fontSize: '0.6rem' }}
                  />
                </TableCell>
                <TableCell align="right">
                  <Tooltip title={user.is_active ? "Disable User" : "Enable User"}>
                    <IconButton size="small" onClick={() => handleToggleStatus(user.id)} sx={{ color: user.is_active ? tokens.accent.primary : '#ff0055' }}>
                      <PowerIcon />
                    </IconButton>
                  </Tooltip>
                  <Tooltip title="Edit User">
                    <IconButton size="small" onClick={() => handleOpenModal(user)} sx={{ color: tokens.accent.primary }}>
                      <EditIcon />
                    </IconButton>
                  </Tooltip>
                  <Tooltip title="Delete User">
                    <IconButton size="small" onClick={() => handleDeleteUser(user.id)} sx={{ color: '#ff0055' }}>
                      <DeleteIcon />
                    </IconButton>
                  </Tooltip>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      <Dialog
        open={isModalOpen}
        onClose={handleCloseModal}
        slotProps={{
          paper: {
            sx: {
              background: 'background.paper',
              backdropFilter: 'blur(20px)',
              border: 1,
              borderColor: 'divider',
              color: 'text.primary',
              minWidth: '400px'
            }
          }
        }}
      >
        <DialogTitle sx={{ fontFamily: 'Orbitron', color: tokens.accent.primary }}>
          {editingUser ? 'EDIT USER' : 'ADD NEW USER'}
        </DialogTitle>
        <DialogContent>
          <Box sx={{ mt: 2, display: 'flex', flexDirection: 'column', gap: 3 }}>
            {!editingUser && (
              <TextField
                label="Username"
                fullWidth
                value={formData.username}
                onChange={(e) => setFormData({ ...formData, username: e.target.value })}
                sx={textFieldStyle}
              />
            )}
            <TextField
              label={editingUser ? "New Password (leave empty to keep current)" : "Password"}
              type="password"
              fullWidth
              value={formData.password}
              onChange={(e) => setFormData({ ...formData, password: e.target.value })}
              sx={textFieldStyle}
            />
            <TextField
              select
              label="Role"
              fullWidth
              value={formData.role}
              onChange={(e) => setFormData({ ...formData, role: e.target.value })}
              sx={textFieldStyle}
            >
              {ROLES.map((option) => (
                <MenuItem key={option.value} value={option.value}>
                  {option.label}
                </MenuItem>
              ))}
            </TextField>
          </Box>
        </DialogContent>
        <DialogActions sx={{ p: 3 }}>
          <Button onClick={handleCloseModal} sx={{ color: 'text.secondary' }}>CANCEL</Button>
          <Button
            variant="contained"
            onClick={handleSubmit}
            sx={{
              backgroundColor: tokens.accent.primary,
              color: '#000',
              fontWeight: 'bold',
              '&:hover': { backgroundColor: tokens.accent.primary, filter: 'brightness(1.1)' }
            }}
          >
            {editingUser ? 'UPDATE' : 'CREATE'}
          </Button>
        </DialogActions>
      </Dialog>

      <Snackbar 
        open={snackbar.open} 
        autoHideDuration={6000} 
        onClose={handleCloseSnackbar}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        <Alert 
          onClose={handleCloseSnackbar} 
          severity={snackbar.severity} 
          variant="filled"
          sx={{ 
            fontFamily: 'Orbitron', 
            fontSize: '0.8rem',
            fontWeight: 700,
            bgcolor: snackbar.severity === 'success' ? `${tokens.accent.primary}E6` : 'rgba(255, 0, 85, 0.9)',
            color: '#000',
            '& .MuiAlert-icon': { color: '#000' }
          }}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
};
