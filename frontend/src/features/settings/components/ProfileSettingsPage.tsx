import React, { useState } from 'react';
import {
  Box,
  Typography,
  Paper,
  Grid,
  TextField,
  Button,
  Divider,
  Alert,
  Snackbar,
  IconButton,
  InputAdornment,
} from '@mui/material';
import {
  User,
  Lock,
  Eye,
  EyeOff,
  CheckCircle,
  AlertCircle,
  Shield,
} from 'lucide-react';
import { useParams } from '@tanstack/react-router';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import { changePassword } from '../../auth/api';

export const ProfileSettingsPage: React.FC = () => {
  const { tokens } = useThemeTokens();
  const { projectSlug } = useParams({ from: '/$projectSlug' });
  const [showOldPassword, setShowOldPassword] = useState(false);
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  
  const [formData, setFormData] = useState({
    old_password: '',
    new_password1: '',
    new_password2: '',
  });

  const [notification, setNotification] = useState<{
    open: boolean;
    message: string;
    severity: 'success' | 'error';
  }>({
    open: false,
    message: '',
    severity: 'success',
  });

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData((prev) => ({
      ...prev,
      [name]: value,
    }));
  };

  const handlePasswordChange = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (formData.new_password1 !== formData.new_password2) {
      setNotification({
        open: true,
        message: 'New passwords do not match!',
        severity: 'error',
      });
      return;
    }

    try {
      const accepted = await changePassword(projectSlug, formData);

      if (accepted) {
        setNotification({
          open: true,
          message: 'Password changed successfully!',
          severity: 'success',
        });
        setFormData({
          old_password: '',
          new_password1: '',
          new_password2: '',
        });
      } else {
        setNotification({
          open: true,
          message: 'Failed to change password. Please check your old password.',
          severity: 'error',
        });
      }
    } catch (error) {
      setNotification({
        open: true,
        message: 'An error occurred while changing password.',
        severity: 'error',
      });
    }
  };

  const handleCloseNotification = () => {
    setNotification((prev) => ({ ...prev, open: false }));
  };

  return (
    <Box sx={{ p: { xs: 2, md: 4 }, maxWidth: 1200, margin: '0 auto' }}>
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
          MY PROFILE
        </Typography>
        <Box sx={{ flexGrow: 1, height: '1px', background: `linear-gradient(90deg, ${tokens.accent.primary}80, transparent)` }} />
      </Box>

      <Paper
        elevation={0}
        sx={{
          p: 4,
          background: 'background.paper',
          backdropFilter: 'blur(10px)',
          border: 1,
          borderColor: 'divider',
          borderRadius: 2,
          position: 'relative',
          overflow: 'hidden',
          '&::before': {
            content: '""',
            position: 'absolute',
            top: 0,
            left: 0,
            width: '100%',
            height: '2px',
            background: `linear-gradient(90deg, transparent, ${tokens.accent.primary}, transparent)`,
            opacity: 0.5
          }
        }}
      >
        <Typography 
          variant="h5" 
          sx={{ 
            fontFamily: 'Orbitron', 
            mb: 4, 
            color: tokens.accent.primary,
            display: 'flex',
            alignItems: 'center',
            gap: 1.5,
            fontSize: '1.2rem'
          }}
        >
          HI ROOT!
        </Typography>

        <Grid container spacing={4}>
          {/* Username Section */}
          <Grid size={{xs: 12}} >
            <Typography variant="subtitle2" sx={{ color: 'text.secondary', mb: 1, textTransform: 'uppercase', letterSpacing: 1 }}>
              Username
            </Typography>
            <TextField
              fullWidth
              value="@root"
              disabled
              variant="outlined"
              slotProps={{
                input: {
                  startAdornment: (
                    <InputAdornment position="start">
                      <User size={18} color="rgba(255,255,255,0.3)" />
                    </InputAdornment>
                  ),
                }
              }}
              sx={{
                '& .MuiOutlinedInput-root': {
                  bgcolor: 'action.hover',
                  color: 'text.secondary',
                  '& fieldset': { borderColor: 'divider' },
                }
              }}
            />
          </Grid>

          <Grid size={{xs: 12}} >
            <Divider sx={{ borderColor: 'divider', my: 2 }} />
          </Grid>

          {/* Change Password Section */}
          <Grid size={{xs: 12}} >
            <Typography 
              variant="h6" 
              sx={{ 
                fontFamily: 'Orbitron', 
                mb: 3, 
                color: 'text.primary',
                fontSize: '1rem',
                letterSpacing: 1,
                display: 'flex',
                alignItems: 'center',
                gap: 1
              }}
            >
              <Lock size={18} color={tokens.accent.primary} />
              CHANGE PASSWORD
            </Typography>

            <form onSubmit={handlePasswordChange}>
              <Grid container spacing={3}>
                <Grid size={{xs: 12}} >
                  <Typography variant="subtitle2" sx={{ color: 'text.secondary', mb: 1 }}>
                    Old Password
                  </Typography>
                  <TextField
                    fullWidth
                    type={showOldPassword ? 'text' : 'password'}
                    name="old_password"
                    value={formData.old_password}
                    onChange={handleInputChange}
                    required
                    placeholder="Enter old password"
                    slotProps={{
                      input: {
                        endAdornment: (
                          <InputAdornment position="end">
                              <IconButton onClick={() => setShowOldPassword(!showOldPassword)} edge="end" sx={{ color: 'text.disabled' }}>
                              {showOldPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                            </IconButton>
                          </InputAdornment>
                        ),
                      }
                    }}
                    sx={{
                      '& .MuiOutlinedInput-root': {
                        color: 'text.primary',
                        bgcolor: 'action.hover',
                        '& fieldset': { borderColor: 'divider' },
                        '&:hover fieldset': { borderColor: `${tokens.accent.primary}4D` },
                        '&.Mui-focused fieldset': { borderColor: tokens.accent.primary },
                      },
                      '& .MuiInputBase-input::placeholder': {
                        color: 'text.disabled',
                        opacity: 1,
                      }
                    }}
                  />
                </Grid>

                <Grid size={{xs: 12, md: 6}} >
                  <Typography variant="subtitle2" sx={{ color: 'text.secondary', mb: 1 }}>
                    New Password
                  </Typography>
                  <TextField
                    fullWidth
                    type={showNewPassword ? 'text' : 'password'}
                    name="new_password1"
                    value={formData.new_password1}
                    onChange={handleInputChange}
                    required
                    placeholder="Enter new password"
                    slotProps={{
                      input: {
                        endAdornment: (
                          <InputAdornment position="end">
                              <IconButton onClick={() => setShowNewPassword(!showNewPassword)} edge="end" sx={{ color: 'text.disabled' }}>
                              {showNewPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                            </IconButton>
                          </InputAdornment>
                        ),
                      }
                    }}
                    sx={{
                      '& .MuiOutlinedInput-root': {
                        color: 'text.primary',
                        bgcolor: 'action.hover',
                        '& fieldset': { borderColor: 'divider' },
                        '&:hover fieldset': { borderColor: `${tokens.accent.primary}4D` },
                        '&.Mui-focused fieldset': { borderColor: tokens.accent.primary },
                      },
                      '& .MuiInputBase-input::placeholder': {
                        color: 'text.disabled',
                        opacity: 1,
                      }
                    }}
                  />
                </Grid>

                <Grid size={{xs: 12, md: 6}} >
                  <Typography variant="subtitle2" sx={{ color: 'text.secondary', mb: 1 }}>
                    Confirm Password
                  </Typography>
                  <TextField
                    fullWidth
                    type={showConfirmPassword ? 'text' : 'password'}
                    name="new_password2"
                    value={formData.new_password2}
                    onChange={handleInputChange}
                    required
                    placeholder="Confirm new password"
                    slotProps={{
                      input: {
                        endAdornment: (
                          <InputAdornment position="end">
                              <IconButton onClick={() => setShowConfirmPassword(!showConfirmPassword)} edge="end" sx={{ color: 'text.disabled' }}>
                              {showConfirmPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                            </IconButton>
                          </InputAdornment>
                        ),
                      }
                    }}
                    sx={{
                      '& .MuiOutlinedInput-root': {
                        color: 'text.primary',
                        bgcolor: 'action.hover',
                        '& fieldset': { borderColor: 'divider' },
                        '&:hover fieldset': { borderColor: `${tokens.accent.primary}4D` },
                        '&.Mui-focused fieldset': { borderColor: tokens.accent.primary },
                      },
                      '& .MuiInputBase-input::placeholder': {
                        color: 'text.disabled',
                        opacity: 1,
                      }
                    }}
                  />
                </Grid>

                <Grid size={{xs: 12}} sx={{ display: 'flex', justifyContent: 'flex-end', mt: 2 }}>
                  <Button
                    type="submit"
                    variant="contained"
                    sx={{
                      bgcolor: `${tokens.accent.primary}1A`,
                      color: tokens.accent.primary,
                      border: `1px solid ${tokens.accent.primary}`,
                      fontFamily: 'Orbitron',
                      fontWeight: 600,
                      px: 4,
                      py: 1,
                      '&:hover': {
                        bgcolor: tokens.accent.primary,
                        color: '#000',
                        boxShadow: `0 0 20px ${tokens.accent.primary}66`
                      }
                    }}
                  >
                    CHANGE PASSWORD
                  </Button>
                </Grid>
              </Grid>
            </form>
          </Grid>
        </Grid>
      </Paper>

      {/* Security Info Card */}
      <Box sx={{ mt: 4 }}>
        <Paper
          sx={{
            p: 3,
            background: 'linear-gradient(135deg, rgba(255, 0, 60, 0.05) 0%, transparent 100%)',
            border: '1px solid rgba(255, 0, 60, 0.1)',
            borderRadius: 2,
            display: 'flex',
            alignItems: 'flex-start',
            gap: 2
          }}
        >
          <Shield color="#ff003c" size={24} style={{ marginTop: 4 }} />
          <Box>
            <Typography variant="h6" sx={{ color: '#ff003c', fontFamily: 'Orbitron', fontSize: '0.9rem', mb: 1 }}>
              SECURITY PROTOCOL
            </Typography>
            <Typography variant="body2" sx={{ color: 'text.secondary', lineHeight: 1.6 }}>
              Ensure your password is at least 12 characters long and contains a mix of alphanumeric characters and special symbols. 
              Avoid reusing passwords from other platforms. Your security is the priority of the reNgine perimeter.
            </Typography>
          </Box>
        </Paper>
      </Box>

      <Snackbar
        open={notification.open}
        autoHideDuration={6000}
        onClose={handleCloseNotification}
        anchorOrigin={{ vertical: 'top', horizontal: 'right' }}
      >
        <Alert 
          onClose={handleCloseNotification} 
          severity={notification.severity}
          sx={{ 
            width: '100%',
            bgcolor: notification.severity === 'success' ? 'rgba(0, 200, 83, 0.9)' : 'rgba(211, 47, 47, 0.9)',
            color: '#fff',
            backdropFilter: 'blur(10px)',
            '& .MuiAlert-icon': { color: '#fff' }
          }}
        >
          {notification.message}
        </Alert>
      </Snackbar>
    </Box>
  );
};
