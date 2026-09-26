import React, { useState } from 'react';
import {
  Box,
  Paper,
  Typography,
  TextField,
  Button,
  IconButton,
  InputAdornment,
  Alert,
  Link
} from '@mui/material';
import { Eye, EyeOff, User, Lock, ExternalLink } from 'lucide-react';
import { useAppContext } from '../../../context/AppContext';
import { useLogin } from '../api';

/** Static grain overlay — same look as animated canvas static, zero rAF cost */
const StaticOverlay: React.FC = () => (
  <Box
    aria-hidden
    sx={{
      position: 'absolute',
      top: 0,
      left: 0,
      width: '100%',
      height: '100%',
      borderRadius: 'inherit',
      pointerEvents: 'none',
      zIndex: 0,
      backgroundImage: 'url("/staticfiles/img/cyber_noise.png")',
      backgroundSize: '128px 128px',
      backgroundRepeat: 'repeat',
      opacity: 0.22,
      mixBlendMode: 'overlay',
    }}
  />
);

export const LoginPage: React.FC = () => {
  const { version } = useAppContext();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loginMutation = useLogin();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    const formData = new FormData();
    formData.append('username', username);
    formData.append('password', password);

    try {
      const response = await loginMutation.mutateAsync(formData);
      if (response.status) {
        window.location.href = response.redirect_url || '/';
      } else {
        setError(response.message || 'Invalid username or password.');
      }
    } catch (err: any) {
      setError('An error occurred during login. Please try again.');
    }
  };

  return (
    <Box sx={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      backgroundImage: 'url("/staticfiles/img/neon_city.png")',
      backgroundSize: 'cover',
      backgroundPosition: 'center',
      backgroundRepeat: 'no-repeat',
      position: 'relative',
      '&::before': {
        content: '""',
        position: 'absolute',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        bgcolor: 'rgba(0, 0, 0, 0.6)',
        backdropFilter: 'blur(4px)'
      }
    }}>
      <Paper elevation={24} sx={{
        position: 'relative',
        zIndex: 1,
        width: '100%',
        maxWidth: 400,
        bgcolor: 'rgba(10, 10, 15, 0.9)',
        backdropFilter: 'blur(12px)',
        border: '1px solid rgba(255, 255, 255, 0.1)',
        borderRadius: 4,
        overflow: 'hidden',
        boxShadow: '0 0 40px rgba(0, 0, 0, 0.4)',
        transition: 'border-color 0.4s cubic-bezier(0.4, 0, 0.2, 1), box-shadow 0.4s cubic-bezier(0.4, 0, 0.2, 1)',
        '&:hover': {
          borderColor: 'rgba(0, 243, 255, 0.3)',
          boxShadow: '0 0 50px rgba(0, 243, 255, 0.1)'
        }
      }}>
        <StaticOverlay />
        <Box sx={{ position: 'relative', zIndex: 1, width: '100%', p: 4, display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
        <Box sx={{ mb: 3, textAlign: 'center' }}>
          <img src="/staticfiles/img/r3ngine_logo.png" alt="reNgine Logo" style={{ height: 80, marginBottom: 16 }} />
          <Typography variant="h5" sx={{
            fontFamily: 'Orbitron',
            fontWeight: 900,
            letterSpacing: 2,
            color: '#00f3ff',
            textShadow: '0 0 10px rgba(0, 243, 255, 0.5)'
          }}>
            LOGIN TO RENGINE
          </Typography>
          <Typography variant="caption" sx={{ color: 'rgba(255, 255, 255, 0.5)', mt: 1, display: 'block' }}>
            Current release: v{version}
          </Typography>
        </Box>

        <Alert severity="info" sx={{
          width: '100%',
          mb: 3,
          bgcolor: 'rgba(0, 243, 255, 0.05)',
          color: '#00f3ff',
          border: '1px solid rgba(0, 243, 255, 0.15)',
          borderRadius: 2,
          '& .MuiAlert-icon': { color: '#00f3ff' }
        }}>
          <Link href="https://rengine.wiki" target="_blank" sx={{ color: 'inherit', display: 'flex', alignItems: 'center', gap: 0.5, textDecoration: 'none' }}>
            Learn how to create reNgine account <ExternalLink size={14} />
          </Link>
        </Alert>

        {error && (
          <Alert severity="error" sx={{ width: '100%', mb: 3 }}>
            {error}
          </Alert>
        )}

        <form onSubmit={handleSubmit} style={{ width: '100%' }}>
          <Box sx={{ mb: 3 }}>
            <Typography variant="caption" sx={{ color: 'rgba(255, 255, 255, 0.7)', mb: 1, display: 'block', fontWeight: 800 }}>
              Username
            </Typography>
            <TextField
              fullWidth
              variant="outlined"
              placeholder="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              slotProps={{
                input: {
                  startAdornment: (
                    <InputAdornment position="start">
                      <Typography sx={{ color: 'rgba(255, 255, 255, 0.5)', fontWeight: 'bold', mr: 1 }}>@</Typography>
                    </InputAdornment>
                  ),
                  sx: {
                    bgcolor: 'rgba(8, 8, 14, 0.92)',
                    color: '#fff',
                    borderRadius: 2,
                    '& .MuiOutlinedInput-notchedOutline': { borderColor: 'rgba(255, 255, 255, 0.08)' },
                    '&:hover .MuiOutlinedInput-notchedOutline': { borderColor: 'rgba(0, 243, 255, 0.3)' },
                    '&.Mui-focused .MuiOutlinedInput-notchedOutline': { borderColor: '#00f3ff' }
                  }
                }
              }}
            />
          </Box>

          <Box sx={{ mb: 4 }}>
            <Typography variant="caption" sx={{ color: 'rgba(255, 255, 255, 0.7)', mb: 1, display: 'block', fontWeight: 800 }}>
              Password
            </Typography>
            <TextField
              fullWidth
              type={showPassword ? 'text' : 'password'}
              variant="outlined"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              slotProps={{
                input: {
                  startAdornment: (
                    <InputAdornment position="start">
                      <Lock size={18} color="rgba(255, 255, 255, 0.5)" />
                    </InputAdornment>
                  ),
                  endAdornment: (
                    <InputAdornment position="end">
                      <IconButton onClick={() => setShowPassword(!showPassword)} sx={{ color: 'rgba(255, 255, 255, 0.5)' }}>
                        {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                      </IconButton>
                    </InputAdornment>
                  ),
                  sx: {
                    bgcolor: 'rgba(8, 8, 14, 0.92)',
                    color: '#fff',
                    borderRadius: 2,
                    '& .MuiOutlinedInput-notchedOutline': { borderColor: 'rgba(255, 255, 255, 0.08)' },
                    '&:hover .MuiOutlinedInput-notchedOutline': { borderColor: 'rgba(0, 243, 255, 0.3)' },
                    '&.Mui-focused .MuiOutlinedInput-notchedOutline': { borderColor: '#00f3ff' }
                  }
                }
              }}
            />
          </Box>

          <Button
            type="submit"
            fullWidth
            variant="contained"
            disabled={loginMutation.isPending}
            sx={{
              py: 1.5,
              background: 'linear-gradient(135deg, #00f3ff 0%, #7000ff 100%)',
              color: '#fff',
              fontFamily: 'Orbitron',
              fontWeight: 900,
              letterSpacing: 2,
              clipPath: 'polygon(12px 0, 100% 0, 100% calc(100% - 12px), calc(100% - 12px) 100%, 0 100%, 0 12px)',
              transition: 'all 0.3s ease',
              '&:hover': {
                background: 'linear-gradient(135deg, #00f3ff 20%, #7000ff 80%)',
                filter: 'drop-shadow(0 0 10px rgba(0, 243, 255, 0.5))',
                transform: 'translateY(-2px)'
              },
              '&.Mui-disabled': {
                background: 'rgba(0, 243, 255, 0.1)',
                color: 'rgba(255, 255, 255, 0.3)',
                clipPath: 'polygon(12px 0, 100% 0, 100% calc(100% - 12px), calc(100% - 12px) 100%, 0 100%, 0 12px)'
              }
            }}
          >
            {loginMutation.isPending ? 'AUTHENTICATING...' : 'LOG IN'}
          </Button>
        </form>

        <Box sx={{ mt: 4, textAlign: 'center' }}>
          <Typography variant="caption" sx={{ color: 'rgba(255, 255, 255, 0.4)' }}>
            Issues or feature requests? <Link href="https://github.com/whiterabb17/r3ngine/issues" target="_blank" sx={{ color: '#00f3ff' }}>Raise issue on Github.</Link>
          </Typography>
        </Box>
        </Box>
      </Paper>
    </Box>
  );
};
