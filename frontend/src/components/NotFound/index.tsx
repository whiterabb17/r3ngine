import { useThemeTokens } from '../../theme/useThemeTokens';
import React from 'react';
import { Box, Typography, Button, alpha } from '@mui/material';
import { ShieldAlert, Home, RefreshCw } from 'lucide-react';
import { Link } from '@tanstack/react-router';

export const NotFound: React.FC = () => {
  const { tokens } = useThemeTokens();
  return (
    <Box
      sx={{
        height: '80vh',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'center',
        alignItems: 'center',
        textAlign: 'center',
        position: 'relative',
        overflow: 'hidden'
      }}
    >
      {/* Glitch Effect Background */}
      <Box sx={{
        position: 'absolute',
        fontSize: '15rem',
        fontWeight: 900,
        opacity: 0.03,
        color: tokens.accent.error,
        zIndex: 0,
        userSelect: 'none',
        fontFamily: 'Orbitron'
      }}>
        404
      </Box>

      <Box sx={{ zIndex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
        <Box sx={{
          p: 3,
          borderRadius: '50%',
          bgcolor: alpha(tokens.accent.error, 0.1),
          border: `2px solid ${alpha(tokens.accent.error, 0.3)}`,
          boxShadow: `0 0 30px ${alpha(tokens.accent.error, 0.2)}`,
          mb: 4,
        }}>
          <ShieldAlert size={64} color={tokens.accent.error} />
        </Box>

        <Typography variant="h2" sx={{
          fontFamily: 'Orbitron',
          fontWeight: 900,
          letterSpacing: 4,
          color: 'text.primary',
          mb: 1,
          textShadow: `0 0 10px ${alpha(tokens.accent.error, 0.8)}`
        }}>
          SIGNAL LOST
        </Typography>

        <Typography variant="h6" sx={{
          color: tokens.accent.error,
          fontWeight: 800,
          fontFamily: 'Orbitron',
          mb: 4,
          opacity: 0.8
        }}>
          UNAUTHORIZED SECTOR ACCESS
        </Typography>

        <Typography variant="body1" sx={{ color: tokens.text.secondary, maxWidth: 450, mb: 6, lineHeight: 1.6 }}>
          The tactical coordinates you provided do not match any known sectors in the reNgine perimeter.
          Return to base or verify the target parameters.
        </Typography>

        <Box sx={{ display: 'flex', gap: 3 }}>
          <Button
            component={Link}
            to="/"
            variant="contained"
            startIcon={<Home size={18} />}
            sx={{
              bgcolor: alpha(tokens.text.primary, 0.05),
              color: 'text.primary',
              border: `1px solid ${tokens.border.subtle}`,
              '&:hover': { bgcolor: alpha(tokens.text.primary, 0.1), borderColor: tokens.text.primary },
              fontFamily: 'Orbitron',
              fontWeight: 800,
              px: 4
            }}
          >
            Return to Dashboard
          </Button>
          <Button
            onClick={() => window.location.reload()}
            variant="outlined"
            startIcon={<RefreshCw size={18} />}
            sx={{
              borderColor: tokens.accent.error,
              color: tokens.accent.error,
              '&:hover': { borderColor: tokens.accent.error, bgcolor: alpha(tokens.accent.error, 0.05) },
              fontFamily: 'Orbitron',
              fontWeight: 800,
              px: 4
            }}
          >
            Reconnect Signal
          </Button>
        </Box>
      </Box>
    </Box>
  );
};
