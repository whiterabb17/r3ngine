import React from 'react';
import { 
  Box, 
  Paper, 
  Typography, 
  Button, 
  Link,
  Stack
} from '@mui/material';
import { LogIn, Globe, ExternalLink, Heart } from 'lucide-react';
import { useNavigate } from '@tanstack/react-router';

export const LogoutPage: React.FC = () => {
  const navigate = useNavigate();

  return (
    <Box sx={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      position: 'relative',
      overflow: 'hidden',
    }}>
      {/* Blur only the background image — never the logout card */}
      <Box
        aria-hidden
        sx={{
          position: 'absolute',
          inset: 0,
          backgroundImage: 'url("/staticfiles/img/neon_city.png")',
          backgroundSize: 'cover',
          backgroundPosition: 'center',
          backgroundRepeat: 'no-repeat',
          filter: 'blur(8px)',
          transform: 'scale(1.08)',
          zIndex: 0,
        }}
      />
      <Box
        aria-hidden
        sx={{
          position: 'absolute',
          inset: 0,
          bgcolor: 'rgba(0, 0, 0, 0.7)',
          zIndex: 0,
        }}
      />
      <Paper elevation={24} sx={{
        position: 'relative',
        zIndex: 1,
        width: '100%',
        maxWidth: 450,
        bgcolor: 'rgba(10, 10, 15, 0.94)',
        border: '1px solid rgba(0, 243, 255, 0.3)',
        borderRadius: 4,
        p: 5,
        textAlign: 'center',
        boxShadow: '0 0 40px rgba(0, 243, 255, 0.15)'
      }}>
        <Box sx={{ mb: 4 }}>
          <img src="/img/r3ngine_logo.png" alt="reNgine Logo" style={{ height: 80, marginBottom: 24 }} />
          
          <Typography variant="h4" sx={{ 
            fontFamily: 'Orbitron', 
            fontWeight: 900, 
            mb: 2,
            color: '#fff',
            textShadow: '0 0 10px rgba(255, 255, 255, 0.3)'
          }}>
            FAREWELL, AGENT
          </Typography>
          
          <Typography variant="h6" sx={{ 
            color: '#00f3ff', 
            fontWeight: 500,
            mb: 3,
            fontFamily: 'Inter'
          }}>
            You have been successfully logged out.
          </Typography>

          <Typography sx={{ color: 'rgba(255, 255, 255, 0.6)', mb: 4, lineHeight: 1.6 }}>
            Thank you for using reNgine for your reconnaissance operations. 
            The system state has been secured and your session terminated.
          </Typography>
        </Box>

        <Stack spacing={2}>
          <Button
            fullWidth
            variant="contained"
            startIcon={<LogIn size={18} />}
            onClick={() => navigate({ to: '/login' })}
            sx={{ 
              py: 1.5,
              bgcolor: '#00f3ff',
              color: '#000',
              fontFamily: 'Orbitron',
              fontWeight: 900,
              letterSpacing: 1,
              '&:hover': { bgcolor: '#00d4df' }
            }}
          >
            LOG BACK IN
          </Button>

          <Button
            fullWidth
            variant="outlined"
            startIcon={<Globe size={18} />}
            component={Link}
            href="https://github.com/whiterabb17/r3ngine/issues"
            target="_blank"
            sx={{ 
              py: 1.5,
              color: 'rgba(255, 255, 255, 0.7)',
              borderColor: 'rgba(255, 255, 255, 0.2)',
              fontFamily: 'Orbitron',
              fontWeight: 700,
              textDecoration: 'none',
              '&:hover': { 
                borderColor: 'rgba(255, 255, 255, 0.5)',
                bgcolor: 'rgba(255, 255, 255, 0.05)'
              }
            }}
          >
            REPORT AN ISSUE
          </Button>
        </Stack>

        <Box sx={{ mt: 5, pt: 3, borderTop: '1px solid rgba(255, 255, 255, 0.05)' }}>
          <Typography variant="caption" sx={{ color: 'rgba(255, 255, 255, 0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 1 }}>
            Made with <Heart size={12} color="#ff003c" fill="#ff003c" /> by reNgine Team
          </Typography>
        </Box>
      </Paper>
    </Box>
  );
};
