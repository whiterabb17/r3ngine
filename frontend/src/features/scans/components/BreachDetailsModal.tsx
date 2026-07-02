import React from 'react';
import {
  Box,
  Typography,
  Chip,
  Stack,
  Button,
  Grid,
  Card,
  CardContent,
  Dialog,
  DialogTitle,
  DialogContent,
  IconButton,
} from '@mui/material';
import { ExternalLink, X } from 'lucide-react';
import { useThemeTokens } from '../../../theme/useThemeTokens';

interface BreachDetailsModalProps {
  open: boolean;
  onClose: () => void;
  breaches: any[] | null;
}

export const BreachDetailsModal: React.FC<BreachDetailsModalProps> = ({ open, onClose, breaches }) => {
  const { tokens } = useThemeTokens();

  if (!breaches) return null;

  return (
    <Dialog 
      open={open} 
      onClose={onClose}
      maxWidth="md"
      fullWidth
      sx={{
        '& .MuiDialog-paper': {
          bgcolor: 'background.paper',
          border: `1px solid ${tokens.border.subtle}`,
          backgroundImage: 'none'
        }
      }}
    >
      <DialogTitle sx={{ 
        fontFamily: 'Orbitron', 
        fontWeight: 900, 
        display: 'flex', 
        justifyContent: 'space-between', 
        alignItems: 'center',
        color: tokens.accent.primary
      }}>
        BREACH DETAILS
        <IconButton size="small" onClick={onClose} sx={{ color: 'text.secondary' }}>
          <X size={16} />
        </IconButton>
      </DialogTitle>
      <DialogContent dividers sx={{ borderColor: tokens.border.subtle }}>
        <Grid container spacing={2}>
          {breaches.map((breach: any) => (
            <Grid size={{ xs: 12, sm: 6 }} key={breach.id}>
              <Card sx={{ bgcolor: 'background.paper', border: `1px solid ${tokens.border.subtle}`, borderRadius: 1 }}>
                <CardContent sx={{ p: 2.5, '&:last-child': { pb: 2.5 } }}>
                  <Stack direction="row" sx={{ justifyContent: 'space-between', alignItems: 'flex-start', mb: 1.5 }}>
                    <Box>
                      <Typography variant="subtitle2" sx={{ fontWeight: 800, color: tokens.accent.primary }}>{breach.breach_name}</Typography>
                      <Typography sx={{ fontSize: '0.65rem', fontFamily: 'monospace', color: 'text.secondary' }}>Target: {breach.email_address}</Typography>
                    </Box>
                    <Chip label={breach.breach_date || 'Unknown Date'} size="small" sx={{ bgcolor: 'action.hover', color: 'text.primary', fontSize: '0.65rem', fontWeight: 700 }} />
                  </Stack>
                  <Typography sx={{ fontSize: '0.75rem', color: 'text.secondary', mb: 2, lineHeight: 1.4 }}>{breach.description}</Typography>
                  <Box sx={{ mb: 2 }}>
                    <Typography sx={{ fontSize: '10px', fontWeight: 800, color: 'text.primary', mb: 0.5, letterSpacing: 0.5 }}>COMPROMISED DATA:</Typography>
                    <Stack direction="row" sx={{ flexWrap: 'wrap', gap: 0.5 }}>
                      {breach.compromised_data?.map((dataClass: string) => (
                        <Chip 
                          key={dataClass} 
                          label={dataClass.toUpperCase()} 
                          size="small" 
                          sx={{ 
                            bgcolor: 'rgba(255,0,60,0.1)', 
                            color: '#ff003c', 
                            fontSize: '0.55rem', 
                            fontWeight: 900, 
                            height: '18px', 
                            border: '1px solid rgba(255,0,60,0.2)' 
                          }} 
                        />
                      ))}
                    </Stack>
                  </Box>
                  <Button size="small" variant="outlined" component="a"
                    href={`https://haveibeenpwned.com/Breach/${encodeURIComponent(breach.breach_name)}`}
                    target="_blank" endIcon={<ExternalLink size={10} />}
                    sx={{ fontSize: '0.65rem', fontWeight: 900, fontFamily: 'Orbitron', color: tokens.accent.primary, borderColor: 'rgba(112,0,255,0.3)', '&:hover': { borderColor: tokens.accent.primary, bgcolor: 'rgba(112,0,255,0.05)' } }}>
                    View Details
                  </Button>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      </DialogContent>
    </Dialog>
  );
};
