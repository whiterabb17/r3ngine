import React, { useState } from 'react';
import {
  Box,
  Typography,
  TextField,
  Button,
  Stack,
  Switch,
  FormControlLabel,
  Grid,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Paper,
  InputAdornment,
  Divider,
  Alert
} from '@mui/material';
import {
  Rocket,
  FolderPlus,
  UserPlus,
  Shield,
  Key,
  Database,
  Target,
  ChevronRight,
  CheckCircle2,
  Lock,
  User,
  Zap,
  Globe,
  Mail,
  Infinity
} from 'lucide-react';
import { useNavigate } from '@tanstack/react-router';
import { useOnboarding } from '../api';
import type { OnboardingData } from '../api';
import type { ApiErrorLike } from '../../../types/errors';

const SECTION_TITLE_STYLE = {
  fontFamily: 'Orbitron',
  fontSize: '0.8rem',
  fontWeight: 900,
  color: 'rgba(0, 243, 255, 0.7)',
  letterSpacing: 2,
  mb: 2,
  display: 'flex',
  alignItems: 'center',
  gap: 1.5
};

export const OnboardingPage: React.FC = () => {
  const navigate = useNavigate();
  const onboardingMutation = useOnboarding();
  const [error, setError] = useState<string | null>(null);

  const [form, setForm] = useState<OnboardingData>({
    project_name: 'Default',
    create_username: '',
    create_password: '',
    create_user_role: 'sys_admin',
    key_openai: '',
    key_netlas: '',
    key_chaos: '',
    key_hackerone: '',
    username_hackerone: '',
    key_shodan: '',
    key_censys: '',
    bug_bounty_mode: false,
  });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      const response = await onboardingMutation.mutateAsync(form);
      if (response.status === false || response.error) {
        setError(response.error || 'An unexpected error occurred during onboarding.');
      } else {
        // Redirect to dashboard
        // Assuming the response contains the project slug or we redirect to a default path
        navigate({ to: '/' });
      }
    } catch (caught) {
      const err = caught as ApiErrorLike;
      setError(err?.response?.data?.error || 'Failed to complete setup. Please check your inputs.');
    }
  };

  return (
    <Box sx={{
      minHeight: '100vh',
      bgcolor: '#0a0a0a',
      backgroundImage: 'radial-gradient(circle at 50% 50%, rgba(0, 243, 255, 0.05) 0%, transparent 70%)',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      p: 4
    }}>
      <Box sx={{ maxWidth: 900, width: '100%' }}>
        {/* Header */}
        <Box sx={{ textAlign: 'center', mb: 6 }}>
          <Stack direction="row" spacing={2} sx={{ justifyContent: "center", alignItems: "center", mb: 2 }}>
            <Box sx={{
              width: 50,
              height: 50,
              borderRadius: '12px',
              bgcolor: 'rgba(0, 243, 255, 0.1)',
              border: '1px solid rgba(0, 243, 255, 0.3)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              boxShadow: '0 0 20px rgba(0, 243, 255, 0.2)'
            }}>
              <Rocket size={28} color="#00f3ff" />
            </Box>
            <Typography variant="h3" sx={{
              fontFamily: 'Orbitron',
              fontWeight: 900,
              color: '#fff',
              textShadow: '0 0 20px rgba(0, 243, 255, 0.5)'
            }}>
              INITIAL SETUP
            </Typography>
          </Stack>
          <Typography variant="body1" sx={{ color: 'rgba(255,255,255,0.6)', letterSpacing: 1 }}>
            INITIALIZING R3NGINE ENVIRONMENT V3
          </Typography>
        </Box>

        {error && (
          <Alert severity="error" sx={{
            mb: 4,
            bgcolor: 'rgba(211, 47, 47, 0.1)',
            color: '#ff5252',
            border: '1px solid rgba(211, 47, 47, 0.3)',
            '& .MuiAlert-icon': { color: '#ff5252' }
          }}>
            {error}
          </Alert>
        )}

        <form onSubmit={handleSubmit}>
          <Stack spacing={4}>
            {/* Project Section */}
            <Paper sx={{
              p: 3,
              bgcolor: 'rgba(255,255,255,0.02)',
              border: '1px solid rgba(255,255,255,0.05)',
              position: 'relative',
              overflow: 'hidden',
              '&::before': {
                content: '""',
                position: 'absolute',
                top: 0,
                left: 0,
                width: '4px',
                height: '100%',
                bgcolor: '#00f3ff'
              }
            }}>
              <Typography sx={SECTION_TITLE_STYLE}>
                <FolderPlus size={18} /> PROJECT_INITIALIZATION
              </Typography>
              <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.5)', mb: 3 }}>
                Define your first workspace to organize security assessments.
              </Typography>
              <TextField
                fullWidth
                label="Project Name"
                required
                value={form.project_name}
                onChange={(e) => setForm({ ...form, project_name: e.target.value })}
                variant="outlined"
                sx={{
                  '& .MuiOutlinedInput-root': {
                    color: '#fff',
                    bgcolor: 'rgba(255,255,255,0.03)'
                  }
                }}
              />
            </Paper>

            {/* User Section */}
            <Paper sx={{
              p: 3,
              bgcolor: 'rgba(255,255,255,0.02)',
              border: '1px solid rgba(255,255,255,0.05)',
              position: 'relative',
              overflow: 'hidden',
              '&::before': {
                content: '""',
                position: 'absolute',
                top: 0,
                left: 0,
                width: '4px',
                height: '100%',
                bgcolor: '#ffd600'
              }
            }}>
              <Typography sx={SECTION_TITLE_STYLE}>
                <UserPlus size={18} /> OPERATOR PROVISIONING
              </Typography>
              <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.5)', mb: 3 }}>
                Create an additional system operator with specific access privileges.
              </Typography>
              <Grid container spacing={3}>
                <Grid size={{ xs: 12, md: 4 }}>
                  <TextField
                    fullWidth
                    label="Username"
                    value={form.create_username}
                    onChange={(e) => setForm({ ...form, create_username: e.target.value })}
                    slotProps={{
                      input: {
                        startAdornment: (
                          <InputAdornment position="start">
                            <User size={18} color="rgba(255,255,255,0.3)" />
                          </InputAdornment>
                        ),
                      }
                    }}
                  />
                </Grid>
                <Grid size={{ xs: 12, md: 4 }}>
                  <TextField
                    fullWidth
                    label="Password"
                    type="password"
                    value={form.create_password}
                    onChange={(e) => setForm({ ...form, create_password: e.target.value })}
                    slotProps={{
                      input: {
                        startAdornment: (
                          <InputAdornment position="start">
                            <Lock size={18} color="rgba(255,255,255,0.3)" />
                          </InputAdornment>
                        ),
                      }
                    }}
                  />
                </Grid>
                <Grid size={{ xs: 12, md: 4 }}>
                  <FormControl fullWidth>
                    <InputLabel sx={{ color: 'rgba(255,255,255,0.5)' }}>Role</InputLabel>
                    <Select
                      value={form.create_user_role}
                      label="Role"
                      onChange={(e) => setForm({ ...form, create_user_role: e.target.value })}
                      sx={{ color: '#fff', bgcolor: 'rgba(255,255,255,0.03)' }}
                    >
                      <MenuItem value="sys_admin">System Administrator</MenuItem>
                      <MenuItem value="penetration_tester">Penetration Tester</MenuItem>
                      <MenuItem value="auditor">Security Auditor</MenuItem>
                    </Select>
                  </FormControl>
                </Grid>
              </Grid>
            </Paper>

            {/* Mode Section */}
            <Paper sx={{
              p: 3,
              bgcolor: 'rgba(255,255,255,0.02)',
              border: '1px solid rgba(255,255,255,0.05)',
              position: 'relative',
              overflow: 'hidden',
              '&::before': {
                content: '""',
                position: 'absolute',
                top: 0,
                left: 0,
                width: '4px',
                height: '100%',
                bgcolor: '#ff00ff'
              }
            }}>
              <Typography sx={SECTION_TITLE_STYLE}>
                <Shield size={18} /> OPERATIONAL MODE
              </Typography>
              <Stack direction="row" sx={{ justifyContent: "space-between", alignItems: "center" }}>
                <Box>
                  <Typography variant="subtitle1" sx={{ color: '#fff', fontWeight: 600 }}>
                    BUG BOUNTY MODE
                  </Typography>
                  <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.4)', display: 'block' }}>
                    Enables HackerOne integration and specialized target importing.
                  </Typography>
                </Box>
                <FormControlLabel
                  control={
                    <Switch
                      checked={form.bug_bounty_mode}
                      onChange={(e) => setForm({ ...form, bug_bounty_mode: e.target.checked })}
                      sx={{
                        '& .MuiSwitch-switchBase.Mui-checked': { color: '#ff00ff' },
                        '& .MuiSwitch-switchBase.Mui-checked + .MuiSwitch-track': { bgcolor: '#ff00ff' }
                      }}
                    />
                  }
                  label=""
                />
              </Stack>
            </Paper>

            {/* API Vault Section */}
            <Paper sx={{
              p: 3,
              bgcolor: 'rgba(255,255,255,0.02)',
              border: '1px solid rgba(255,255,255,0.05)',
              position: 'relative',
              overflow: 'hidden',
              '&::before': {
                content: '""',
                position: 'absolute',
                top: 0,
                left: 0,
                width: '4px',
                height: '100%',
                bgcolor: '#00ff00'
              }
            }}>
              <Typography sx={SECTION_TITLE_STYLE}>
                <Key size={18} /> API VAULT SYNCHRONIZATION
              </Typography>
              <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.5)', mb: 3 }}>
                Configure external service keys to enhance reconnaissance and reporting.
              </Typography>
              
              <Grid container spacing={3}>
                <Grid size={{ xs: 12, md: 6 }}>
                  <TextField
                    fullWidth
                    label="OpenAI Key"
                    placeholder="sk-..."
                    value={form.key_openai}
                    onChange={(e) => setForm({ ...form, key_openai: e.target.value })}
                    helperText="Used for AI vulnerability descriptions and report writing."
                  />
                </Grid>
                <Grid size={{ xs: 12, md: 6 }}>
                  <TextField
                    fullWidth
                    label="Chaos Key"
                    value={form.key_chaos}
                    onChange={(e) => setForm({ ...form, key_chaos: e.target.value })}
                    helperText="Project Discovery Chaos dataset access."
                  />
                </Grid>
                <Grid size={{ xs: 12, md: 6 }}>
                  <TextField
                    fullWidth
                    label="HackerOne Username"
                    value={form.username_hackerone}
                    onChange={(e) => setForm({ ...form, username_hackerone: e.target.value })}
                  />
                </Grid>
                <Grid size={{ xs: 12, md: 6 }}>
                  <TextField
                    fullWidth
                    label="HackerOne API Token"
                    value={form.key_hackerone}
                    onChange={(e) => setForm({ ...form, key_hackerone: e.target.value })}
                  />
                </Grid>
                <Grid size={{ xs: 12, md: 6 }}>
                  <TextField
                    fullWidth
                    label="Shodan Key"
                    value={form.key_shodan}
                    onChange={(e) => setForm({ ...form, key_shodan: e.target.value })}
                  />
                </Grid>
                <Grid size={{ xs: 12, md: 6 }}>
                  <TextField
                    fullWidth
                    label="Censys Platform API Key"
                    type="password"
                    value={form.key_censys}
                    onChange={(e) => setForm({ ...form, key_censys: e.target.value })}
                    helperText="Required for origin discovery and enhanced reconnaissance."
                  />
                </Grid>
              </Grid>
            </Paper>

            {/* Actions */}
            <Box sx={{ display: 'flex', justifyContent: 'flex-end', pt: 2 }}>
              <Button
                type="submit"
                variant="contained"
                disabled={onboardingMutation.isPending}
                endIcon={onboardingMutation.isPending ? null : <ChevronRight size={20} />}
                sx={{
                  bgcolor: '#00f3ff',
                  color: '#000',
                  fontFamily: 'Orbitron',
                  fontWeight: 900,
                  px: 6,
                  py: 1.5,
                  fontSize: '1rem',
                  '&:hover': {
                    bgcolor: '#00d8e4',
                    boxShadow: '0 0 30px rgba(0, 243, 255, 0.4)'
                  }
                }}
              >
                {onboardingMutation.isPending ? 'SYNCHRONIZING...' : 'INITIALIZE SYSTEM'}
              </Button>
            </Box>
          </Stack>
        </form>

        {/* Footer info */}
        <Box sx={{ mt: 8, mb: 4, textAlign: 'center', opacity: 0.5 }}>
          <Typography variant="caption" sx={{ letterSpacing: 1, color: '#fff' }}>
            R3NGINE V3 // SECURE INITIALIZATION PROTOCOL ACTIVE
          </Typography>
        </Box>
      </Box>
    </Box>
  );
};
