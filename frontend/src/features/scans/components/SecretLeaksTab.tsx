import React from 'react';
import {
  Box,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  Chip,
  CircularProgress,
  Stack,
  Tooltip,
  IconButton,
  TextField,
  Button,
  Grid,
  Card,
  CardContent
} from '@mui/material';
import { Shield, ExternalLink, Copy, AlertTriangle, Play, Mail, ShieldAlert } from 'lucide-react';
import { useSecretLeaks, useScanSummary, useEmailBreaches, useCheckEmailBreach } from '../api';
import { TacticalPanel } from '../../../components/TacticalPanel';
import { useThemeTokens } from '../../../theme/useThemeTokens';

interface SecretLeaksTabProps {
  projectSlug: string;
  scanId: number;
}

export const SecretLeaksTab: React.FC<SecretLeaksTabProps> = ({ projectSlug, scanId }) => {
  const { tokens } = useThemeTokens();
  const { data: leaks, isLoading } = useSecretLeaks(projectSlug, scanId);
  const { data: summary, refetch: refetchSummary } = useScanSummary(projectSlug, scanId);
  const { data: emailBreaches, refetch: refetchBreaches } = useEmailBreaches(scanId);
  const checkEmailMutation = useCheckEmailBreach();

  const [manualEmail, setManualEmail] = React.useState('');
  const [checkingEmails, setCheckingEmails] = React.useState<Record<string, boolean>>({});
  const [leaksPage, setLeaksPage] = React.useState(0);
  const [leaksRowsPerPage, setLeaksRowsPerPage] = React.useState(10);

  const emails = summary?.emails || [];

  const handleManualCheck = async (emailAddress: string) => {
    if (!emailAddress) return;
    setCheckingEmails(prev => ({ ...prev, [emailAddress]: true }));
    try {
      await checkEmailMutation.mutateAsync({ emailAddress, scanId });
      refetchSummary();
      refetchBreaches();
    } catch (err) {
      console.error("Failed to check breach:", err);
    } finally {
      setCheckingEmails(prev => ({ ...prev, [emailAddress]: false }));
    }
  };

  const handleAddAndScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!manualEmail.trim()) return;
    const targetEmail = manualEmail.trim();
    setManualEmail('');
    await handleManualCheck(targetEmail);
  };

  if (isLoading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', p: 8 }}>
        <CircularProgress sx={{ color: tokens.accent.primary }} />
      </Box>
    );
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'verified': return '#00ff62';
      case 'unverified': return '#ff9f00';
      case 'false_positive': return '#ff003c';
      default: return '#fff';
    }
  };

  return (
    <Box sx={{ width: '100%' }}>
      <Box sx={{ mb: 4, mt: 2 }}>
        <Typography variant="h5" sx={{ 
          fontWeight: 900, 
          fontFamily: 'Orbitron', 
          letterSpacing: 3, 
          color: 'text.primary',
          textTransform: 'uppercase'
        }}>
          Leaks & Secrets
        </Typography>
        <Typography sx={{ fontSize: '12px', color: 'text.secondary', mt: 0.5, letterSpacing: 1 }}>
          V3.0 CREDENTIAL INTELLIGENCE REPORT
        </Typography>
      </Box>

      <TacticalPanel title="SENSITIVE FINDINGS" icon={<Shield size={14} />}>
        <TableContainer>
          <Table size="small">
            <TableHead>
              <TableRow sx={{ '& th': { borderBottom: '2px solid #7000ff', bgcolor: 'action.hover', color: tokens.accent.primary, fontSize: '0.7rem', fontWeight: 900, py: 2 } }}>
                <TableCell sx={{ color: tokens.accent.primary, fontSize: '10px', fontWeight: 900, fontFamily: 'Orbitron' }}>TOOL</TableCell>
                <TableCell sx={{ color: tokens.accent.primary, fontSize: '10px', fontWeight: 900, fontFamily: 'Orbitron' }}>TYPE</TableCell>
                <TableCell sx={{ display: { xs: 'none', md: 'table-cell' }, color: tokens.accent.primary, fontSize: '10px', fontWeight: 900, fontFamily: 'Orbitron' }}>SOURCE</TableCell>
                <TableCell sx={{ color: tokens.accent.primary, fontSize: '10px', fontWeight: 900, fontFamily: 'Orbitron' }}>MATCH CONTENT</TableCell>
                <TableCell sx={{ display: { xs: 'none', sm: 'table-cell' }, color: tokens.accent.primary, fontSize: '10px', fontWeight: 900, fontFamily: 'Orbitron' }}>STATUS</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {leaks?.slice(leaksPage * leaksRowsPerPage, leaksPage * leaksRowsPerPage + leaksRowsPerPage).map((leak: any) => (
                <TableRow key={leak.id} sx={{ '& td': { borderBottom: 1, borderColor: 'divider', py: 2 } }}>
                  <TableCell>
                    <Chip 
                      label={leak.tool_name} 
                      size="small" 
                      sx={{ 
                        bgcolor: 'rgba(112,0,255,0.1)', 
                        color: '#7000ff', 
                        fontWeight: 800, 
                        fontSize: '0.65rem',
                        border: '1px solid rgba(112,0,255,0.2)'
                      }} 
                    />
                  </TableCell>
                  <TableCell>
                    <Typography sx={{ fontSize: '0.75rem', fontWeight: 700, color: 'text.primary' }}>
                      {leak.secret_type}
                    </Typography>
                  </TableCell>
                  <TableCell sx={{ display: { xs: 'none', md: 'table-cell' } }}>
                    <Stack direction="row" sx={{ alignItems: 'center' }} spacing={1}>
                      <Typography sx={{ fontSize: '0.7rem', color: 'text.secondary', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {leak.source_url}
                      </Typography>
                      <IconButton size="small" component="a" href={leak.source_url} target="_blank" sx={{ color: tokens.accent.primary, p: 0.5 }}>
                        <ExternalLink size={12} />
                      </IconButton>
                    </Stack>
                  </TableCell>
                  <TableCell>
                    <Box sx={{ 
                       p: 1, 
                       bgcolor: 'rgba(0,0,0,0.3)', 
                       border: 1, borderColor: 'divider', 
                       borderRadius: 0.5,
                       display: 'flex',
                       alignItems: 'center',
                       justifyContent: 'space-between',
                       maxWidth: { xs: '150px', sm: '300px' }
                    }}>
                      <Typography sx={{ 
                        fontSize: '0.7rem', 
                        fontFamily: 'monospace', 
                        color: '#00ff62',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap'
                      }}>
                        {leak.match_content}
                      </Typography>
                      <IconButton size="small" sx={{ color: 'text.disabled', p: 0.2 }}>
                        <Copy size={12} />
                      </IconButton>
                    </Box>
                  </TableCell>
                  <TableCell sx={{ display: { xs: 'none', sm: 'table-cell' } }}>
                    <Box sx={{ 
                      display: 'inline-flex',
                      px: 1,
                      py: 0.2,
                      borderRadius: 0.5,
                      bgcolor: `${getStatusColor(leak.status)}10`,
                      border: `1px solid ${getStatusColor(leak.status)}30`,
                      color: getStatusColor(leak.status),
                      fontSize: '0.65rem',
                      fontWeight: 900,
                      textTransform: 'uppercase'
                    }}>
                      {leak.status}
                    </Box>
                  </TableCell>
                </TableRow>
              ))}
              {(!leaks || leaks.length === 0) && (
                <TableRow>
                  <TableCell colSpan={5} align="center" sx={{ py: 8 }}>
                    <Box sx={{ opacity: 0.3 }}>
                      <AlertTriangle size={32} style={{ marginBottom: '8px' }} />
                      <Typography sx={{ fontSize: '0.8rem', fontWeight: 700 }}>NO SECRETS OR LEAKS DETECTED</Typography>
                    </Box>
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </TableContainer>
        {leaks && leaks.length > 0 && (
          <TablePagination
            component="div"
            count={leaks.length}
            page={leaksPage}
            rowsPerPage={leaksRowsPerPage}
            rowsPerPageOptions={[10, 25, 50]}
            onPageChange={(_e, newPage) => setLeaksPage(newPage)}
            onRowsPerPageChange={(e) => {
              setLeaksRowsPerPage(parseInt(e.target.value, 10));
              setLeaksPage(0);
            }}
            sx={{
              borderTop: '1px solid',
              borderColor: 'divider',
              color: 'text.secondary',
              fontSize: '0.7rem',
              '& .MuiTablePagination-selectLabel, & .MuiTablePagination-displayedRows': {
                fontSize: '0.7rem',
              },
              '& .MuiTablePagination-select': {
                fontSize: '0.7rem',
              },
            }}
          />
        )}
      </TacticalPanel>

      <Box sx={{ mt: 4 }}>
        <Grid container spacing={3}>
          <Grid size={{ xs: 12, md: 4 }}>
            <TacticalPanel title="MANUAL EMAIL AUDIT" icon={<Mail size={14} />}>
              <Box component="form" onSubmit={handleAddAndScan} sx={{ p: 2, display: 'flex', flexDirection: 'column', gap: 2 }}>
                <Typography variant="caption" sx={{ color: 'text.secondary' }}>
                  Audit individual email addresses for third-party security breaches.
                </Typography>
                <TextField
                  fullWidth
                  size="small"
                  label="Email Address"
                  placeholder="e.g. user@target.com"
                  value={manualEmail}
                  onChange={(e) => setManualEmail(e.target.value)}
                  sx={{
                    '& .MuiInputBase-input': { fontSize: '0.8rem', fontFamily: 'monospace' },
                    '& .MuiInputLabel-root': { fontSize: '0.8rem' }
                  }}
                />
                <Button
                  fullWidth
                  type="submit"
                  variant="contained"
                  disabled={checkEmailMutation.isPending}
                  sx={{
                    bgcolor: tokens.accent.primary,
                    color: '#fff',
                    fontWeight: 800,
                    fontFamily: 'Orbitron',
                    fontSize: '0.75rem',
                    '&:hover': {
                      bgcolor: 'rgba(112,0,255,0.8)',
                    }
                  }}
                >
                  {checkEmailMutation.isPending ? 'CHECKING...' : 'ADD & CHECK'}
                </Button>
              </Box>
            </TacticalPanel>
          </Grid>

          <Grid size={{ xs: 12, md: 8 }}>
            <TacticalPanel title="EMAIL BREACH COVERAGE" icon={<ShieldAlert size={14} />}>
              <TableContainer sx={{ maxHeight: '280px' }}>
                <Table size="small" stickyHeader>
                  <TableHead>
                    <TableRow sx={{ '& th': { borderBottom: '2px solid #7000ff', bgcolor: 'action.hover', color: tokens.accent.primary, fontSize: '0.7rem', fontWeight: 900, py: 1 } }}>
                      <TableCell sx={{ color: tokens.accent.primary, fontSize: '10px', fontWeight: 900, fontFamily: 'Orbitron' }}>EMAIL ADDRESS</TableCell>
                      <TableCell sx={{ color: tokens.accent.primary, fontSize: '10px', fontWeight: 900, fontFamily: 'Orbitron' }}>STATUS</TableCell>
                      <TableCell align="right" sx={{ color: tokens.accent.primary, fontSize: '10px', fontWeight: 900, fontFamily: 'Orbitron' }}>ACTIONS</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {emails?.map((email: any) => {
                      const matchedBreaches = emailBreaches?.filter((b: any) => b.email_address === email.address) || [];
                      const isChecking = checkingEmails[email.address];

                      return (
                        <TableRow key={email.id} sx={{ '& td': { py: 1 } }}>
                          <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.75rem', fontWeight: 700 }}>
                            {email.address}
                          </TableCell>
                          <TableCell>
                            {isChecking ? (
                              <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }}>
                                <CircularProgress size={10} sx={{ color: tokens.accent.primary }} />
                                <Typography sx={{ fontSize: '0.65rem', color: 'text.secondary' }}>CHECKING HIBP...</Typography>
                              </Stack>
                            ) : matchedBreaches.length > 0 ? (
                              <Chip
                                label={`${matchedBreaches.length} BREACHES`}
                                size="small"
                                sx={{
                                  bgcolor: 'rgba(255,0,60,0.1)',
                                  color: '#ff003c',
                                  fontWeight: 900,
                                  fontSize: '0.6rem',
                                  border: '1px solid rgba(255,0,60,0.2)'
                                }}
                              />
                            ) : (
                              <Chip
                                label="CLEAN"
                                size="small"
                                sx={{
                                  bgcolor: 'rgba(0,255,98,0.1)',
                                  color: '#00ff62',
                                  fontWeight: 900,
                                  fontSize: '0.6rem',
                                  border: '1px solid rgba(0,255,98,0.2)'
                                }}
                              />
                            )}
                          </TableCell>
                          <TableCell align="right">
                            <Tooltip title="Run HIBP Audit">
                              <IconButton
                                size="small"
                                disabled={isChecking}
                                onClick={() => handleManualCheck(email.address)}
                                sx={{ color: tokens.accent.primary }}
                              >
                                <Play size={12} />
                              </IconButton>
                            </Tooltip>
                          </TableCell>
                        </TableRow>
                      );
                    })}
                    {(!emails || emails.length === 0) && (
                      <TableRow>
                        <TableCell colSpan={3} align="center" sx={{ py: 4 }}>
                          <Typography sx={{ fontSize: '0.7rem', color: 'text.secondary' }}>
                            NO EMAIL ADDRESSES ASSOCIATED WITH THIS SCAN
                          </Typography>
                        </TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </TableContainer>
            </TacticalPanel>
          </Grid>
        </Grid>
      </Box>

      {emailBreaches && emailBreaches.length > 0 && (
        <Box sx={{ mt: 4 }}>
          <Box sx={{ mb: 2 }}>
            <Typography variant="h6" sx={{ 
              fontWeight: 800, 
              fontFamily: 'Orbitron', 
              letterSpacing: 2, 
              color: 'text.primary',
              fontSize: '1rem'
            }}>
              IDENTIFIED THIRD-PARTY BREACHES
            </Typography>
            <Typography sx={{ fontSize: '10px', color: 'text.secondary' }}>
              SOURCE: HAVEIBEENPWNED DATABASE AUDIT
            </Typography>
          </Box>

          <Grid container spacing={2}>
            {emailBreaches.map((breach: any) => (
              <Grid size={{ xs: 12, sm: 6 }} key={breach.id}>
                <Card sx={{ 
                  bgcolor: 'background.paper',
                  border: `1px solid ${tokens.border.subtle}`,
                  borderRadius: 1,
                  position: 'relative',
                  '&:hover': {
                    borderColor: tokens.border.strong,
                    boxShadow: 2
                  }
                }}>
                  <CardContent sx={{ p: 2.5, '&:last-child': { pb: 2.5 } }}>
                    <Stack direction="row" sx={{ justifyContent: 'space-between', alignItems: 'flex-start', mb: 1.5 }}>
                      <Box>
                        <Typography variant="subtitle2" sx={{ fontWeight: 800, color: tokens.accent.primary }}>
                          {breach.breach_name}
                        </Typography>
                        <Typography sx={{ fontSize: '0.65rem', fontFamily: 'monospace', color: 'text.secondary' }}>
                          Target: {breach.email_address}
                        </Typography>
                      </Box>
                      <Chip
                        label={breach.breach_date || 'Unknown Date'}
                        size="small"
                        sx={{
                          bgcolor: 'action.hover',
                          color: 'text.primary',
                          fontSize: '0.65rem',
                          fontWeight: 700
                        }}
                      />
                    </Stack>

                    <Typography sx={{ fontSize: '0.75rem', color: 'text.secondary', mb: 2, lineHeight: 1.4 }}>
                      {breach.description}
                    </Typography>

                    <Box sx={{ mb: 2 }}>
                      <Typography sx={{ fontSize: '10px', fontWeight: 800, color: 'text.primary', mb: 0.5, letterSpacing: 0.5 }}>
                        COMPROMISED DATA:
                      </Typography>
                      <Stack direction="row" sx={{ flexWrap: 'wrap', gap: 0.5 }}>
                        {breach.compromised_data?.map((dataClass: string) => (
                          <Chip
                            key={dataClass}
                            label={dataClass}
                            size="small"
                            sx={{
                              bgcolor: 'rgba(112,0,255,0.05)',
                              color: 'text.primary',
                              fontSize: '0.6rem',
                              fontWeight: 600,
                              height: '18px',
                              borderRadius: 0.5
                            }}
                          />
                        ))}
                      </Stack>
                    </Box>

                    <Button
                      size="small"
                      variant="outlined"
                      component="a"
                      href={`https://haveibeenpwned.com/Breach/${encodeURIComponent(breach.breach_name)}`}
                      target="_blank"
                      endIcon={<ExternalLink size={10} />}
                      sx={{
                        fontSize: '0.65rem',
                        fontWeight: 900,
                        fontFamily: 'Orbitron',
                        color: tokens.accent.primary,
                        borderColor: 'rgba(112,0,255,0.3)',
                        '&:hover': {
                          borderColor: tokens.accent.primary,
                          bgcolor: 'rgba(112,0,255,0.05)'
                        }
                      }}
                    >
                      View Details
                    </Button>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Box>
      )}
    </Box>
  );
};
