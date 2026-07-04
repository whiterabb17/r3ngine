import React, { useState } from 'react';
import Avatar from '@mui/material/Avatar';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Card from '@mui/material/Card';
import CardContent from '@mui/material/CardContent';
import Grid from '@mui/material/Grid';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import Typography from '@mui/material/Typography';
import { Users, User, ExternalLink, Search, ChevronDown } from 'lucide-react';
import { TacticalPanel } from '../../../../components/TacticalPanel';
import { useEmployees } from '../../api';
import { useEmployeeIntelStore } from '../../../../store/employeeIntelStore';
import { EmployeeIntelModal } from './EmployeeIntelModal';

interface EmployeeSectionProps {
  scanId: number;
}

export const EmployeeSection: React.FC<EmployeeSectionProps> = ({ scanId }) => {
  const { data: employees = [], refetch: refetchEmployees } = useEmployees(scanId);
  const [actionsAnchor, setActionsAnchor] = useState<HTMLElement | null>(null);
  const [intelOpen, setIntelOpen] = useState(false);
  const running = useEmployeeIntelStore((s) => s.running);

  const actionsMenu = (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
      <Button
        size="small"
        variant="outlined"
        endIcon={<ChevronDown size={14} />}
        onClick={(e) => setActionsAnchor(e.currentTarget)}
        sx={{ fontSize: '0.7rem', letterSpacing: '0.08em' }}
      >
        {running ? 'GATHERING...' : 'ACTIONS'}
      </Button>
      <Menu
        anchorEl={actionsAnchor}
        open={Boolean(actionsAnchor)}
        onClose={() => setActionsAnchor(null)}
      >
        <MenuItem
          onClick={() => { setActionsAnchor(null); setIntelOpen(true); }}
          disabled={running}
        >
          <ListItemIcon><Search size={16} /></ListItemIcon>
          Gather Employee Intelligence
        </MenuItem>
      </Menu>
    </Box>
  );

  return (
    <>
      <TacticalPanel
        title="DISCOVERED EMPLOYEES & USERNAMES"
        icon={<Users size={18} />}
        headerAction={actionsMenu}
      >
        {employees.length === 0 ? (
          <Typography variant="body2" sx={{ color: 'text.secondary', p: 2 }}>
            No employees discovered yet. Use Actions to gather employee intelligence.
          </Typography>
        ) : (
          <Grid container spacing={2}>
            {employees.map((employee) => (
              <Grid size={{ xs: 12, sm: 6, md: 4 }} key={employee.id}>
                <Card sx={{
                  background: 'rgba(255, 255, 255, 0.03)',
                  border: '1px solid rgba(255, 255, 255, 0.1)',
                  borderRadius: 0,
                  height: '100%',
                  '&:hover': {
                    borderColor: 'primary.main',
                    background: 'rgba(255, 255, 255, 0.05)',
                  },
                }}>
                  <CardContent sx={{ display: 'flex', flexDirection: 'column', gap: 2, '&:last-child': { pb: 2 } }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                      <Avatar sx={{ bgcolor: 'primary.dark', borderRadius: 0 }}>
                        <User size={20} />
                      </Avatar>
                      <Box>
                        <Typography variant="subtitle2" sx={{ fontWeight: 'bold' }}>
                          {employee.name ?? 'Unknown'}
                        </Typography>
                        <Typography variant="caption" sx={{ color: 'text.secondary' }}>
                          {employee.designation ?? 'Position unknown'}
                        </Typography>
                      </Box>
                    </Box>

                    {employee.metadata?.maigret && employee.metadata.maigret.length > 0 && (
                      <Box sx={{ mt: 1 }}>
                        <Typography variant="caption" sx={{ color: 'primary.light', fontWeight: 'bold', mb: 1, display: 'block' }}>
                          SOCIAL PROFILES
                        </Typography>
                        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                          {employee.metadata.maigret.map((profile, idx) => {
                            const safeSrc = /^https?:\/\//i.test(profile.url) ? profile.url : '#';
                            return (
                              <Box
                                key={idx}
                                component="a"
                                href={safeSrc}
                                target="_blank"
                                rel="noopener noreferrer"
                                sx={{
                                  display: 'flex',
                                  alignItems: 'center',
                                  gap: 0.5,
                                  fontSize: '10px',
                                  px: 1,
                                  py: 0.5,
                                  background: 'rgba(33, 150, 243, 0.1)',
                                  color: 'info.light',
                                  border: '1px solid rgba(33, 150, 243, 0.3)',
                                  textDecoration: 'none',
                                  '&:hover': {
                                    background: 'rgba(33, 150, 243, 0.2)',
                                    borderColor: 'info.main',
                                  },
                                }}
                              >
                                {profile.site}
                                <ExternalLink size={10} />
                              </Box>
                            );
                          })}
                        </Box>
                      </Box>
                    )}
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        )}
      </TacticalPanel>

      <EmployeeIntelModal
        open={intelOpen}
        onClose={() => setIntelOpen(false)}
        scanId={scanId}
        onComplete={refetchEmployees}
      />
    </>
  );
};
