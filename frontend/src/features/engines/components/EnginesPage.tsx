import React from 'react';
import { Box, Typography, Tabs, Tab, Grid, Card, Button } from '@mui/material';
import { EngineList } from './EngineList';
import { WordlistList } from './WordlistList';
import { useEngines, useWordlists } from '../api';
import { Cpu, List, Plus, FileUp, Sliders } from 'lucide-react';
import { EngineConfigModal } from './EngineConfigModal';
import { UploadWordlistModal } from './UploadWordlistModal';
import { ProfileManager } from '../../profiles/components/ProfileManager';
import { useThemeTokens } from '../../../theme/useThemeTokens';

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;

  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`engines-tabpanel-${index}`}
      {...other}
    >
      {value === index && (
        <Box sx={{ py: 3 }}>
          {children}
        </Box>
      )}
    </div>
  );
}

export const EnginesPage: React.FC = () => {
  const { tokens, isLight } = useThemeTokens();
  const [value, setValue] = React.useState(0);
  const [addEngineOpen, setAddEngineOpen] = React.useState(false);
  const [uploadWordlistOpen, setUploadWordlistOpen] = React.useState(false);
  
  const { data: engines } = useEngines();
  const { data: wordlists } = useWordlists();

  const handleChange = (event: React.SyntheticEvent, newValue: number) => {
    setValue(newValue);
  };

  return (
    <Box>
      <Grid container spacing={2} sx={{ mb: 4 }}>
        <Grid size={{ xs: 12, sm: 4 }}>
          <Card sx={{ bgcolor: 'rgba(112, 0, 255, 0.05)', border: '1px solid rgba(112, 0, 255, 0.2)', p: 2, borderRadius: 2 }}>
            <Typography variant="caption" sx={{ color: '#7000ff', fontWeight: 800, letterSpacing: 1 }}>TOTAL ENGINES</Typography>
            <Typography variant="h4" sx={{ color: isLight ? 'text.primary' : '#fff', fontFamily: 'Orbitron', fontWeight: 900 }}>{engines?.length || 0}</Typography>
          </Card>
        </Grid>
        <Grid size={{ xs: 12, sm: 4 }}>
          <Card sx={{ bgcolor: 'rgba(255, 0, 255, 0.05)', border: '1px solid rgba(255, 0, 255, 0.2)', p: 2, borderRadius: 2 }}>
            <Typography variant="caption" sx={{ color: '#ff00ff', fontWeight: 800, letterSpacing: 1 }}>WORDLIST COUNT</Typography>
            <Typography variant="h4" sx={{ color: isLight ? 'text.primary' : '#fff', fontFamily: 'Orbitron', fontWeight: 900 }}>{wordlists?.length || 0}</Typography>
          </Card>
        </Grid>
        <Grid size={{ xs: 12, sm: 4 }}>
          <Card sx={{ bgcolor: 'rgba(0, 243, 255, 0.05)', border: '1px solid rgba(0, 243, 255, 0.2)', p: 2, borderRadius: 2 }}>
            <Typography variant="caption" sx={{ color: '#00f3ff', fontWeight: 800, letterSpacing: 1 }}>DEFAULT ENGINE</Typography>
            <Typography variant="h6" sx={{ color: isLight ? 'text.primary' : '#fff', fontFamily: 'Orbitron', fontWeight: 800, mt: 1 }}>
              {engines?.find(e => e.default_engine)?.engine_name || 'NONE'}
            </Typography>
          </Card>
        </Grid>
      </Grid>

      <Box sx={{ 
        display: 'flex', 
        alignItems: 'center', 
        justifyContent: 'space-between',
        borderBottom: 1, 
        borderColor: isLight ? 'rgba(0,0,0,0.08)' : 'rgba(255, 255, 255, 0.1)',
        mb: 1
      }}>
        <Tabs 
          value={value} 
          onChange={handleChange}
          sx={{
            '& .MuiTabs-indicator': {
              bgcolor: value === 0 ? '#7000ff' : value === 1 ? '#ff00ff' : '#00ff62',
              height: 3,
              borderRadius: '3px 3px 0 0'
            },
            '& .MuiTab-root': {
              fontFamily: 'Orbitron',
              fontWeight: 700,
              fontSize: '0.8rem',
              color: isLight ? 'text.secondary' : 'rgba(255,255,255,0.4)',
              minHeight: 48,
              '&.Mui-selected': {
                color: value === 0 ? '#7000ff' : value === 1 ? '#ff00ff' : '#00ff62',
              }
            }
          }}
        >
          <Tab icon={<Cpu size={16} />} iconPosition="start" label="ENGINES" />
          <Tab icon={<List size={16} />} iconPosition="start" label="WORDLISTS" />
          <Tab icon={<Sliders size={16} />} iconPosition="start" label="SCAN PROFILES" />
        </Tabs>

        <Box sx={{ display: 'flex', gap: 2, pr: 2 }}>
          {value === 0 && (
            <Button
              variant="outlined"
              size="small"
              startIcon={<Plus size={16} />}
              onClick={() => setAddEngineOpen(true)}
              sx={{
                borderColor: 'rgba(112, 0, 255, 0.5)',
                color: isLight ? '#7000ff' : '#fff',
                fontFamily: 'Orbitron',
                fontWeight: 700,
                fontSize: '0.7rem',
                '&:hover': {
                  borderColor: '#7000ff',
                  bgcolor: 'rgba(112, 0, 255, 0.1)'
                }
              }}
            >
              ADD ENGINE
            </Button>
          )}
          {value === 1 && (
            <Button
              variant="outlined"
              size="small"
              startIcon={<FileUp size={16} />}
              onClick={() => setUploadWordlistOpen(true)}
              sx={{
                borderColor: 'rgba(255, 0, 255, 0.5)',
                color: isLight ? '#ff00ff' : '#fff',
                fontFamily: 'Orbitron',
                fontWeight: 700,
                fontSize: '0.7rem',
                '&:hover': {
                  borderColor: '#ff00ff',
                  bgcolor: 'rgba(255, 0, 255, 0.1)'
                }
              }}
            >
              UPLOAD WORDLIST
            </Button>
          )}
        </Box>
      </Box>
      
      <TabPanel value={value} index={0}>
        <EngineList />
      </TabPanel>
      <TabPanel value={value} index={1}>
        <WordlistList />
      </TabPanel>
      <TabPanel value={value} index={2}>
        <ProfileManager />
      </TabPanel>

      <EngineConfigModal
        mode="create"
        open={addEngineOpen}
        onClose={() => setAddEngineOpen(false)}
      />
      <UploadWordlistModal 
        open={uploadWordlistOpen} 
        onClose={() => setUploadWordlistOpen(false)} 
      />
    </Box>
  );
};
