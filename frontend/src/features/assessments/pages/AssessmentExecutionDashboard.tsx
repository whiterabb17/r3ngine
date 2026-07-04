import React, { useState } from 'react';
import { useParams } from 'react-router-dom';
import { Box, Typography, Grid, Paper, Tabs, Tab, Chip } from '@mui/material';
import { Activity, Shield, BarChart2 } from 'lucide-react';
import { useAssessments } from '../api';
import { useAssessmentStream } from '../hooks/useAssessmentStream';
import { AssessmentControlPanel } from '../components/AssessmentControlPanel';
import { AssessmentStatusTimeline } from '../components/AssessmentStatusTimeline';
import { EvidencePage } from '../../evidence';

// -------------------------------------------------------------------------
// Tab definitions
// -------------------------------------------------------------------------
const TABS = [
  { value: 'execution', label: 'Execution', icon: <Activity size={14} /> },
  { value: 'evidence',  label: 'Evidence',  icon: <Shield size={14} /> },
  { value: 'metrics',   label: 'Metrics',   icon: <BarChart2 size={14} /> },
];

export const AssessmentExecutionDashboard: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [activeTab, setActiveTab] = useState<'execution' | 'evidence' | 'metrics'>('execution');

  // Use existing query to get initial status, fallback to finding by ID
  const { data: assessments, isLoading } = useAssessments();
  const assessment = assessments?.find(a => a.uuid === id);

  // Connect WebSocket
  const { events, isConnected } = useAssessmentStream(id || '');

  // The latest state from WebSockets takes precedence, otherwise fallback to DB state
  const latestEvent = events.length > 0 ? events[events.length - 1] : null;
  const currentStatus = latestEvent?.data?.status || assessment?.status || 'Draft';
  const progress = latestEvent?.data?.progress || 0;

  if (isLoading) return <Typography>Loading...</Typography>;
  if (!assessment) return <Typography>Assessment not found</Typography>;

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
        <Box>
          <Typography
            variant="h5"
            sx={{ fontFamily: 'Orbitron', fontWeight: 700, color: '#fff', letterSpacing: 1 }}
          >
            {assessment.name}
          </Typography>
          <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.4)', fontFamily: 'monospace' }}>
            Assessment ID: {assessment.uuid}
          </Typography>
        </Box>
        <Chip
          label={isConnected ? '● LIVE' : '○ OFFLINE'}
          size="small"
          sx={{
            bgcolor: isConnected ? 'rgba(0,230,118,0.12)' : 'rgba(255,71,87,0.12)',
            color: isConnected ? '#00e676' : '#ff4757',
            fontFamily: 'Orbitron',
            fontSize: '0.6rem',
            letterSpacing: 1,
            border: `1px solid ${isConnected ? 'rgba(0,230,118,0.3)' : 'rgba(255,71,87,0.3)'}`,
          }}
        />
      </Box>

      {/* Tabs */}
      <Tabs
        value={activeTab}
        onChange={(_, v) => setActiveTab(v)}
        slotProps={{ indicator: { sx: { bgcolor: '#00f3ff' } } }}
        sx={{ borderBottom: '1px solid rgba(255,255,255,0.06)', mb: 3, minHeight: 36 }}
      >
        {TABS.map(t => (
          <Tab
            key={t.value}
            value={t.value}
            label={
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75 }}>
                {t.icon}
                <span style={{ fontSize: '0.72rem', fontFamily: 'Orbitron', letterSpacing: 1 }}>
                  {t.label.toUpperCase()}
                </span>
              </Box>
            }
            sx={{ minHeight: 36, py: 0, color: 'rgba(255,255,255,0.4)', '&.Mui-selected': { color: '#00f3ff' } }}
          />
        ))}
      </Tabs>

      {/* Tab content */}
      {activeTab === 'execution' && (
        <Grid container spacing={3}>
          <Grid size={{ xs: 12, md: 4 }}>
            <Paper sx={{ p: 0, height: '100%' }} elevation={2}>
              <AssessmentControlPanel assessmentId={assessment.uuid} status={currentStatus} />
            </Paper>
          </Grid>

          <Grid size={{ xs: 12, md: 8 }}>
            <Paper sx={{ p: 0, height: '100%' }} elevation={2}>
              <AssessmentStatusTimeline
                currentStage={currentStatus}
                progress={progress}
                events={events}
              />
            </Paper>
          </Grid>
        </Grid>
      )}

      {activeTab === 'evidence' && (
        <Paper
          elevation={0}
          sx={{
            p: 2,
            bgcolor: 'rgba(0,0,0,0.2)',
            border: '1px solid rgba(255,255,255,0.06)',
            borderRadius: 2,
          }}
        >
          <EvidencePage assessmentUuid={assessment.uuid} />
        </Paper>
      )}

      {activeTab === 'metrics' && (
        <Paper sx={{ p: 2 }} elevation={2}>
          <Typography variant="h6" sx={{ fontFamily: 'Orbitron', fontSize: '0.85rem', color: '#00f3ff', mb: 1 }}>
            ASSESSMENT METRICS
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Findings and vulnerability trends will appear here as the assessment progresses.
          </Typography>
        </Paper>
      )}
    </Box>
  );
};
