import React, { useMemo } from 'react';
import { Box, Grid, Typography, useTheme, alpha } from '@mui/material';
import { Zap, Network, AlertTriangle, BarChart3 } from 'lucide-react';
import { KpiCard } from '../../../KpiCard';
import { TacticalPanel } from '../../../TacticalPanel';
import { TimeSeriesChart, DistributionChart, PerformanceGauge } from '../SharedToolCharts';

export interface StressorTelemetryPoint {
  timestamp: number;
  pps?: number;
  bps?: number;
  rps?: number;
  [key: string]: unknown;
}

export interface StressorDashboardProps {
  telemetry: StressorTelemetryPoint[];
  attackMode?: 'layer4' | 'layer7' | 'unknown';
  ppsPeak?: number;
  bpsPeak?: number;
  rpsPeak?: number;
  statusCodes?: { [code: string]: number };
  responseRate?: number;
  blockRate?: number;
}

const STRESSOR_STATUS_COLORS: { [code: string]: string } = {
  '200': '#10b981',
  '301': '#3b82f6',
  '400': '#f59e0b',
  '500': '#8b5cf6',
};

export const StressorDashboard: React.FC<StressorDashboardProps> = ({
  telemetry = [],
  attackMode = 'unknown',
  ppsPeak = 0,
  bpsPeak = 0,
  rpsPeak = 0,
  statusCodes = {},
  responseRate = 0,
  blockRate = 0,
}) => {
  const theme = useTheme();

  // Ensure valid data types
  const validTelemetry = Array.isArray(telemetry) ? telemetry : [];
  const validAttackMode = typeof attackMode === 'string' ? attackMode : 'unknown';
  const validPpsPeak = typeof ppsPeak === 'number' ? ppsPeak : 0;
  const validBpsPeak = typeof bpsPeak === 'number' ? bpsPeak : 0;
  const validRpsPeak = typeof rpsPeak === 'number' ? rpsPeak : 0;
  const validStatusCodes = typeof statusCodes === 'object' && statusCodes !== null && !Array.isArray(statusCodes) ? statusCodes : {};
  const validResponseRate = typeof responseRate === 'number' ? responseRate : 0;
  const validBlockRate = typeof blockRate === 'number' ? blockRate : 0;

  const isLayer4 = validAttackMode === 'layer4';
  const isLayer7 = validAttackMode === 'layer7';

  const latestMetrics = useMemo(() => {
    let pps = validPpsPeak;
    let bps = validBpsPeak;
    let rps = validRpsPeak;

    if (validTelemetry.length > 0) {
      const latest = validTelemetry[validTelemetry.length - 1];
      if (latest.pps !== undefined) pps = Math.max(...validTelemetry.map(t => t.pps || 0));
      if (latest.bps !== undefined) bps = Math.max(...validTelemetry.map(t => t.bps || 0));
      if (latest.rps !== undefined) rps = Math.max(...validTelemetry.map(t => t.rps || 0));
    }

    return {
      ppsPeak: pps.toFixed(0),
      bpsPeak: (bps / (1024 * 1024)).toFixed(2),
      rpsPeak: rps.toFixed(1),
      responseRate: validResponseRate.toFixed(1),
      blockRate: validBlockRate.toFixed(1),
    };
  }, [validTelemetry, validPpsPeak, validBpsPeak, validRpsPeak, validResponseRate, validBlockRate]);

  return (
    <Box sx={{ width: '100%' }}>
      {/* Attack Mode Indicator */}
      {validAttackMode !== 'unknown' && (
        <Box
          sx={{
            mb: 3,
            p: 2,
            background: alpha(theme.palette.primary.main, 0.1),
            border: `1px solid ${alpha(theme.palette.primary.main, 0.3)}`,
            borderRadius: '8px',
          }}
        >
          <Typography
            sx={{
              fontFamily: 'Orbitron',
              fontSize: '12px',
              fontWeight: 700,
              letterSpacing: '2px',
              color: theme.palette.primary.main,
              textTransform: 'uppercase',
            }}
          >
            {isLayer4 ? '⚠️ Layer 4 Attack Mode (TCP/UDP/ICMP)' : isLayer7 ? '⚠️ Layer 7 Attack Mode (HTTP)' : '❓ Unknown Attack Mode'}
          </Typography>
        </Box>
      )}

      {/* KPI Cards */}
      <Grid container spacing={2} sx={{ mb: 3 }}>
        {isLayer4 ? (
          <>
            <Grid size={{ xs: 12, sm: 6, md: 3 }}>
              <KpiCard
                title="PPS PEAK"
                value={latestMetrics.ppsPeak}
                icon={Zap}
                color="#3b82f6"
                subtitle="Packets/sec"
              />
            </Grid>
            <Grid size={{ xs: 12, sm: 6, md: 3 }}>
              <KpiCard
                title="BPS PEAK"
                value={`${latestMetrics.bpsPeak} MB/s`}
                icon={Network}
                color="#10b981"
                subtitle="Bytes/sec"
              />
            </Grid>
          </>
        ) : (
          <>
            <Grid size={{ xs: 12, sm: 6, md: 3 }}>
              <KpiCard
                title="RPS PEAK"
                value={latestMetrics.rpsPeak}
                icon={Zap}
                color="#3b82f6"
                subtitle="Requests/sec"
              />
            </Grid>
            {Object.keys(validStatusCodes).length > 0 && (
              <Grid size={{ xs: 12, sm: 6, md: 3 }}>
                <KpiCard
                  title="STATUS CODES"
                  value={Object.values(validStatusCodes).reduce((sum, v) => sum + (typeof v === 'number' ? v : 0), 0).toString()}
                  icon={BarChart3}
                  color="#10b981"
                  subtitle="Total responses"
                />
              </Grid>
            )}
          </>
        )}

        {validResponseRate > 0 && (
          <Grid size={{ xs: 12, sm: 6, md: 3 }}>
            <KpiCard
              title="RESPONSE RATE"
              value={`${latestMetrics.responseRate}%`}
              icon={Zap}
              color="#10b981"
              subtitle="Successful rate"
            />
          </Grid>
        )}
        {validBlockRate > 0 && (
          <Grid size={{ xs: 12, sm: 6, md: 3 }}>
            <KpiCard
              title="BLOCK RATE"
              value={`${latestMetrics.blockRate}%`}
              icon={AlertTriangle}
              color={validBlockRate > 0 ? '#facc15' : '#10b981'}
              subtitle="Blocked rate"
            />
          </Grid>
        )}
      </Grid>

      {/* Charts Grid */}
      <Grid container spacing={2}>
        {isLayer4 ? (
          <>
            {/* PPS Trend */}
            <Grid size={{ xs: 12, md: 6 }}>
              <TacticalPanel title="PACKETS PER SECOND" icon={<Zap size={18} />}>
                <TimeSeriesChart
                  data={validTelemetry.map(t => ({
                    timestamp: t.timestamp,
                    pps: t.pps || 0,
                  }))}
                  series={[{ key: 'pps', name: 'PPS', color: '#3b82f6' }]}
                  title="Packet Rate Over Time"
                  yAxisLabel="PPS"
                  height={300}
                />
              </TacticalPanel>
            </Grid>

            {/* BPS Trend */}
            <Grid size={{ xs: 12, md: 6 }}>
              <TacticalPanel title="BITS PER SECOND" icon={<Network size={18} />}>
                <TimeSeriesChart
                  data={validTelemetry.map(t => ({
                    timestamp: t.timestamp,
                    bps: (t.bps || 0) / (1024 * 1024),
                  }))}
                  series={[{ key: 'bps', name: 'BPS (MB/s)', color: '#10b981' }]}
                  title="Throughput Over Time"
                  yAxisLabel="MB/s"
                  height={300}
                />
              </TacticalPanel>
            </Grid>
          </>
        ) : (
          <>
            {/* RPS Trend */}
            <Grid size={{ xs: 12, md: Object.keys(validStatusCodes).length > 0 ? 6 : 12 }}>
              <TacticalPanel title="REQUESTS PER SECOND" icon={<Zap size={18} />}>
                <TimeSeriesChart
                  data={validTelemetry.map(t => ({
                    timestamp: t.timestamp,
                    rps: t.rps || 0,
                  }))}
                  series={[{ key: 'rps', name: 'RPS', color: '#3b82f6' }]}
                  title="Request Rate Over Time"
                  yAxisLabel="RPS"
                  height={300}
                />
              </TacticalPanel>
            </Grid>

            {/* Status Codes */}
            {Object.keys(validStatusCodes).length > 0 && (
              <Grid size={{ xs: 12, md: 6 }}>
                <TacticalPanel title="HTTP STATUS CODES" icon={<BarChart3 size={18} />}>
                  <DistributionChart
                    data={validStatusCodes}
                    title="Status Code Distribution"
                    type="pie"
                    colorMap={STRESSOR_STATUS_COLORS}
                    height={300}
                  />
                </TacticalPanel>
              </Grid>
            )}
          </>
        )}

        {/* Response Rate Gauge */}
        {validResponseRate > 0 && (
          <Grid size={{ xs: 12, md: validBlockRate > 0 ? 6 : 12 }}>
            <TacticalPanel title="RESPONSE RATE" icon={<Zap size={18} />}>
              <PerformanceGauge
                value={validResponseRate}
                max={100}
                title="Success Rate"
                unit="%"
                colorRanges={[
                  { min: 80, max: 100, color: '#10b981' },
                  { min: 50, max: 80, color: '#f59e0b' },
                  { min: 0, max: 50, color: '#ef4444' },
                ]}
                size={250}
              />
            </TacticalPanel>
          </Grid>
        )}

        {/* Block Rate Gauge */}
        {validBlockRate > 0 && (
          <Grid size={{ xs: 12, md: validResponseRate > 0 ? 6 : 12 }}>
            <TacticalPanel title="BLOCK RATE" icon={<AlertTriangle size={18} />}>
              <PerformanceGauge
                value={validBlockRate}
                max={100}
                title="Block Rate"
                unit="%"
                colorRanges={[
                  { min: 0, max: 5, color: '#10b981' },
                  { min: 5, max: 20, color: '#facc15' },
                  { min: 20, max: 100, color: '#ef4444' },
                ]}
                size={250}
              />
            </TacticalPanel>
          </Grid>
        )}
      </Grid>
    </Box>
  );
};
