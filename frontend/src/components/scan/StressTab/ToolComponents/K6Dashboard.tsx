import React, { useMemo } from 'react';
import { Box, Grid, useTheme } from '@mui/material';
import { Zap, AlertTriangle, BarChart3, CheckCircle } from 'lucide-react';
import { KpiCard } from '../../../KpiCard';
import { TacticalPanel } from '../../../TacticalPanel';
import { TimeSeriesChart, DistributionChart } from '../SharedToolCharts';

export interface K6TelemetryPoint {
  timestamp: number;
  throughput_rps?: number;
  avg_latency?: number;
  error_rate?: number;
  [key: string]: unknown;
}

export interface K6DashboardProps {
  telemetry: K6TelemetryPoint[];
  statusCodes?: { [code: string]: number };
  errors?: { [type: string]: number };
}

const K6_STATUS_CODE_COLORS: { [code: string]: string } = {
  '200': '#10b981',
  '301': '#3b82f6',
  '302': '#3b82f6',
  '304': '#06b6d4',
  '400': '#f59e0b',
  '401': '#f59e0b',
  '403': '#f59e0b',
  '404': '#facc15',
  '429': '#ef4444',
  '500': '#8b5cf6',
  '502': '#ec4899',
  '503': '#ef4444',
};

const K6_ERROR_COLORS: { [type: string]: string } = {
  'timeout': '#ef4444',
  'connection_refused': '#f59e0b',
  'connection_reset': '#facc15',
  'tls_error': '#8b5cf6',
  'http_error': '#ec4899',
};

export const K6Dashboard: React.FC<K6DashboardProps> = ({ telemetry = [], statusCodes = {}, errors = {} }) => {
  const theme = useTheme();

  // Ensure valid data types
  const validTelemetry = Array.isArray(telemetry) ? telemetry : [];
  const validStatusCodes = typeof statusCodes === 'object' && statusCodes !== null && !Array.isArray(statusCodes) ? statusCodes : {};
  const validErrors = typeof errors === 'object' && errors !== null && !Array.isArray(errors) ? errors : {};

  // Calculate latest metrics
  const latestMetrics = useMemo(() => {
    let peakRps = 0;
    let errorCount = 0;
    let statusCodeCount = 0;
    let checkPassCount = 0;

    if (validTelemetry.length > 0) {
      peakRps = Math.max(...validTelemetry.map(p => p.throughput_rps || 0));
    }

    errorCount = Object.values(validErrors).reduce((sum, count) => sum + (typeof count === 'number' ? count : 0), 0);
    statusCodeCount = Object.values(validStatusCodes).reduce((sum, count) => sum + (typeof count === 'number' ? count : 0), 0);
    checkPassCount = Object.values(validStatusCodes)
      .filter((_, idx) => {
        const code = Object.keys(validStatusCodes)[idx];
        return parseInt(code) >= 200 && parseInt(code) < 300;
      })
      .reduce((sum, count) => sum + (typeof count === 'number' ? count : 0), 0);

    return {
      peakRps,
      errorCount,
      statusCodeCount,
      checkPassRate: statusCodeCount > 0 ? Math.round((checkPassCount / statusCodeCount) * 100) : 0,
    };
  }, [validTelemetry, validStatusCodes, validErrors]);

  return (
    <Box sx={{ width: '100%' }}>
      {/* KPI Cards */}
      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <KpiCard
            title="PEAK RPS"
            value={latestMetrics.peakRps.toFixed(1)}
            icon={Zap}
            color="#10b981"
            subtitle="Requests/sec"
          />
        </Grid>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <KpiCard
            title="ERROR COUNT"
            value={latestMetrics.errorCount.toString()}
            icon={AlertTriangle}
            color={latestMetrics.errorCount > 0 ? '#ef4444' : '#10b981'}
            subtitle="Errors detected"
          />
        </Grid>
        {Object.keys(validStatusCodes).length > 0 && (
          <>
            <Grid size={{ xs: 12, sm: 6, md: 3 }}>
              <KpiCard
                title="STATUS CODES"
                value={latestMetrics.statusCodeCount.toString()}
                icon={BarChart3}
                color="#3b82f6"
                subtitle="Total responses"
              />
            </Grid>
            <Grid size={{ xs: 12, sm: 6, md: 3 }}>
              <KpiCard
                title="PASS RATE"
                value={`${latestMetrics.checkPassRate}%`}
                icon={CheckCircle}
                color={latestMetrics.checkPassRate >= 95 ? '#10b981' : '#facc15'}
                subtitle="2xx responses"
              />
            </Grid>
          </>
        )}
      </Grid>

      {/* Charts Grid */}
      <Grid container spacing={2}>
        {/* RPS Trend */}
        <Grid size={{ xs: 12, md: Object.keys(validStatusCodes).length > 0 ? 6 : 12 }}>
          <TacticalPanel
            title="RPS TREND"
            icon={<Zap size={18} />}
            headerAction={<span style={{ fontSize: '10px', opacity: 0.6 }}>Real-time</span>}
          >
            <TimeSeriesChart
              data={validTelemetry.map(t => ({
                timestamp: t.timestamp,
                rps: t.throughput_rps || 0,
              }))}
              series={[{ key: 'rps', name: 'RPS', color: '#10b981' }]}
              title="Requests Per Second"
              yAxisLabel="RPS"
              height={300}
            />
          </TacticalPanel>
        </Grid>

        {/* Status Codes */}
        {Object.keys(validStatusCodes).length > 0 && (
          <Grid size={{ xs: 12, md: 6 }}>
            <TacticalPanel title="STATUS CODE DISTRIBUTION" icon={<BarChart3 size={18} />}>
              <DistributionChart
                data={validStatusCodes}
                title="HTTP Status Codes"
                type="pie"
                colorMap={K6_STATUS_CODE_COLORS}
                height={300}
              />
            </TacticalPanel>
          </Grid>
        )}

        {/* Error Breakdown */}
        {Object.keys(validErrors).length > 0 && (
          <Grid size={{ xs: 12 }}>
            <TacticalPanel title="ERROR TYPE BREAKDOWN" icon={<AlertTriangle size={18} />}>
              <DistributionChart
                data={validErrors}
                title="Error Distribution"
                type="bar"
                colorMap={K6_ERROR_COLORS}
                height={250}
              />
            </TacticalPanel>
          </Grid>
        )}
      </Grid>
    </Box>
  );
};
