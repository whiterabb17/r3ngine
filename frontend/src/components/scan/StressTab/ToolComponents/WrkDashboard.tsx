import React, { useMemo } from 'react';
import { Box, Grid } from '@mui/material';
import { Activity, AlertTriangle, HardDrive, TrendingUp } from 'lucide-react';
import { KpiCard } from '../../../KpiCard';
import { TacticalPanel } from '../../../TacticalPanel';
import { TimeSeriesChart, PercentileChart, DistributionChart } from '../SharedToolCharts';

export interface WrkTelemetryPoint {
  timestamp: number;
  throughput_rps?: number;
  avg_latency?: number;
  throughput_bps?: number;
  latency?: number;
  [key: string]: unknown;
}

export interface WrkDashboardProps {
  telemetry: WrkTelemetryPoint[];
  latencyStats?: { min: number; avg: number; max: number; stdev: number; p50?: number; p90?: number; p95?: number; p99?: number };
  socketErrors?: number;
  timeouts?: number;
}

export const WrkDashboard: React.FC<WrkDashboardProps> = ({
  telemetry = [],
  latencyStats = { min: 0, avg: 0, max: 0, stdev: 0 },
  socketErrors = 0,
  timeouts = 0,
}) => {
  // Ensure valid data types
  const validTelemetry = Array.isArray(telemetry) ? telemetry : [];
  const validLatencyStats = typeof latencyStats === 'object' && latencyStats !== null ? latencyStats : { min: 0, avg: 0, max: 0, stdev: 0 };
  const validSocketErrors = typeof socketErrors === 'number' ? socketErrors : 0;
  const validTimeouts = typeof timeouts === 'number' ? timeouts : 0;

  const latestMetrics = useMemo(() => {
    let currentRps = 0;
    let peakRps = 0;
    let errorRate = 0;

    if (validTelemetry.length > 0) {
      const latest = validTelemetry[validTelemetry.length - 1];
      currentRps = latest.throughput_rps || 0;
      peakRps = Math.max(...validTelemetry.map(t => t.throughput_rps || 0));
      errorRate = validSocketErrors + validTimeouts;
    }

    return {
      currentRps,
      peakRps,
      socketErrors: validSocketErrors,
      timeouts: validTimeouts,
      errorRate,
    };
  }, [validTelemetry, validSocketErrors, validTimeouts]);

  return (
    <Box sx={{ width: '100%' }}>
      {/* KPI Cards */}
      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <KpiCard
            title="CURRENT RPS"
            value={latestMetrics.currentRps.toFixed(1)}
            icon={Activity}
            color="#10b981"
            subtitle="Requests/second"
          />
        </Grid>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <KpiCard
            title="PEAK RPS"
            value={latestMetrics.peakRps.toFixed(1)}
            icon={TrendingUp}
            color="#3b82f6"
            subtitle="Requests/sec"
          />
        </Grid>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <KpiCard
            title="SOCKET ERRORS"
            value={latestMetrics.socketErrors.toString()}
            icon={AlertTriangle}
            color={latestMetrics.socketErrors > 0 ? '#ef4444' : '#10b981'}
            subtitle="Errors encountered"
          />
        </Grid>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <KpiCard
            title="TIMEOUTS"
            value={latestMetrics.timeouts.toString()}
            icon={Activity}
            color={latestMetrics.timeouts > 0 ? '#facc15' : '#10b981'}
            subtitle="Timeout count"
          />
        </Grid>
      </Grid>

      {/* Charts Grid */}
      <Grid container spacing={2}>
        {/* Latency Distribution */}
        <Grid size={{ xs: 12, md: 6 }}>
          <TacticalPanel title="LATENCY DISTRIBUTION" icon={<Activity size={18} />}>
            <PercentileChart
              percentiles={{
                p50: validLatencyStats.p50 || validLatencyStats.avg,
                p90: validLatencyStats.p90 || validLatencyStats.max,
                p95: validLatencyStats.p95 || validLatencyStats.max,
                p99: validLatencyStats.p99 || validLatencyStats.max,
                min: validLatencyStats.min,
                max: validLatencyStats.max,
              }}
              title="Latency Percentiles"
              unit="ms"
              height={300}
            />
          </TacticalPanel>
        </Grid>

        {/* Throughput Trend */}
        <Grid size={{ xs: 12, md: 6 }}>
          <TacticalPanel title="RPS TREND" icon={<TrendingUp size={18} />}>
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

        {/* Error Breakdown */}
        {(validSocketErrors > 0 || validTimeouts > 0) && (
          <Grid size={{ xs: 12 }}>
            <TacticalPanel title="ERROR TYPE BREAKDOWN" icon={<AlertTriangle size={18} />}>
              <DistributionChart
                data={{
                  'Socket Errors': validSocketErrors,
                  'Timeouts': validTimeouts,
                }}
                title="Error Distribution"
                type="bar"
                colorMap={{
                  'Socket Errors': '#ef4444',
                  'Timeouts': '#facc15',
                }}
                height={250}
              />
            </TacticalPanel>
          </Grid>
        )}
      </Grid>
    </Box>
  );
};
