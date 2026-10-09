import React, { useMemo } from 'react';
import { Box, Grid } from '@mui/material';
import { Users, TrendingUp, AlertTriangle, Gauge } from 'lucide-react';
import { KpiCard } from '../../../KpiCard';
import { TacticalPanel } from '../../../TacticalPanel';
import { TimeSeriesChart, PercentileChart } from '../SharedToolCharts';

export interface LocustTelemetryPoint {
  timestamp: number;
  total_users?: number;
  avg_latency?: number;
  error_rate?: number;
  [key: string]: unknown;
}

export interface LocustDashboardProps {
  telemetry: LocustTelemetryPoint[];
  totalUsers?: number;
  avgResponseTime?: number;
  failureRate?: number;
  endpointCount?: number;
  percentiles?: { p50: number; p90: number; p95: number; p99: number };
}

export const LocustDashboard: React.FC<LocustDashboardProps> = ({
  telemetry = [],
  totalUsers = 0,
  avgResponseTime = 0,
  failureRate = 0,
  endpointCount = 0,
  percentiles = { p50: 0, p90: 0, p95: 0, p99: 0 },
}) => {
  // Ensure valid data types
  const validTelemetry = Array.isArray(telemetry) ? telemetry : [];
  const validTotalUsers = typeof totalUsers === 'number' ? totalUsers : 0;
  const validAvgResponseTime = typeof avgResponseTime === 'number' ? avgResponseTime : 0;
  const validFailureRate = typeof failureRate === 'number' ? failureRate : 0;
  const validEndpointCount = typeof endpointCount === 'number' ? endpointCount : 0;
  const validPercentiles = typeof percentiles === 'object' && percentiles !== null ? percentiles : { p50: 0, p90: 0, p95: 0, p99: 0 };

  const latestMetrics = useMemo(() => {
    let currentUsers = validTotalUsers;
    let errorRate = validFailureRate;

    if (validTelemetry.length > 0) {
      const latest = validTelemetry[validTelemetry.length - 1];
      currentUsers = latest.total_users || validTotalUsers;
      errorRate = latest.error_rate !== undefined ? latest.error_rate * 100 : validFailureRate;
    }

    return {
      currentUsers,
      avgResponseTime: validAvgResponseTime.toFixed(2),
      failureRate: errorRate.toFixed(2),
      endpointCount: validEndpointCount,
    };
  }, [validTelemetry, validTotalUsers, validAvgResponseTime, validFailureRate, validEndpointCount]);

  return (
    <Box sx={{ width: '100%' }}>
      {/* KPI Cards */}
      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <KpiCard
            title="CURRENT USERS"
            value={latestMetrics.currentUsers.toString()}
            icon={Users}
            color="#3b82f6"
            subtitle="Concurrent users"
          />
        </Grid>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <KpiCard
            title="AVG RESPONSE"
            value={`${latestMetrics.avgResponseTime}ms`}
            icon={TrendingUp}
            color="#10b981"
            subtitle="Response time"
          />
        </Grid>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <KpiCard
            title="FAILURE RATE"
            value={`${latestMetrics.failureRate}%`}
            icon={AlertTriangle}
            color={parseFloat(latestMetrics.failureRate) > 5 ? '#ef4444' : '#10b981'}
            subtitle="Failure percentage"
          />
        </Grid>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <KpiCard
            title="ENDPOINTS"
            value={latestMetrics.endpointCount.toString()}
            icon={Gauge}
            color="#f59e0b"
            subtitle="Endpoints tested"
          />
        </Grid>
      </Grid>

      {/* Charts Grid */}
      <Grid container spacing={2}>
        {/* User Ramp-up Progress */}
        <Grid size={{ xs: 12, md: 6 }}>
          <TacticalPanel title="USER RAMP-UP PROGRESS" icon={<Users size={18} />}>
            <TimeSeriesChart
              data={validTelemetry.map(t => ({
                timestamp: t.timestamp,
                users: t.total_users || 0,
              }))}
              series={[{ key: 'users', name: 'Concurrent Users', color: '#3b82f6' }]}
              title="User Ramp-Up Over Time"
              yAxisLabel="Users"
              height={300}
            />
          </TacticalPanel>
        </Grid>

        {/* Response Time Percentiles */}
        <Grid size={{ xs: 12, md: 6 }}>
          <TacticalPanel title="RESPONSE TIME PERCENTILES" icon={<TrendingUp size={18} />}>
            <PercentileChart
              percentiles={{
                p50: validPercentiles.p50,
                p90: validPercentiles.p90,
                p95: validPercentiles.p95,
                p99: validPercentiles.p99,
              }}
              title="Response Time Distribution"
              unit="ms"
              height={300}
            />
          </TacticalPanel>
        </Grid>

        {/* Error Rate Over Time */}
        <Grid size={{ xs: 12 }}>
          <TacticalPanel title="FAILURE RATE PROGRESSION" icon={<AlertTriangle size={18} />}>
            <TimeSeriesChart
              data={validTelemetry.map(t => ({
                timestamp: t.timestamp,
                errorRate: ((t.error_rate || 0) * 100),
                users: t.total_users || 0,
              }))}
              series={[
                { key: 'errorRate', name: 'Failure Rate %', color: '#ef4444' },
                { key: 'users', name: 'User Count', color: '#3b82f6' },
              ]}
              title="Error Rate vs User Ramp-Up"
              yAxisLabel="Rate / Count"
              height={250}
            />
          </TacticalPanel>
        </Grid>
      </Grid>
    </Box>
  );
};
