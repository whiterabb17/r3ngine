import React, { useMemo } from 'react';
import { Box, Grid } from '@mui/material';
import { Activity, AlertTriangle, Gauge, Network } from 'lucide-react';
import { KpiCard } from '../../../KpiCard';
import { TacticalPanel } from '../../../TacticalPanel';
import { TimeSeriesChart, PerformanceGauge } from '../SharedToolCharts';

export interface Hping3TelemetryPoint {
  timestamp: number;
  [key: string]: unknown;
}

export interface Hping3DashboardProps {
  telemetry: Hping3TelemetryPoint[];
  packetsSent?: number;
  packetsReceived?: number;
  rttMin?: number;
  rttAvg?: number;
  rttMax?: number;
  protocol?: string;
}

export const Hping3Dashboard: React.FC<Hping3DashboardProps> = ({
  telemetry = [],
  packetsSent = 0,
  packetsReceived = 0,
  rttMin = 0,
  rttAvg = 0,
  rttMax = 100,
  protocol = 'ICMP',
}) => {
  // Ensure valid data types
  const validTelemetry = Array.isArray(telemetry) ? telemetry : [];
  const validPacketsSent = typeof packetsSent === 'number' ? packetsSent : 0;
  const validPacketsReceived = typeof packetsReceived === 'number' ? packetsReceived : 0;
  const validRttMin = typeof rttMin === 'number' ? rttMin : 0;
  const validRttAvg = typeof rttAvg === 'number' ? rttAvg : 0;
  const validRttMax = typeof rttMax === 'number' ? rttMax : 100;
  const validProtocol = typeof protocol === 'string' ? protocol : 'ICMP';

  const metrics = useMemo(() => {
    const packetLoss = validPacketsSent > 0
      ? ((validPacketsSent - validPacketsReceived) / validPacketsSent) * 100
      : 0;

    return {
      packetLoss: Math.min(100, Math.max(0, packetLoss)),
      packetsSent: validPacketsSent,
      packetsReceived: validPacketsReceived,
      rttMin: validRttMin,
      rttAvg: validRttAvg,
      rttMax: validRttMax,
      received: validPacketsReceived,
    };
  }, [validPacketsSent, validPacketsReceived, validRttMin, validRttAvg, validRttMax]);

  const rttTrendData = useMemo(() => {
    let currentMin = Infinity;
    let currentMax = -Infinity;
    let sum = 0;

    return validTelemetry.map((t, idx) => {
      const lat = typeof t.latency === 'number'
        ? t.latency
        : (typeof t.avg_latency === 'number' ? t.avg_latency : 0);

      if (lat < currentMin) currentMin = lat;
      if (lat > currentMax) currentMax = lat;
      sum += lat;
      const runningAvg = sum / (idx + 1);

      return {
        timestamp: t.timestamp,
        min: currentMin === Infinity ? 0 : currentMin,
        avg: runningAvg,
        max: currentMax === -Infinity ? 0 : currentMax,
      };
    });
  }, [validTelemetry]);

  const packetLossColor = metrics.packetLoss < 1 ? '#10b981' : metrics.packetLoss < 5 ? '#facc15' : '#ef4444';

  return (
    <Box sx={{ width: '100%' }}>
      {/* KPI Cards */}
      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <KpiCard
            title="PACKETS SENT"
            value={metrics.packetsSent.toString()}
            icon={Activity}
            color="#3b82f6"
            subtitle="Total packets"
          />
        </Grid>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <KpiCard
            title="PACKETS RECEIVED"
            value={metrics.received.toString()}
            icon={Network}
            color="#10b981"
            subtitle="Successful"
          />
        </Grid>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <KpiCard
            title="RTT AVERAGE"
            value={metrics.rttAvg.toFixed(2)}
            icon={Gauge}
            color="#f59e0b"
            subtitle="Round-trip time (ms)"
          />
        </Grid>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <KpiCard
            title="PROTOCOL"
            value={validProtocol.toUpperCase()}
            icon={Network}
            color="#8b5cf6"
            subtitle="Transport protocol"
          />
        </Grid>
      </Grid>

      {/* Charts Grid */}
      <Grid container spacing={2}>
        {/* Packet Loss Gauge */}
        <Grid size={{ xs: 12, md: 6 }}>
          <TacticalPanel title="PACKET LOSS INDICATOR &" icon={<AlertTriangle size={18} />}>
            <PerformanceGauge
              value={metrics.packetLoss}
              max={100}
              title=""
              unit="%"
              colorRanges={[
                { min: 0, max: 1, color: '#10b981' },
                { min: 1, max: 5, color: '#facc15' },
                { min: 5, max: 100, color: '#ef4444' },
              ]}
              size={250}
            />
          </TacticalPanel>
        </Grid>

        {/* RTT Distribution */}
        <Grid size={{ xs: 12, md: 6 }}>
          <TacticalPanel title="RTT DISTRIBUTION" icon={<Gauge size={18} />}>
            <TimeSeriesChart
              data={rttTrendData}
              series={[
                { key: 'min', name: 'Min RTT', color: '#10b981' },
                { key: 'avg', name: 'Avg RTT', color: '#3b82f6' },
                { key: 'max', name: 'Max RTT', color: '#ef4444' },
              ]}
              title="Round-Trip Time Trend"
              yAxisLabel="RTT (ms)"
              height={300}
            />
          </TacticalPanel>
        </Grid>

        {/* Packet Loss Over Time */}
        <Grid size={{ xs: 12 }}>
          <TacticalPanel title="PACKET LOSS OVER TIME" icon={<AlertTriangle size={18} />}>
            <TimeSeriesChart
              data={validTelemetry.map((t, idx) => {
                let loss = 0;
                if (typeof t.packet_loss === 'number') {
                  loss = t.packet_loss;
                } else if (typeof t.packets_sent === 'number' && typeof t.packets_received === 'number') {
                  loss = t.packets_sent > 0 ? ((t.packets_sent - t.packets_received) / t.packets_sent) * 100 : 0;
                }
                return {
                  timestamp: t.timestamp,
                  loss: Math.min(100, Math.max(0, loss)),
                };
              })}
              series={[{ key: 'loss', name: 'Packet Loss %', color: packetLossColor }]}
              title="Loss Rate Progression"
              yAxisLabel="Loss %"
              yAxisMax={100}
              height={250}
            />
          </TacticalPanel>
        </Grid>
      </Grid>
    </Box>
  );
};
