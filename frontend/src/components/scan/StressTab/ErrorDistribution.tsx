import React, { useMemo } from 'react';
import { Box, Typography, alpha } from '@mui/material';
import { AlertTriangle } from 'lucide-react';
import ReactECharts from 'echarts-for-react';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import { useStressStore } from '../../../store/stressStore';
import { TacticalPanel } from '../../TacticalPanel';

export interface EndpointErrorRate {
  endpoint: string;
  /** Percentage of failed requests, 0-100. */
  error_rate: number;
}

interface ErrorDistributionProps {
  data: EndpointErrorRate[];
  height?: number;
}

export const ErrorDistribution: React.FC<ErrorDistributionProps> = ({ data, height = 320 }) => {
  const { tokens, theme } = useThemeTokens();
  const setSelectedEndpoint = useStressStore((state) => state.setSelectedEndpoint);

  const option = useMemo(() => {
    const axisColor = alpha(theme.palette.text.primary, 0.4);
    return {
      backgroundColor: 'transparent',
      animation: false,
      grid: { top: 30, bottom: 10, left: 10, right: 10, containLabel: true },
      tooltip: {
        trigger: 'item',
        backgroundColor: theme.palette.background.paper,
        borderColor: alpha(tokens.accent.error, 0.3),
        textStyle: { color: theme.palette.text.primary, fontSize: 11, fontFamily: 'monospace' },
        valueFormatter: (value: number) => `${value}%`,
      },
      xAxis: {
        type: 'category',
        data: data.map((row) => row.endpoint),
        axisLine: { lineStyle: { color: alpha(theme.palette.text.primary, 0.1) } },
        axisLabel: { color: axisColor, fontSize: 10, rotate: 30, width: 140, overflow: 'truncate' },
      },
      yAxis: {
        type: 'value',
        name: 'Error Rate (%)',
        nameTextStyle: { color: axisColor, fontSize: 10 },
        splitLine: { lineStyle: { color: alpha(theme.palette.text.primary, 0.05) } },
        axisLabel: { color: axisColor, fontSize: 10 },
      },
      series: [
        {
          type: 'bar',
          name: 'Error Rate',
          data: data.map((row) => row.error_rate),
          barMaxWidth: 48,
          itemStyle: { color: tokens.accent.error, borderRadius: [2, 2, 0, 0] },
          label: { show: true, position: 'top', color: alpha(theme.palette.text.primary, 0.6), fontSize: 10 },
          cursor: 'pointer',
        },
      ],
    };
  }, [data, theme, tokens]);

  const onEvents = useMemo(() => ({
    click: (params: { name?: string }) => {
      if (params.name) setSelectedEndpoint(params.name);
    },
  }), [setSelectedEndpoint]);

  return (
    <TacticalPanel title="ERROR DISTRIBUTION" icon={<AlertTriangle size={18} />}>
      {data.length === 0 ? (
        <Box sx={{ height, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <Typography sx={{ fontFamily: 'Orbitron', fontSize: '0.75rem', color: 'text.disabled', letterSpacing: 1 }}>
            NO ERROR DATA
          </Typography>
        </Box>
      ) : (
        <ReactECharts option={option} onEvents={onEvents} style={{ height: `${height}px`, width: '100%' }} />
      )}
    </TacticalPanel>
  );
};
