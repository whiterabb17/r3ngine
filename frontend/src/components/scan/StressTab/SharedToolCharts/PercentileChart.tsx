import { useThemeTokens } from '../../../../theme/useThemeTokens';
import React, { useMemo } from 'react';
import { useTheme, alpha } from '@mui/material';
import ReactECharts from 'echarts-for-react';
import type { TooltipComponentFormatterCallbackParams } from 'echarts';

export interface Percentiles {
  p50: number;
  p75?: number;
  p90: number;
  p95: number;
  p99?: number;
  p999?: number;
  min?: number;
  max?: number;
}

export interface PercentileChartProps {
  percentiles: Percentiles;
  title: string;
  unit: string;
  height?: number;
}

export const PercentileChart: React.FC<PercentileChartProps> = ({
  percentiles,
  title,
  unit,
  height = 300,
}) => {
  const { tokens } = useThemeTokens();
  const theme = useTheme();

  const option = useMemo(() => {
    // Handle invalid percentiles object
    if (!percentiles || typeof percentiles !== 'object') {
      return {
        backgroundColor: 'transparent',
        title: {
          text: 'NO DATA',
          textStyle: {
            color: alpha(theme.palette.text.primary, 0.3),
            fontFamily: 'Orbitron',
            fontSize: 12,
          },
        },
      };
    }

    const labels: string[] = [];
    const values: number[] = [];
    const colors: string[] = [];

    const colorMap: { [key: string]: string } = {
      'p50': '#10b981',
      'p75': '#3b82f6',
      'p90': '#f59e0b',
      'p95': '#ef4444',
      'p99': '#8b5cf6',
      'p999': '#ec4899',
      'min': '#06b6d4',
      'max': '#f97316',
    };

    // Add percentiles in order
    if (percentiles.min !== undefined) {
      labels.push('MIN');
      values.push(percentiles.min);
      colors.push(colorMap['min']);
    }

    labels.push('P50');
    values.push(percentiles.p50);
    colors.push(colorMap['p50']);

    if (percentiles.p75 !== undefined) {
      labels.push('P75');
      values.push(percentiles.p75);
      colors.push(colorMap['p75']);
    }

    labels.push('P90');
    values.push(percentiles.p90);
    colors.push(colorMap['p90']);

    labels.push('P95');
    values.push(percentiles.p95);
    colors.push(colorMap['p95']);

    if (percentiles.p99 !== undefined) {
      labels.push('P99');
      values.push(percentiles.p99);
      colors.push(colorMap['p99']);
    }

    if (percentiles.p999 !== undefined) {
      labels.push('P999');
      values.push(percentiles.p999);
      colors.push(colorMap['p999']);
    }

    if (percentiles.max !== undefined) {
      labels.push('MAX');
      values.push(percentiles.max);
      colors.push(colorMap['max']);
    }

    return {
      backgroundColor: 'transparent',
      animation: false,
      title: {
        text: title.toUpperCase(),
        textStyle: {
          color: theme.palette.primary.main,
          fontFamily: 'Orbitron',
          fontSize: 12,
          fontWeight: 800,
          letterSpacing: 1,
        },
      },
      tooltip: {
        trigger: 'axis',
        backgroundColor: 'rgba(5, 5, 10, 0.95)',
        borderColor: alpha(theme.palette.primary.main, 0.3),
        textStyle: { color: 'text.primary', fontSize: 11, fontFamily: 'monospace' },
        borderWidth: 1,
        borderRadius: 4,
        formatter: (params: TooltipComponentFormatterCallbackParams) => {
          if (Array.isArray(params) && params.length > 0) {
            return `${params[0].name}: ${params[0].value} ${unit}`;
          }
          return '';
        },
      },
      grid: { top: 60, bottom: 40, left: 60, right: 20 },
      xAxis: {
        type: 'category',
        data: labels,
        axisLine: { lineStyle: { color: alpha(theme.palette.text.primary, 0.1) } },
        axisLabel: { color: alpha(theme.palette.text.primary, 0.4), fontSize: 10, fontWeight: 700 },
        splitLine: { show: false },
      },
      yAxis: {
        type: 'value',
        name: unit,
        splitLine: { lineStyle: { color: alpha(theme.palette.text.primary, 0.05) } },
        axisLine: { show: false },
        axisLabel: { color: alpha(theme.palette.text.primary, 0.4), fontSize: 10 },
      },
      series: [
        {
          type: 'bar',
          data: values.map((v, idx) => ({
            value: v,
            itemStyle: { color: colors[idx] },
          })),
          label: {
            show: true,
            position: 'top',
            formatter: '{c}',
            color: alpha(theme.palette.text.primary, 0.7),
            fontSize: 11,
            fontWeight: 700,
          },
          emphasis: {
            itemStyle: {
              shadowBlur: 10,
              shadowOffsetX: 0,
              shadowColor: 'rgba(0, 0, 0, 0.3)',
            },
          },
        },
      ],
    };
  }, [percentiles, title, unit, theme]);

  return <ReactECharts option={option} style={{ height: `${height}px` }} />;
};
