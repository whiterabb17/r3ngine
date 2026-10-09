import React, { useMemo } from 'react';
import ReactECharts from 'echarts-for-react';
import { useStressStore } from '../../../store/stressStore';
import type { EndpointStressMetrics } from '../../../types/stressTesting';

interface LatencyChartProps {
  data: Pick<EndpointStressMetrics, 'timestamp' | 'avg_latency' | 'p95_latency' | 'p99_latency'>[];
}

export const LatencyChart: React.FC<LatencyChartProps> = ({ data }) => {
  const { setSelectedTimeRange } = useStressStore();

  const options = useMemo(() => {
    return {
      backgroundColor: 'transparent',
      tooltip: {
        trigger: 'axis',
        axisPointer: { type: 'cross' }
      },
      legend: {
        data: ['Avg Latency', 'p95', 'p99'],
        textStyle: { color: '#ccc' }
      },
      dataZoom: [
        { type: 'inside', start: 0, end: 100 },
        { start: 0, end: 100, textStyle: { color: '#ccc' } }
      ],
      xAxis: {
        type: 'category',
        data: data.map(d => d.timestamp),
        axisLine: { lineStyle: { color: '#666' } }
      },
      yAxis: {
        type: 'value',
        name: 'Latency (ms)',
        splitLine: { lineStyle: { color: '#333' } },
        axisLine: { lineStyle: { color: '#666' } }
      },
      series: [
        {
          name: 'Avg Latency',
          type: 'line',
          data: data.map(d => d.avg_latency),
          smooth: true,
          lineStyle: { color: '#3b82f6' }
        },
        {
          name: 'p95',
          type: 'line',
          data: data.map(d => d.p95_latency),
          smooth: true,
          lineStyle: { color: '#f59e0b' }
        },
        {
          name: 'p99',
          type: 'line',
          data: data.map(d => d.p99_latency),
          smooth: true,
          lineStyle: { color: '#ef4444' }
        }
      ]
    };
  }, [data]);

  const onEvents = {
    dataZoom: () => {
      // Stub for mapping zoom level to time range
    }
  };

  return (
    <div className="w-full h-96 bg-gray-900 rounded-lg p-4 border border-gray-800">
      <h3 className="text-lg font-bold text-gray-200 mb-2">Endpoint Latency Over Time</h3>
      <ReactECharts 
        option={options} 
        onEvents={onEvents} 
        style={{ height: 'calc(100% - 2rem)', width: '100%' }}
      />
    </div>
  );
};
