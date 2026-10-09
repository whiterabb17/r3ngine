import React, { useMemo } from 'react';
import ReactECharts from 'echarts-for-react';
import type { EndpointStressMetrics } from '../../../types/stressTesting';

interface ThroughputChartProps {
  data: Pick<EndpointStressMetrics, 'concurrent_users' | 'throughput_rps'>[];
}

export const ThroughputChart: React.FC<ThroughputChartProps> = ({ data }) => {
  const options = useMemo(() => {
    return {
      backgroundColor: 'transparent',
      tooltip: {
        trigger: 'axis',
        axisPointer: { type: 'cross' }
      },
      xAxis: {
        type: 'value',
        name: 'Concurrent Users',
        axisLine: { lineStyle: { color: '#666' } }
      },
      yAxis: {
        type: 'value',
        name: 'Requests/sec',
        splitLine: { lineStyle: { color: '#333' } },
        axisLine: { lineStyle: { color: '#666' } }
      },
      series: [
        {
          name: 'Throughput',
          type: 'scatter',
          data: data.map(d => [d.concurrent_users, d.throughput_rps]),
          itemStyle: { color: '#10b981' }
        }
      ]
    };
  }, [data]);

  return (
    <div className="w-full h-96 bg-gray-900 rounded-lg p-4 border border-gray-800">
      <h3 className="text-lg font-bold text-gray-200 mb-2">Throughput vs Load</h3>
      <ReactECharts 
        option={options} 
        style={{ height: 'calc(100% - 2rem)', width: '100%' }}
      />
    </div>
  );
};
