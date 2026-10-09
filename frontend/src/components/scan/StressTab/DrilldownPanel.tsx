import React, { useMemo } from 'react';
import ReactECharts from 'echarts-for-react';
import { useStressStore } from '../../../store/stressStore';
import type { EndpointStressMetrics } from '../../../types/stressTesting';

interface DrilldownPanelProps {
  data: Pick<EndpointStressMetrics, 'endpoint' | 'timestamp' | 'avg_latency' | 'error_rate'>[];
}

export const DrilldownPanel: React.FC<DrilldownPanelProps> = ({ data }) => {
  const { selectedEndpoint, setSelectedEndpoint } = useStressStore();

  const endpointData = useMemo(() => {
    return data.filter(d => d.endpoint === selectedEndpoint);
  }, [data, selectedEndpoint]);

  if (!selectedEndpoint) {
    return (
      <div className="w-full h-96 bg-gray-900/50 rounded-lg border border-gray-800 flex items-center justify-center border-dashed">
        <p className="text-gray-500">Select an endpoint from the table to view deep drilldown analytics.</p>
      </div>
    );
  }

  const options = useMemo(() => {
    return {
      backgroundColor: 'transparent',
      tooltip: { trigger: 'axis' },
      xAxis: {
        type: 'category',
        data: endpointData.map(d => d.timestamp),
        axisLine: { lineStyle: { color: '#666' } }
      },
      yAxis: {
        type: 'value',
        name: 'Latency',
        splitLine: { lineStyle: { color: '#333' } }
      },
      series: [
        {
          name: 'Latency',
          type: 'bar',
          data: endpointData.map(d => d.avg_latency),
          itemStyle: { color: '#8b5cf6' }
        }
      ]
    };
  }, [endpointData]);

  return (
    <div className="w-full bg-gray-900 rounded-lg p-4 border border-blue-900/50 shadow-lg shadow-blue-900/20 relative">
      <button 
        onClick={() => setSelectedEndpoint(null)}
        className="absolute top-4 right-4 text-gray-400 hover:text-white"
      >
        ✕ Close
      </button>
      <h3 className="text-xl font-bold text-gray-100 mb-1">Deep Dive: {selectedEndpoint}</h3>
      <p className="text-sm text-gray-400 mb-6">Detailed performance characteristics under varying loads.</p>
      
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="h-64">
             <h4 className="text-sm text-gray-400 mb-2">Latency Histogram</h4>
             <ReactECharts option={options} style={{ height: '100%', width: '100%' }} />
          </div>
          <div className="h-64 bg-gray-800 rounded p-4 overflow-y-auto">
             <h4 className="text-sm text-gray-400 mb-2">Error Timeline & Samples</h4>
             {endpointData.reduce((sum, curr) => sum + curr.error_rate, 0) > 0 ? (
                 <ul className="space-y-2">
                     <li className="text-red-400 text-xs font-mono">Status 502 Bad Gateway - Connection Refused</li>
                     <li className="text-yellow-400 text-xs font-mono">Status 408 Request Timeout</li>
                 </ul>
             ) : (
                 <p className="text-green-500 text-sm mt-4">✓ No errors detected for this endpoint.</p>
             )}
          </div>
      </div>
    </div>
  );
};
