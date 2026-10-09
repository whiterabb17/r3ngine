import React from 'react';
import { useStressStore } from '../../../store/stressStore';
import type { EndpointStressMetrics } from '../../../types/stressTesting';

interface EndpointTableProps {
  data: Pick<EndpointStressMetrics, 'endpoint' | 'total_requests' | 'avg_latency' | 'p95_latency' | 'error_rate' | 'throughput_rps'>[];
}

export const EndpointTable: React.FC<EndpointTableProps> = ({ data }) => {
  const { setSelectedEndpoint, selectedEndpoint } = useStressStore();

  return (
    <div className="w-full bg-gray-900 rounded-lg border border-gray-800 overflow-hidden">
      <div className="px-4 py-3 border-b border-gray-800 flex justify-between items-center">
        <h3 className="text-lg font-bold text-gray-200">Endpoint Performance</h3>
      </div>
      <div className="overflow-x-auto max-h-96 overflow-y-auto">
        <table className="w-full text-sm text-left text-gray-400">
          <thead className="text-xs text-gray-400 uppercase bg-gray-800 sticky top-0">
            <tr>
              <th className="px-6 py-3">Endpoint</th>
              <th className="px-6 py-3">Requests</th>
              <th className="px-6 py-3">Avg Latency</th>
              <th className="px-6 py-3">p95 Latency</th>
              <th className="px-6 py-3">Error Rate</th>
              <th className="px-6 py-3">Throughput (RPS)</th>
            </tr>
          </thead>
          <tbody>
            {data.map((row, idx) => (
              <tr 
                key={idx} 
                className={`border-b border-gray-800 hover:bg-gray-700 cursor-pointer transition-colors ${selectedEndpoint === row.endpoint ? 'bg-gray-700' : 'bg-gray-900'}`}
                onClick={() => setSelectedEndpoint(row.endpoint)}
              >
                <td className="px-6 py-4 font-medium text-gray-200 truncate max-w-xs" title={row.endpoint}>
                  {row.endpoint}
                </td>
                <td className="px-6 py-4">{row.total_requests}</td>
                <td className="px-6 py-4">{row.avg_latency.toFixed(2)}ms</td>
                <td className="px-6 py-4 text-yellow-500">{row.p95_latency.toFixed(2)}ms</td>
                <td className={`px-6 py-4 ${row.error_rate > 0 ? 'text-red-500 font-bold' : 'text-green-500'}`}>
                  {(row.error_rate * 100).toFixed(2)}%
                </td>
                <td className="px-6 py-4">{row.throughput_rps.toFixed(2)}</td>
              </tr>
            ))}
            {data.length === 0 && (
                <tr>
                    <td colSpan={6} className="px-6 py-8 text-center text-gray-500">
                        No endpoint data available.
                    </td>
                </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
