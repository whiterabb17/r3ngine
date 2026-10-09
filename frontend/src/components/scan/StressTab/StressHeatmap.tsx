import { useThemeTokens } from '../../../theme/useThemeTokens';
import React, { useMemo } from 'react';
import ReactECharts from 'echarts-for-react';
import { useStressStore } from '../../../store/stressStore';
import type { EndpointStressMetrics } from '../../../types/stressTesting';

interface StressHeatmapProps {
  data: Pick<EndpointStressMetrics, 'concurrent_users' | 'endpoint' | 'avg_latency'>[];
}

export const StressHeatmap: React.FC<StressHeatmapProps> = ({ data }) => {
  const { tokens } = useThemeTokens();
  const { setSelectedEndpoint } = useStressStore();
  
  const options = useMemo(() => {
    // We expect data mapped into [x, y, value] format for heatmaps
    // x = load (users), y = endpoint, value = latency
    const hours = data.map(d => d.concurrent_users);
    const days = data.map(d => d.endpoint);
    const heatmapData = data.map((d, index) => [
        hours.indexOf(d.concurrent_users), 
        days.indexOf(d.endpoint), 
        d.avg_latency
    ]);

    return {
      backgroundColor: 'transparent',
      tooltip: {
        position: 'top'
      },
      grid: {
        height: '50%',
        top: '10%'
      },
      xAxis: {
        type: 'category',
        data: [...new Set(hours)],
        splitArea: {
          show: true
        },
        name: 'Users'
      },
      yAxis: {
        type: 'category',
        data: [...new Set(days)],
        splitArea: {
          show: true
        },
        name: 'Endpoint'
      },
      visualMap: {
        min: 0,
        max: 1000,
        calculable: true,
        orient: 'horizontal',
        left: 'center',
        bottom: '15%',
        inRange: {
            color: ['#10b981', '#facc15', '#ef4444']
        }
      },
      series: [
        {
          name: 'Latency',
          type: 'heatmap',
          data: heatmapData,
          label: {
            show: false
          },
          emphasis: {
            itemStyle: {
              shadowBlur: 10,
              shadowColor: 'rgba(0, 0, 0, 0.5)'
            }
          }
        }
      ]
    };
  }, [data]);

  const onEvents = {
    click: (params: { name?: string }) => {
      // params.name would be the Y axis category (endpoint) if we structure data correctly
      if (params.name) {
         setSelectedEndpoint(params.name);
      }
    }
  };

  return (
    <div className="w-full h-96 bg-gray-900 rounded-lg p-4 border border-gray-800">
      <h3 className="text-lg font-bold text-gray-200 mb-2">Endpoint Saturation Map</h3>
      <ReactECharts 
        option={options} 
        onEvents={onEvents} 
        style={{ height: 'calc(100% - 2rem)', width: '100%' }}
      />
    </div>
  );
};
