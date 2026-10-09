import React from 'react';
import { Box, Card, CardContent, Typography, useTheme } from '@mui/material';
import Chart from 'react-apexcharts';
import type { ApexOptions } from 'apexcharts';
import type { DashboardData } from '../api';
import { themeTokens } from '../../../theme/tokens';


export const TrendCharts: React.FC<{ data: DashboardData['trends'] }> = ({ data }) => {
  const theme = useTheme();
  const isLight = theme.palette.mode === 'light';
  const chartColors = isLight ? themeTokens.enterprise.chart.series.slice(0, 3) : ['#00f3ff', '#ff003c', '#7000ff'];
  const chartMode = isLight ? 'light' : 'dark';

  const areaOptions: ApexOptions = {
    chart: {
      type: 'area',
      toolbar: { show: false },
      sparkline: { enabled: false },
      background: 'transparent'
    },
    stroke: { curve: 'smooth', width: 2 },
    fill: {
      type: 'gradient',
      gradient: {
        shadeIntensity: 1,
        opacityFrom: isLight ? 0.25 : 0.45,
        opacityTo: 0.05,
        stops: [20, 100]
      }
    },
    xaxis: {
      categories: data.last_7_dates.map(d => new Date(d).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })),
      labels: { style: { colors: theme.palette.text.secondary } }
    },
    yaxis: { labels: { show: false } },
    grid: { borderColor: theme.palette.divider, strokeDashArray: 4 },
    tooltip: { theme: chartMode },
    colors: chartColors
  };

  const series = [
    { name: 'Subdomains', data: data.subdomains_in_last_week },
    { name: 'Vulnerabilities', data: data.vulns_in_last_week },
    { name: 'Endpoints', data: data.endpoints_in_last_week }
  ];

  return (
    <Card sx={{
      height: 500,
      bgcolor: isLight ? theme.palette.background.paper : 'rgba(5, 5, 15, 0.6)',
      backdropFilter: isLight ? 'none' : 'blur(10px)',
      border: isLight ? `1px solid ${theme.palette.divider}` : '1px solid rgba(0, 243, 255, 0.1)',
      display: 'flex',
      flexDirection: 'column'
    }}>
      <CardContent sx={{ flexGrow: 1, display: 'flex', flexDirection: 'column' }}>
        <Typography variant="h6" sx={{ mb: 3, fontSize: '0.9rem', textTransform: 'uppercase', letterSpacing: 1, fontFamily: 'var(--r3-heading-font)' }}>
          7-Day Activity Horizon
        </Typography>
        <Box sx={{ flexGrow: 1 }}>
          <Chart 
            options={areaOptions} 
            series={series} 
            type="area"
            height="100%"
          />
        </Box>
      </CardContent>
    </Card>
  );
};
