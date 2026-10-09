import { render, screen } from '@testing-library/react';
import { ThemeProvider } from '@mui/material/styles';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { hackerTheme } from '../../../../theme';
import { useStressStore } from '../../../../store/stressStore';
import { ErrorDistribution } from '../ErrorDistribution';

interface CapturedChartProps {
  option: {
    xAxis: { data: string[] };
    series: { type: string; data: number[] }[];
  };
  onEvents: { click: (params: { name?: string }) => void };
}

const chartProps: { current: CapturedChartProps | null } = { current: null };

vi.mock('echarts-for-react', () => ({
  default: (props: CapturedChartProps) => {
    chartProps.current = props;
    return <div data-testid="echart" />;
  },
}));

vi.mock('../../../../theme/useThemeTokens', async () => {
  const { hackerTheme: theme } = await import('../../../../theme');
  const { getResolvedTokens: resolve } = await import('../../../../theme/tokens');
  return {
    useThemeTokens: () => ({
      tokens: resolve('hacker'),
      theme,
      isLight: false,
      isCyber: true,
      themeName: 'hacker',
    }),
  };
});

const renderChart = (data: Parameters<typeof ErrorDistribution>[0]['data']) => render(
  <ThemeProvider theme={hackerTheme}>
    <ErrorDistribution data={data} />
  </ThemeProvider>,
);

beforeEach(() => {
  chartProps.current = null;
  useStressStore.getState().resetSelections();
});

describe('ErrorDistribution', () => {
  it('draws one bar per endpoint with its error rate', () => {
    renderChart([
      { endpoint: 'https://app.example.test/login', error_rate: 12.5 },
      { endpoint: 'https://app.example.test/api', error_rate: 3 },
    ]);

    expect(screen.getByTestId('echart')).toBeInTheDocument();
    expect(chartProps.current?.option.xAxis.data).toEqual([
      'https://app.example.test/login',
      'https://app.example.test/api',
    ]);
    expect(chartProps.current?.option.series[0]).toMatchObject({ type: 'bar', data: [12.5, 3] });
  });

  it('selects the clicked endpoint for the drill-down', () => {
    renderChart([{ endpoint: 'https://app.example.test/login', error_rate: 12.5 }]);

    chartProps.current?.onEvents.click({ name: 'https://app.example.test/login' });
    expect(useStressStore.getState().selectedEndpoint).toBe('https://app.example.test/login');
  });

  it('shows an empty state instead of an empty chart', () => {
    renderChart([]);

    expect(screen.getByText('NO ERROR DATA')).toBeInTheDocument();
    expect(screen.queryByTestId('echart')).not.toBeInTheDocument();
  });
});
