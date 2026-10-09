import { fireEvent, render, screen, within } from '@testing-library/react';
import { ThemeProvider } from '@mui/material/styles';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { hackerTheme } from '../../../../theme';
import type { HardwareProfile } from '../../../engines/types';
import { ScanHardwareProfileControl } from '../ScanHardwareProfileControl';

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

const profile = (id: number, name: string, extra: Partial<HardwareProfile> = {}): HardwareProfile => ({
  id,
  name,
  threads: 4,
  rate_limit: 50,
  timeout: 10,
  delay: 0,
  retries: 1,
  profile_type: 'builtin',
  is_active: true,
  is_default: false,
  ...extra,
});

const profiles: HardwareProfile[] = [
  profile(1, 'vps', { is_default: true }),
  profile(2, 'dedicated', { threads: 64, rate_limit: 1000 }),
  profile(3, 'retired', { is_active: false }),
];

const mutate = vi.fn();
vi.mock('../../../engines/api', () => ({
  useHardwareProfiles: () => ({ data: profiles }),
}));
vi.mock('../../api', () => ({
  useSetScanHardwareProfile: () => ({ mutate, isPending: false }),
}));

const renderControl = (props: Parameters<typeof ScanHardwareProfileControl>[0]) => render(
  <ThemeProvider theme={hackerTheme}>
    <ScanHardwareProfileControl {...props} />
  </ThemeProvider>,
);

describe('ScanHardwareProfileControl', () => {
  beforeEach(() => mutate.mockReset());

  it('is hidden once the scan has finished', () => {
    const { container } = renderControl({ scanId: 7, scanStatus: 2, currentProfileId: 1 });
    expect(container).toBeEmptyDOMElement();
  });

  it('explains that only later steps are affected', () => {
    renderControl({ scanId: 7, scanStatus: 1, currentProfileId: 1 });
    expect(screen.getByText(/steps that start after the change/i)).toBeInTheDocument();
    expect(screen.getByText(/tools already running keep their settings/i)).toBeInTheDocument();
  });

  it('offers only active profiles and switches the running scan', () => {
    renderControl({ scanId: 7, scanStatus: 1, currentProfileId: 1 });

    fireEvent.mouseDown(screen.getByRole('combobox'));
    const listbox = within(screen.getByRole('listbox'));
    expect(listbox.queryByText(/RETIRED/)).not.toBeInTheDocument();
    fireEvent.click(listbox.getByText(/DEDICATED/));

    expect(mutate).toHaveBeenCalledTimes(1);
    expect(mutate.mock.calls[0][0]).toEqual({ scanId: 7, hardwareProfileId: 2 });
  });

  it('shows the default profile for a scan without its own', () => {
    renderControl({ scanId: 7, scanStatus: -1, currentProfileId: null });
    expect(screen.getByRole('combobox')).toHaveTextContent(/VPS \(DEFAULT\)/);
  });
});
