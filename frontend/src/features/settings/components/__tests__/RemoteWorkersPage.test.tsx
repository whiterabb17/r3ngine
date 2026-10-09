import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { ThemeProvider } from '@mui/material/styles';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { hackerTheme } from '../../../../theme';
import { RemoteWorkersPage } from '../RemoteWorkersPage';
import * as api from '../../api';

vi.mock('../../api');
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

const worker: api.RemoteWorker = {
  id: 1,
  name: 'worker-eu-1',
  description: null,
  task_queue: 'worker-eu-1',
  hostname: null,
  ip_address: '192.0.2.10',
  is_active: true,
  last_heartbeat: null,
};

const mutateAsync = vi.fn();

function renderPage() {
  return render(
    <ThemeProvider theme={hackerTheme}>
      <RemoteWorkersPage />
    </ThemeProvider>,
  );
}

beforeEach(() => {
  mutateAsync.mockReset();
  vi.mocked(api.useRemoteWorkers).mockReturnValue(
    { data: [worker], isLoading: false } as unknown as ReturnType<typeof api.useRemoteWorkers>,
  );
  vi.mocked(api.useCreateRemoteWorker).mockReturnValue(
    { mutateAsync, isPending: false } as unknown as ReturnType<typeof api.useCreateRemoteWorker>,
  );
  vi.mocked(api.useDeleteRemoteWorker).mockReturnValue(
    { mutateAsync: vi.fn(), isPending: false } as unknown as ReturnType<typeof api.useDeleteRemoteWorker>,
  );
});

describe('RemoteWorkersPage', () => {
  it('lists workers by task queue without any token column', () => {
    renderPage();
    expect(screen.getByText('Task Queue')).toBeInTheDocument();
    expect(screen.queryByText(/Keep Secret/)).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Auth Token')).not.toBeInTheDocument();
  });

  it('creates a worker from its name and shows the issued token once', async () => {
    mutateAsync.mockResolvedValue({ ...worker, name: 'worker-us-1', auth_token: 'r3n_wkr_issued' });
    renderPage();

    fireEvent.change(screen.getByLabelText('Worker Name'), { target: { value: 'worker-us-1' } });
    fireEvent.click(screen.getByRole('button', { name: 'Create Worker' }));

    await waitFor(() => expect(screen.getByText('r3n_wkr_issued')).toBeInTheDocument());
    expect(mutateAsync).toHaveBeenCalledWith({ name: 'worker-us-1' });

    const tokenAlert = screen.getByText('r3n_wkr_issued').closest('[role="alert"]') as HTMLElement;
    fireEvent.click(within(tokenAlert).getByRole('button', { name: /close/i }));
    expect(screen.queryByText('r3n_wkr_issued')).not.toBeInTheDocument();
  });
});
