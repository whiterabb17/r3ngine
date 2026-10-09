import { render, screen } from '@testing-library/react';
import { ThemeProvider } from '@mui/material/styles';
import { describe, expect, it, vi } from 'vitest';
import { hackerTheme } from '../../../../theme';
import type { InAppNotification } from '../../api';
import { NotificationsDropdown } from '../NotificationsDropdown';

vi.mock('../../../../theme/useThemeTokens', async () => {
  const { hackerTheme: theme } = await import('../../../../theme');
  const { getResolvedTokens: resolve } = await import('../../../../theme/tokens');
  return {
    useThemeTokens: () => ({ tokens: resolve('hacker'), theme, isLight: false, isCyber: true, themeName: 'hacker' }),
  };
});

const notification = (id: number, status: InAppNotification['status']): InAppNotification => ({
  id,
  title: `Notice ${id}`,
  description: 'Anonymised test notice',
  icon: 'info',
  is_read: false,
  created_at: '2026-01-01T00:00:00Z',
  notification_type: 'project',
  status,
});

const mutation = { mutate: vi.fn(), isPending: false };

vi.mock('../../api', () => ({
  useNotifications: () => ({
    data: [notification(1, 'error'), notification(2, 'warning'), notification(3, 'success')],
    isLoading: false,
  }),
  useUnreadCount: () => ({ data: { count: 3 } }),
  useMarkAllRead: () => mutation,
  useClearAll: () => mutation,
  useMarkRead: () => mutation,
}));

describe('NotificationsDropdown', () => {
  it('picks each row icon from the notification status', () => {
    render(
      <ThemeProvider theme={hackerTheme}>
        <NotificationsDropdown anchorEl={document.body} onClose={vi.fn()} projectSlug="demo" />
      </ThemeProvider>,
    );

    const iconClass = (title: string) =>
      screen.getByText(title).closest('li')?.querySelector('svg')?.getAttribute('class') ?? '';

    expect(iconClass('Notice 1')).toContain('lucide-circle-x');
    expect(iconClass('Notice 2')).toContain('lucide-circle-alert');
    expect(iconClass('Notice 3')).toContain('lucide-bell');
  });
});
