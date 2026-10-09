import React from 'react';
import {
  Box,
  Typography,
  Menu,
  IconButton,
  Stack,
  Button,
  Divider,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  CircularProgress
} from '@mui/material';
import { Bell, Check, Trash2, Info, AlertCircle, XCircle, BellOff } from 'lucide-react';
// import { formatDistanceToNow } from 'date-fns';
import { useNotifications, useUnreadCount, useMarkAllRead, useClearAll, useMarkRead, type InAppNotification } from '../api';
import { useThemeTokens } from '../../../theme/useThemeTokens';

interface NotificationsDropdownProps {
  anchorEl: HTMLElement | null;
  onClose: () => void;
  projectSlug?: string;
}

export const NotificationsDropdown: React.FC<NotificationsDropdownProps> = ({
  anchorEl,
  onClose,
  projectSlug
}) => {
  const { tokens, theme } = useThemeTokens();
  const { data: notifications, isLoading } = useNotifications(projectSlug);
  const markAllRead = useMarkAllRead();
  const clearAll = useClearAll();
  const markRead = useMarkRead();

  const open = Boolean(anchorEl);

  const getIcon = (status: InAppNotification['status']) => {
    switch (status) {
      case 'info': return <Info size={16} color={tokens.accent.primary} />;
      case 'warning': return <AlertCircle size={16} color={tokens.accent.warning} />;
      case 'error': return <XCircle size={16} color={tokens.accent.error} />;
      default: return <Bell size={16} color={theme.palette.text.secondary} />;
    }
  };

  return (
    <Menu
      anchorEl={anchorEl}
      open={open}
      onClose={onClose}
      disableScrollLock
      slotProps={{
        paper: {
          sx: {
            width: 360,
            maxHeight: 500,
            bgcolor: 'background.default',
            backdropFilter: 'blur(20px)',
            border: 1, borderColor: 'divider',
            borderRadius: 2,
            backgroundImage: 'none',
            mt: 1.5,
            '& .MuiList-root': { p: 0 }
          }
        }
      }}
    >
      <Box sx={{ p: 2, borderBottom: 1, borderColor: 'divider' }}>
        <Stack direction="row" sx={{ justifyContent: 'space-between', alignItems: 'center' }}>
          <Typography sx={{ fontFamily: 'Orbitron', fontWeight: 900, fontSize: '0.75rem', letterSpacing: 1, color: tokens.accent.primary }}>
            NOTIFICATIONS
          </Typography>
          <Stack direction="row" spacing={1}>
            <Button
              size="small"
              onClick={() => markAllRead.mutate(projectSlug)}
              sx={{ fontSize: '0.65rem', color: 'text.secondary', '&:hover': { color: tokens.accent.primary } }}
            >
              Mark all read
            </Button>
            <Button
              size="small"
              onClick={() => clearAll.mutate(projectSlug)}
              sx={{ fontSize: '0.65rem', color: 'text.secondary', '&:hover': { color: tokens.accent.error } }}
            >
              Clear All
            </Button>
          </Stack>
        </Stack>
      </Box>

      <List sx={{ maxHeight: 400, overflow: 'auto' }}>
        {isLoading ? (
          <Box sx={{ p: 4, textAlign: 'center' }}>
            <CircularProgress size={20} sx={{ color: tokens.accent.primary }} />
          </Box>
        ) : (Array.isArray(notifications) && notifications.length > 0) ? (
          notifications.map((notif) => (
            <ListItem
              key={notif.id}
              onClick={() => markRead.mutate(notif.id)}
              sx={{
                borderBottom: 1, borderColor: 'divider',
                cursor: 'pointer',
                bgcolor: notif.is_read ? 'transparent' : `${tokens.accent.primary}08`,
                '&:hover': { bgcolor: 'action.hover' },
                transition: 'all 0.2s'
              }}
            >
              <ListItemIcon sx={{ minWidth: 36 }}>
                {getIcon(notif.status)}
              </ListItemIcon>
              <ListItemText
                primary={notif.title}
                secondary={
                  <Stack spacing={0.5} sx={{ mt: 0.5 }}>
                    <Typography sx={{ fontSize: '0.75rem', color: 'text.disabled' }}>
                      {notif.description}
                    </Typography>
                    <Typography sx={{ fontSize: '0.6rem', color: 'text.disabled', fontFamily: 'monospace' }}>
                      {new Date(notif.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </Typography>
                  </Stack>
                }
                slotProps={{
                  primary: {
                    sx: {
                      fontSize: '0.8rem',
                      fontWeight: notif.is_read ? 500 : 900,
                      color: notif.is_read ? 'text.secondary' : 'text.primary'
                    }
                  }
                }}
              />
            </ListItem>
          ))
        ) : (
          <Box sx={{ p: 4, textAlign: 'center', opacity: 0.5 }}>
            <BellOff size={32} style={{ marginBottom: 8, color: 'text.disabled' }} />
            <Typography sx={{ fontSize: '0.75rem', color: 'text.disabled' }}>
              Ping? Pong! No notifications, moving along
            </Typography>
          </Box>
        )}
      </List>
    </Menu>
  );
};
