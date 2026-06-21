import { useThemeTokens } from '../../theme/useThemeTokens';
import { getMenuPaperSx } from '../../theme/semanticColors';
import React, { useState } from 'react';
import {
  Box,
  Drawer,
  AppBar,
  Toolbar,
  List,
  Typography,
  Divider,
  IconButton,
  ListItem,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Avatar,
  Menu,
  MenuItem,
  Tooltip,
  InputBase,
  Collapse,
  Button,
  Chip,
  Grid,
  Badge,
  alpha,
  useMediaQuery,
  Snackbar,
  Alert
} from '@mui/material';

import {
  Home,
  Folder,
  Target,
  Monitor,
  Activity,
  ShieldAlert,
  CheckSquare,
  Briefcase,
  Cpu,
  Command,
  Settings,
  Bell,
  Search,
  ChevronRight,
  ChevronDown,
  LayoutGrid,
  Sliders,
  Clock,
  Globe,
  Plus,
  RefreshCw,
  LogOut,
  User as UserIcon,
  Wrench,
  List as ListIcon,
  Bug,
  Menu as MenuIcon,
  X,
  Heart,
  Scan,
  ScanEyeIcon
} from 'lucide-react';
import { useTheme } from '@mui/material/styles';
import { Link, useRouterState, useParams } from '@tanstack/react-router';
import { useAppContext } from '../../context/AppContext';
import {
  WhoisModal,
  CMSDetectorModal,
  CVELookupModal,
  WAFDetectorModal
} from '../../features/tools/components/ToolboxModals';
import { useQuery } from '@tanstack/react-query';
import axios from 'axios';
import { NotificationsDropdown } from '../../features/notifications/components/NotificationsDropdown';
import { useUnreadCount } from '../../features/notifications/api';
import { ScanHistoryDrawer } from '../../features/scans/components/ScanHistoryDrawer';
import { CheckForUpdateModal } from '../../features/settings/components/CheckForUpdateModal';
import { useProxySettings, useRengineUpdateCheck, useTorStatus, useTorExitIP } from '../../features/settings/api';
import { HeaderThemeSwitcher } from './HeaderThemeSwitcher';

const drawerWidth = 260;
const collapsedWidth = 72;

interface NavItem {
  title: string;
  icon: React.ReactNode;
  path: string;
  color?: string;
  children?: { title: string; path: string }[];
}

export const Shell: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { tokens, isLight, isCyber } = useThemeTokens();
  const theme = useTheme();
  const { version, projectName, setVersion } = useAppContext();
  const [isHovered, setIsHovered] = useState(false);
  const [openItems, setOpenItems] = useState<string[]>([]);
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [quickAddAnchorEl, setQuickAddAnchorEl] = useState<null | HTMLElement>(null);
  const [toolboxAnchorEl, setToolboxAnchorEl] = useState<null | HTMLElement>(null);
  const [openTool, setOpenTool] = useState<string | null>(null);
  const [notificationAnchorEl, setNotificationAnchorEl] = useState<null | HTMLElement>(null);
  const [scanHistoryAnchorEl, setScanHistoryAnchorEl] = useState<null | HTMLElement>(null);
  const [scanHistoryOpen, setScanHistoryOpen] = useState(false);
  const [updateModalOpen, setUpdateModalOpen] = useState(false);
  const [updateAvailable, setUpdateAvailable] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const isMobileHeader = useMediaQuery(theme.breakpoints.down('lg'));

  const { projectSlug = 'default' } = useParams({ strict: false }) as any;
  const { data: torStatus } = useTorStatus();
  const torActive = torStatus?.running ?? false;
  const { data: torExitIP } = useTorExitIP(torActive);
  const { data: unreadData } = useUnreadCount(projectSlug);
  const { data: proxySettings } = useProxySettings(projectSlug, {
    refetchInterval: 15000,
    refetchIntervalInBackground: true,
  });
  const [proxyWarningOpen, setProxyWarningOpen] = useState(false);
  const [hasWarnedForLowProxyStock, setHasWarnedForLowProxyStock] = useState(false);

  const { data: pluginsRegistry } = useQuery({
    queryKey: ['pluginsRegistry'],
    queryFn: async () => {
      const res = await axios.get('/api/plugins/registry/');
      return res.data;
    }
  });

  const pluginMenuChildren = (pluginsRegistry || [])
    .filter((p: any) => p.components?.menu_item)
    .map((p: any) => ({
      title: p.components.menu_item,
      path: `/${projectSlug}${p.components.menu_path}`
    }));

  const navItems: NavItem[] = [
    { title: 'Dashboard', icon: <Home size={20} />, path: `/${projectSlug}/dashboard`, color: theme.palette.primary.main },
    { title: 'Projects', icon: <Folder size={20} />, path: `/${projectSlug}/projects`, color: theme.palette.primary.main },
    { title: 'Targets', icon: <Target size={20} />, path: `/${projectSlug}/targets`, color: theme.palette.primary.main },
    { title: 'Monitoring', icon: <Monitor size={20} />, path: `/${projectSlug}/monitoring`, color: theme.palette.primary.main },
    {
      title: 'Scan History',
      icon: <Activity size={20} />,
      path: `/${projectSlug}/scans`,
      color: theme.palette.primary.main,
      children: [
        { title: 'Scan History', path: `/${projectSlug}/scans` },
        { title: 'Sub Scan History', path: `/${projectSlug}/scans/sub` },
        { title: 'Scheduled Scan', path: `/${projectSlug}/scans/scheduled` },
        { title: 'All Subdomains', path: `/${projectSlug}/subdomains` },
        { title: 'All Endpoints', path: `/${projectSlug}/endpoints` },
      ]
    },
    { title: 'Vulnerabilities', icon: <ShieldAlert size={20} />, path: `/${projectSlug}/vulns`, color: theme.palette.primary.main },
    { title: 'Todo', icon: <CheckSquare size={20} />, path: `/${projectSlug}/todo`, color: theme.palette.primary.main },
    { title: 'Organization', icon: <Briefcase size={20} />, path: `/${projectSlug}/org`, color: theme.palette.primary.main },
    { title: 'Scan Engine', icon: <Cpu size={20} />, path: `/${projectSlug}/engines`, color: theme.palette.primary.main },
    {
      title: 'Plugins',
      icon: <LayoutGrid size={20} />,
      path: `/${projectSlug}/plugins`,
      color: theme.palette.primary.main,
      children: pluginMenuChildren.length > 0 ? [
        { title: 'Manage Plugins', path: `/${projectSlug}/plugins` },
        ...pluginMenuChildren
      ] : undefined
    },
    { title: 'Bounty Hub', icon: <Command size={20} />, path: `/${projectSlug}/bounty`, color: theme.palette.primary.main },
    {
      title: 'Settings',
      icon: <Settings size={20} />,
      path: `/${projectSlug}/settings`,
      color: theme.palette.primary.main,
      children: [
        { title: 'Proxies', path: `/${projectSlug}/settings/proxies` },
        { title: 'OpSec Settings', path: `/${projectSlug}/settings/opsec` },
        { title: 'Tool Settings', path: `/${projectSlug}/settings/tool-settings` },
        { title: 'API Vault', path: `/${projectSlug}/settings/api-vault` },
        { title: 'LLM Toolkit', path: `/${projectSlug}/settings/llm-toolkit` },
        { title: 'Tool Arsenal', path: `/${projectSlug}/settings/tools-arsenal` },
        { title: 'Report Settings', path: `/${projectSlug}/settings/report-settings` },
        { title: 'reNgine Settings', path: `/${projectSlug}/settings/rengine-settings` },
        { title: 'Notification Settings', path: `/${projectSlug}/settings/notifications` },
      ]
    },
  ];

  const handleToggle = (title: string) => {
    setOpenItems(prev =>
      prev.includes(title) ? prev.filter(i => i !== title) : [...prev, title]
    );
  };

  const handleMenuOpen = (event: React.MouseEvent<HTMLElement>) => setAnchorEl(event.currentTarget);
  const handleMenuClose = () => setAnchorEl(null);

  const handleQuickAddOpen = (event: React.MouseEvent<HTMLElement>) => setQuickAddAnchorEl(event.currentTarget);
  const handleQuickAddClose = () => setQuickAddAnchorEl(null);

  const handleToolboxOpen = (event: React.MouseEvent<HTMLElement>) => setToolboxAnchorEl(event.currentTarget);
  const handleToolboxClose = () => setToolboxAnchorEl(null);

  const handleToolClick = (tool: string) => {
    setOpenTool(tool);
    handleToolboxClose();
  };

  const handleNotificationOpen = (event: React.MouseEvent<HTMLElement>) => setNotificationAnchorEl(event.currentTarget);
  const handleNotificationClose = () => setNotificationAnchorEl(null);
  const handleScanHistoryOpen = (event: React.MouseEvent<HTMLElement>) => setScanHistoryOpen(true);
  const handleScanHistoryClose = () => setScanHistoryOpen(false);

  const routerState = useRouterState();
  const activePath = routerState.location.pathname;

  const updateCheck = useRengineUpdateCheck();

  React.useEffect(() => {
    const lastCheck = localStorage.getItem('last_update_checked');
    const today = new Date().toLocaleDateString();

    if (lastCheck !== today) {
      updateCheck.mutateAsync().then(data => {
        if (data.current_version) {
          setVersion(data.current_version);
        }
        if (data.update_available) {
          setUpdateAvailable(true);
          localStorage.setItem('update_available', 'true');
        } else {
          setUpdateAvailable(false);
          localStorage.setItem('update_available', 'false');
        }
        localStorage.setItem('last_update_checked', today);
      }).catch(err => console.error('Auto update check failed', err));
    } else {
      // Check if update_available is in localStorage from a previous session
      const wasUpdateAvailable = localStorage.getItem('update_available') === 'true';
      if (wasUpdateAvailable) {
        setUpdateAvailable(true);
      }
    }
  }, []);

  const validProxyCount = proxySettings?.proxies 
    ? proxySettings.proxies.split('\n').filter(p => p.trim() !== '').length 
    : (proxySettings?.valid_proxy_count ?? 0);
  const proxyModeEnabled = Boolean(proxySettings?.use_proxy);
  const proxyIndicator = React.useMemo(() => {
    if (!proxyModeEnabled) {
      return {
        fg: alpha(theme.palette.text.secondary, 0.8),
        bg: alpha(theme.palette.text.secondary, 0.08),
        border: alpha(theme.palette.text.secondary, 0.16),
        label: 'PROXY OFF',
      };
    }
    if (validProxyCount > 20) {
      return {
        fg: tokens.accent.success,
        bg: alpha(tokens.accent.success, 0.12),
        border: alpha(tokens.accent.success, 0.28),
        label: `PROXY ${validProxyCount}`,
      };
    }
    if (validProxyCount >= 10) {
      return {
        fg: tokens.accent.warning,
        bg: alpha(tokens.accent.warning, 0.12),
        border: alpha(tokens.accent.warning, 0.28),
        label: `PROXY ${validProxyCount}`,
      };
    }
    return {
      fg: tokens.accent.error,
      bg: alpha(tokens.accent.error, 0.12),
      border: alpha(tokens.accent.error, 0.28),
      label: `PROXY ${validProxyCount}`,
    };
  }, [
    proxyModeEnabled,
    theme.palette.text.secondary,
    tokens.accent.error,
    tokens.accent.success,
    tokens.accent.warning,
    validProxyCount,
  ]);

  React.useEffect(() => {
    if (!proxyModeEnabled || validProxyCount >= 5) {
      setHasWarnedForLowProxyStock(false);
      setProxyWarningOpen(false);
      return;
    }

    if (!hasWarnedForLowProxyStock) {
      setProxyWarningOpen(true);
      setHasWarnedForLowProxyStock(true);
    }
  }, [hasWarnedForLowProxyStock, proxyModeEnabled, validProxyCount]);

  const handleUpdateCheckClick = () => {
    setUpdateModalOpen(true);
    handleMenuClose();
  };

  const quickAddItems = [
    { title: 'Target', icon: <Target size={16} />, path: `/${projectSlug}/targets` },
    { title: 'Organization', icon: <Briefcase size={16} />, path: `/${projectSlug}/org` },
    { title: 'Scan Engine', icon: <Cpu size={16} />, path: `/${projectSlug}/engines` },
    { title: 'External Tool', icon: <Wrench size={16} />, path: `/${projectSlug}/settings/tools-arsenal` },
    { title: 'Wordlist', icon: <ListIcon size={16} />, path: `/${projectSlug}/engines` },
  ];

  const toolboxItems = [
    { id: 'whois', title: 'Whois', icon: <Globe size={28} />, color: tokens.accent.primary },
    { id: 'cms', title: 'CMS Detector', icon: <Search size={28} />, color: tokens.accent.primary },
    { id: 'cve', title: 'CVE Lookup', icon: <Bug size={28} />, color: tokens.accent.secondary },
    { id: 'waf', title: 'WAF Detector', icon: <ShieldAlert size={28} />, color: tokens.accent.warning },
  ];

  return (
    <Box sx={{
      display: 'flex',
      minHeight: '100vh',
      bgcolor: 'transparent'
    }}>
      {/* Sidebar - Mini Drawer Style */}
      <Drawer
        variant="permanent"
        onMouseEnter={() => setIsHovered(true)}
        onMouseLeave={() => {
          setIsHovered(false);
          setOpenItems([]);
        }}
        sx={{
          width: isHovered ? drawerWidth : collapsedWidth,
          flexShrink: 0,
          whiteSpace: 'nowrap',
          transition: theme.transitions.create('width', {
            easing: theme.transitions.easing.sharp,
            duration: theme.transitions.duration.enteringScreen,
          }),
          '& .MuiDrawer-paper': {
            width: isHovered ? drawerWidth : collapsedWidth,
            transition: theme.transitions.create('width', {
              easing: theme.transitions.easing.sharp,
              duration: theme.transitions.duration.enteringScreen,
            }),
            overflowX: 'hidden',
            overflowY: 'auto',
            boxSizing: 'border-box',
            borderRight: 'none',
            bgcolor: alpha(theme.palette.background.paper, 0.8),
            backdropFilter: 'blur(10px)',
            backgroundImage: 'none',
            borderRadius: '0 30px 30px 0',
            height: 'fit-content',
            maxHeight: 'calc(100vh - 40px)',
            top: '50%',
            transform: 'translateY(-50%)',
            border: `1px solid ${alpha(theme.palette.primary.main, 0.1)}`,
            boxShadow: theme.shadows[10],
            py: 2,
            /* Custom Scrollbar */
            '&::-webkit-scrollbar': {
              width: '4px',
            },
            '&::-webkit-scrollbar-track': {
              background: 'transparent',
            },
            '&::-webkit-scrollbar-thumb': {
              background: alpha(theme.palette.primary.main, 0.2),
              borderRadius: '10px',
              '&:hover': {
                background: alpha(theme.palette.primary.main, 0.4),
              },
            },
          },
        }}
      >
        <List sx={{ px: 1, mt: 2 }}>
          {navItems.map((item) => {
            const hasChildren = item.children && item.children.length > 0;
            const isOpen = openItems.includes(item.title);
            const isActive = activePath.startsWith(item.path);
            const itemColor = isLight
              ? (isActive ? theme.palette.primary.main : theme.palette.text.secondary)
              : (isActive ? tokens.accent.secondary : tokens.accent.primary);

            return (
              <React.Fragment key={item.title}>
                <ListItem disablePadding sx={{ mb: '-5px' }}>
                  <ListItemButton
                    {...(hasChildren ? {
                      onClick: () => handleToggle(item.title)
                    } : {
                      component: Link,
                      to: item.path,
                      onClick: () => setOpenItems([])
                    })}
                    sx={{
                      borderRadius: 2,
                      minHeight: 48,
                      justifyContent: isHovered ? 'initial' : 'center',
                      px: 2.5,
                      bgcolor: isActive ? alpha(theme.palette.primary.main, 0.15) : 'transparent',
                      '&:hover': {
                        bgcolor: isActive ? alpha(theme.palette.primary.main, 0.2) : alpha(theme.palette.primary.main, 0.05),
                      }
                    }}
                  >
                    <ListItemIcon sx={{
                      minWidth: 0,
                      mr: isHovered ? 2 : 'auto',
                      justifyContent: 'center',
                      color: itemColor,
                      filter: isCyber ? `drop-shadow(0 0 5px ${itemColor}66)` : 'none'
                    }}>
                      {item.icon}
                    </ListItemIcon>

                    {isHovered && (
                      <>
                        <ListItemText
                          primary={
                            <Typography variant="body2" sx={{
                              fontWeight: 600,
                              color: isActive ? theme.palette.primary.main : alpha(theme.palette.text.primary, 0.6),
                              fontSize: '0.85rem'
                            }}>
                              {item.title}
                            </Typography>
                          }
                        />
                        {hasChildren && (
                          isOpen ? <ChevronDown size={14} style={{ opacity: 0.5 }} /> : <ChevronRight size={14} style={{ opacity: 0.5 }} />
                        )}
                      </>
                    )}
                  </ListItemButton>
                </ListItem>

                {hasChildren && isHovered && (
                  <Collapse in={isOpen} timeout="auto" unmountOnExit>
                    <List component="div" disablePadding sx={{ ml: 2 }}>
                      {item.children?.map((child) => {
                        const isChildActive = activePath === child.path;
                        const subActiveColor = isLight ? theme.palette.primary.main : tokens.severity.unknown;
                        const subInactiveColor = theme.palette.text.secondary;
                        return (
                          <ListItemButton
                            key={child.title}
                            component={Link}
                            to={child.path}
                            onClick={() => setOpenItems([])}
                            sx={{
                              py: 0.5,
                              borderRadius: 1,
                              mb: 0.2,
                              bgcolor: isChildActive ? alpha(theme.palette.primary.main, 0.1) : 'transparent',
                              '&:hover': {
                                bgcolor: alpha(theme.palette.primary.main, 0.05),
                              }
                            }}
                          >
                            <ListItemText
                              primary={
                                <Typography variant="caption" sx={{
                                  fontWeight: isChildActive ? 700 : 500,
                                  color: isChildActive ? subActiveColor : subInactiveColor,
                                  fontSize: '0.75rem',
                                  letterSpacing: 0.5
                                }}>
                                  {child.title}
                                </Typography>
                              }
                            />
                          </ListItemButton>
                        );
                      })}
                    </List>
                  </Collapse>
                )}
              </React.Fragment>
            );
          })}
        </List>
      </Drawer>

      <Box sx={{ flexGrow: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
        {/* Floating Topbar */}
        <AppBar position="fixed" sx={{
          bgcolor: alpha(theme.palette.background.paper, 0.95),
          backdropFilter: 'blur(12px)',
          border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
          borderRadius: 4,
          mt: 1.5,
          mx: 2,
          width: 'calc(100% - 32px)',
          boxShadow: theme.shadows[8],
          backgroundImage: 'none',
          zIndex: theme.zIndex.drawer + 1
        }}>
          <Toolbar sx={{ px: '16px !important', minHeight: '64px !important' }}>
            {/* Logo Section */}
            <Box sx={{ display: 'flex', alignItems: 'center', mr: 4 }}>
              <Typography variant="h6" sx={{
                fontWeight: 900,
                fontFamily: "'Bangers', cursive",
                letterSpacing: 2,
                color: '#d846cb !important', /* #db4224 */
                textShadow: "#8018c7c2 0px 0px 21px !important",
                fontSize: '1.4rem',
                mr: 1.5,
                ml: 12,
                textTransform: 'lowercase'
              }}>
                r3ngine
              </Typography>
              {version && (
                <Chip
                  label={version}
                  size="small"
                  sx={{
                    height: 18,
                    fontSize: '0.6rem',
                    fontWeight: 800,
                    bgcolor: 'transparent',
                    border: '1px solid #8c2a83 !important',
                    color: '#d846cb !important',
                    borderRadius: 1
                  }}
                />
              )}
            </Box>

            {/* Center: TOR exit IP (visible only when TOR mode is active) */}
            <Box sx={{ flexGrow: 1, display: 'flex', justifyContent: 'center', alignItems: 'center' }}>
              {torActive && (
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                  <Typography sx={{
                    fontWeight: 900,
                    fontFamily: "'Bangers', cursive",
                    letterSpacing: 2,
                    color: '#ff4d6d',
                    textShadow: '#8b000080 0px 0px 14px',
                    fontSize: '1.2rem',
                    textTransform: 'uppercase',
                  }}>
                    IP: {torExitIP?.ip ?? '···'}
                  </Typography>
                </Box>
              )}
            </Box>

            {/* Action Group */}
            <Box sx={{ display: 'flex', alignItems: 'center', gap: isMobileHeader ? 1 : 3, backgroundColor: "transparent" }}>
              {/* Universal Search */}
              <Box sx={{
                display: 'flex',
                alignItems: 'center',
                bgcolor: isLight ? alpha(theme.palette.text.primary, 0.05) : alpha(theme.palette.text.primary, 0.03),
                px: 2,
                py: 0.5,
                borderRadius: 10,
                width: isMobileHeader ? 180 : 240,
                border: `1px solid ${theme.palette.divider}`,
                '&:hover': { borderColor: alpha(theme.palette.primary.main, 0.3) }
              }}>
                <InputBase
                  placeholder="Universal Search..."
                  sx={{ color: theme.palette.text.secondary, fontSize: '0.75rem', flex: 1, ml: 1 }}
                />
                <Search size={14} style={{ color: theme.palette.primary.main, opacity: 0.8 }} />
              </Box>

              {!isMobileHeader ? (
                <>
                  <Box
                    component={Link}
                    to={`/${projectSlug}/projects`}
                    sx={{ display: 'flex', alignItems: 'center', cursor: 'pointer', gap: 0.5, textDecoration: 'none' }}
                  >
                    <Typography variant="body2" sx={{ fontSize: '0.8rem', color: theme.palette.text.secondary }}>Projects</Typography>
                    <ChevronDown size={14} style={{ opacity: 0.5, color: theme.palette.text.secondary }} />
                  </Box>

                  <Box
                    onClick={handleQuickAddOpen}
                    sx={{ display: 'flex', alignItems: 'center', cursor: 'pointer', gap: 0.5 }}
                  >
                    <Plus size={14} style={{ opacity: 0.6, color: theme.palette.text.secondary }} />
                    <Typography variant="body2" sx={{ fontSize: '0.8rem', color: theme.palette.text.secondary }}>Quick Add</Typography>
                    <ChevronDown size={14} style={{ opacity: 0.5, color: theme.palette.text.secondary }} />
                  </Box>

                  <Box sx={{ display: 'flex', gap: 1, mx: 2 }}>
                    <HeaderThemeSwitcher />
                    <IconButton
                      onClick={handleToolboxOpen}
                      size="small"
                      sx={{
                        color: toolboxAnchorEl ? theme.palette.primary.main : alpha(theme.palette.text.secondary, 0.5),
                        bgcolor: toolboxAnchorEl ? alpha(theme.palette.primary.main, 0.1) : 'transparent',
                        boxShadow: toolboxAnchorEl && theme.palette.mode === 'dark' ? `0 0 15px ${alpha(theme.palette.primary.main, 0.3)}` : 'none',
                        '&:hover': {
                          color: theme.palette.primary.main,
                          bgcolor: alpha(theme.palette.primary.main, 0.05),
                        }
                      }}
                    >
                      <LayoutGrid size={18} />
                    </IconButton>
                    <IconButton
                      onClick={handleNotificationOpen}
                      size="small"
                      sx={{
                        color: notificationAnchorEl ? theme.palette.primary.main : alpha(theme.palette.text.secondary, 0.5),
                        bgcolor: notificationAnchorEl ? alpha(theme.palette.primary.main, 0.1) : 'transparent',
                        '&:hover': {
                          color: theme.palette.primary.main,
                          bgcolor: alpha(theme.palette.primary.main, 0.05),
                        }
                      }}
                    >
                      <Badge badgeContent={unreadData?.count} color="error" sx={{ '& .MuiBadge-badge': { fontSize: '0.6rem', height: 16, minWidth: 16 } }}>
                        <Bell size={18} />
                      </Badge>
                    </IconButton>
                    <IconButton
                      onClick={handleScanHistoryOpen}
                      size="small"
                      sx={{
                        color: scanHistoryAnchorEl ? theme.palette.primary.main : alpha(theme.palette.text.secondary, 0.5),
                        bgcolor: scanHistoryAnchorEl ? alpha(theme.palette.primary.main, 0.1) : 'transparent',
                        '&:hover': {
                          color: theme.palette.primary.main,
                          bgcolor: alpha(theme.palette.primary.main, 0.05),
                        }
                      }}
                    >
                      <Badge badgeContent={unreadData?.count} color="error" sx={{ '& .MuiBadge-badge': { fontSize: '0.6rem', height: 16, minWidth: 16 } }}>
                        <ScanEyeIcon size={18} />
                      </Badge>
                    </IconButton>
                    <Box
                      sx={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: 0.75,
                        px: isMobileHeader ? 1 : 1.25,
                        py: 0.6,
                        borderRadius: 999,
                        border: `1px solid ${proxyIndicator.border}`,
                        bgcolor: proxyIndicator.bg,
                        color: proxyIndicator.fg,
                        minWidth: isMobileHeader ? 'auto' : 96,
                        cursor: 'default',
                      }}
                    >
                      <ShieldAlert size={14} />
                      <Typography
                        variant="caption"
                        sx={{
                          color: 'inherit',
                          fontWeight: 800,
                          letterSpacing: 0.7,
                          fontSize: isMobileHeader ? '0.62rem' : '0.68rem',
                        }}
                      >
                        {isMobileHeader ? validProxyCount : proxyIndicator.label}
                      </Typography>
                    </Box>
                  </Box>

                  <Box sx={{ display: 'flex', alignItems: 'center', cursor: 'pointer', ml: 1 }} onClick={handleMenuOpen}>
                    <Avatar
                      src="https://api.dicebear.com/7.x/bottts-neutral/svg?seed=hacker&backgroundColor=transparent"
                      sx={{
                        width: 32,
                        height: 32,
                        bgcolor: alpha(theme.palette.text.primary, 0.05),
                        border: `1px solid ${alpha(theme.palette.primary.main, 0.3)}`,
                        p: 0.2
                      }}
                    />
                    <Box sx={{ ml: 1, display: 'flex', alignItems: 'center' }}>
                      <Typography variant="body2" sx={{ fontWeight: 600, fontSize: '0.8rem', color: theme.palette.text.primary }}>root</Typography>
                      <ChevronDown size={14} style={{ opacity: 0.4, marginLeft: 4, color: theme.palette.text.secondary }} />
                    </Box>
                  </Box>
                </>
              ) : (
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <Box
                    sx={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: 0.6,
                      px: 1,
                      py: 0.55,
                      borderRadius: 999,
                      border: `1px solid ${proxyIndicator.border}`,
                      bgcolor: proxyIndicator.bg,
                      color: proxyIndicator.fg,
                      cursor: 'default',
                    }}
                  >
                    <ShieldAlert size={13} />
                    <Typography
                      variant="caption"
                      sx={{
                        color: 'inherit',
                        fontWeight: 800,
                        letterSpacing: 0.6,
                        fontSize: '0.62rem',
                      }}
                    >
                      {validProxyCount}
                    </Typography>
                  </Box>
                  <IconButton
                    onClick={() => setMobileMenuOpen(true)}
                    sx={{
                      color: alpha(theme.palette.primary.main, 0.8),
                      bgcolor: alpha(theme.palette.primary.main, 0.05),
                      border: `1px solid ${alpha(theme.palette.primary.main, 0.1)}`,
                      '&:hover': {
                        bgcolor: alpha(theme.palette.primary.main, 0.1),
                        color: theme.palette.primary.main,
                      }
                    }}
                  >
                    <MenuIcon size={20} />
                  </IconButton>
                </Box>
              )}
            </Box>

            <Menu
              anchorEl={quickAddAnchorEl}
              open={Boolean(quickAddAnchorEl)}
              onClose={handleQuickAddClose}
              slotProps={{
                paper: {
                  sx: {
                    ...getMenuPaperSx(isLight, theme, tokens),
                    minWidth: 200,
                    mt: 1.5,
                    '& .MuiMenuItem-root': {
                      py: 1.5,
                      px: 2.5,
                      gap: 2,
                      color: tokens.text.primary,
                      fontFamily: 'var(--r3-heading-font)',
                      fontSize: '0.75rem',
                      letterSpacing: '1px',
                      '&:hover': {
                        bgcolor: isLight ? alpha(tokens.accent.primary, 0.08) : alpha(tokens.accent.primary, 0.15),
                        color: tokens.accent.primary,
                      }
                    }
                  }
                }
              }}
              transformOrigin={{ horizontal: 'right', vertical: 'top' }}
              anchorOrigin={{ horizontal: 'right', vertical: 'bottom' }}
            >
              {quickAddItems.map((item) => (
                <MenuItem
                  key={item.title}
                  component={Link}
                  to={item.path}
                  onClick={handleQuickAddClose}
                  sx={{ textDecoration: 'none' }}
                >
                  <Box sx={{ display: 'flex', color: 'inherit' }}>{item.icon}</Box>
                  <Typography sx={{ fontSize: 'inherit', fontFamily: 'inherit', fontWeight: 600 }}>
                    {item.title}
                  </Typography>
                </MenuItem>
              ))}
            </Menu>

            <Menu
              anchorEl={toolboxAnchorEl}
              open={Boolean(toolboxAnchorEl)}
              onClose={handleToolboxClose}
              slotProps={{
                paper: {
                  sx: {
                    ...getMenuPaperSx(isLight, theme, tokens),
                    borderRadius: 3,
                    p: 2.5,
                    width: 320,
                    mt: 1.5,
                    overflow: 'hidden',
                    '&::before': {
                      content: '""',
                      position: 'absolute',
                      top: 0,
                      left: 0,
                      right: 0,
                      height: '2px',
                      background: isLight
                        ? `linear-gradient(90deg, ${theme.palette.primary.main}, ${theme.palette.secondary.main})`
                        : `linear-gradient(90deg, ${tokens.accent.primary}, ${tokens.accent.secondary})`,
                      zIndex: 1
                    }
                  }
                }
              }}
              transformOrigin={{ horizontal: 'right', vertical: 'top' }}
              anchorOrigin={{ horizontal: 'right', vertical: 'bottom' }}
            >
              <Box sx={{ px: 2, py: 1, mb: 1.5, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Typography sx={{
                  color: isLight ? theme.palette.primary.main : tokens.accent.secondary,
                  fontFamily: 'var(--r3-heading-font)',
                  fontSize: '0.75rem',
                  fontWeight: 900,
                  letterSpacing: '3px',
                  textShadow: isLight ? 'none' : '0 0 10px rgba(255, 0, 255, 0.5)'
                }}>
                  TOOLBOX
                </Typography>
                <Box sx={{ width: 40, height: 1, bgcolor: isLight ? theme.palette.divider : 'rgba(255,0,255,0.2)' }} />
              </Box>
              <Grid container spacing={2}>
                {toolboxItems.map((item) => (
                  <Grid size={{ xs: 6 }} key={item.title}>
                    <Box
                      onClick={() => handleToolClick(item.id)}
                      sx={{
                        display: 'flex',
                        flexDirection: 'column',
                        alignItems: 'center',
                        justifyContent: 'center',
                        p: 2.5,
                        borderRadius: 2,
                        cursor: 'pointer',
                        transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
                        border: '1px solid transparent',
                        '&:hover': {
                          bgcolor: isLight ? alpha(tokens.accent.primary, 0.08) : alpha(tokens.text.primary, 0.03),
                          borderColor: isLight ? alpha(tokens.accent.primary, 0.2) : tokens.border.subtle,
                          transform: 'translateY(-4px)',
                          boxShadow: isLight ? `0 4px 20px ${alpha(tokens.accent.primary, 0.15)}` : `0 4px 20px ${alpha(item.color, 0.15)}`,
                          '& .icon-box': {
                            color: isLight ? tokens.accent.primary : item.color,
                            filter: isLight ? 'none' : `drop-shadow(0 0 12px ${alpha(item.color, 0.8)})`
                          },
                          '& .item-text': {
                            color: isLight ? tokens.accent.primary : theme.palette.text.primary,
                            textShadow: isLight ? 'none' : `0 0 8px ${alpha(item.color, 0.67)}`
                          }
                        }
                      }}
                    >
                      <Box
                        className="icon-box"
                        sx={{
                          mb: 2,
                          color: tokens.text.secondary,
                          transition: 'all 0.3s',
                          display: 'flex',
                          transform: 'scale(1)',
                          '& svg': {
                            filter: isLight ? 'none' : `drop-shadow(0 0 2px ${alpha(tokens.text.primary, 0.1)})`
                          }
                        }}
                      >
                        {item.icon}
                      </Box>
                      <Typography className="item-text" sx={{
                        fontSize: '0.7rem',
                        color: tokens.text.muted,
                        fontFamily: 'var(--r3-heading-font)',
                        textAlign: 'center',
                        fontWeight: 700,
                        letterSpacing: '1.2px',
                        transition: 'all 0.3s',
                        textTransform: 'uppercase'
                      }}>
                        {item.title}
                      </Typography>
                    </Box>
                  </Grid>
                ))}
              </Grid>
            </Menu>

            <WhoisModal open={openTool === 'whois'} onClose={() => setOpenTool(null)} />
            <CMSDetectorModal open={openTool === 'cms'} onClose={() => setOpenTool(null)} />
            <CVELookupModal open={openTool === 'cve'} onClose={() => setOpenTool(null)} />
            <WAFDetectorModal open={openTool === 'waf'} onClose={() => setOpenTool(null)} />

            <NotificationsDropdown
              anchorEl={notificationAnchorEl}
              onClose={handleNotificationClose}
              projectSlug={projectSlug}
            />

            <ScanHistoryDrawer
              open={scanHistoryOpen}
              onClose={() => setScanHistoryOpen(false)}
              projectSlug={projectSlug}
            />

            <Snackbar
              open={proxyWarningOpen}
              autoHideDuration={8000}
              onClose={() => setProxyWarningOpen(false)}
              anchorOrigin={{ vertical: 'top', horizontal: 'right' }}
            >
              <Alert
                severity="warning"
                onClose={() => setProxyWarningOpen(false)}
                action={(
                  <Button
                    component={Link}
                    to={`/${projectSlug}/settings/proxies`}
                    size="small"
                    color="inherit"
                    sx={{ fontWeight: 700 }}
                  >
                    Open Proxies
                  </Button>
                )}
                sx={{
                  alignItems: 'center',
                  bgcolor: theme.palette.background.paper,
                  color: theme.palette.text.primary,
                  border: `1px solid ${alpha(tokens.accent.warning, 0.3)}`,
                }}
              >
                Very few proxies remain in the pool ({validProxyCount} left).
              </Alert>
            </Snackbar>

            <CheckForUpdateModal
              open={updateModalOpen}
              onClose={() => setUpdateModalOpen(false)}
              onUpdateFound={setUpdateAvailable}
            />

            {/* Mobile Header Menu Drawer */}
            <Drawer
              anchor="right"
              open={mobileMenuOpen}
              onClose={() => setMobileMenuOpen(false)}
              slotProps={{
                paper: {
                  sx: {
                    width: 300,
                    bgcolor: alpha(theme.palette.background.paper, 0.8),
                    backdropFilter: 'blur(25px)',
                    borderLeft: `1px solid ${alpha(theme.palette.primary.main, 0.2)}`,
                    boxShadow: `-10px 0 30px ${alpha('#000', 0.5)}`,
                    backgroundImage: 'none',
                    display: 'flex',
                    flexDirection: 'column',
                    overflow: 'hidden'
                  }
                }
              }}
            >
              {/* Drawer Header */}
              <Box sx={{
                p: 3,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                borderBottom: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
                bgcolor: alpha(theme.palette.primary.main, 0.03)
              }}>
                <Typography sx={{
                  fontFamily: 'Orbitron',
                  fontWeight: 900,
                  fontSize: '0.9rem',
                  letterSpacing: '2px',
                  color: theme.palette.primary.main,
                  textShadow: `0 0 10px ${alpha(theme.palette.primary.main, 0.3)}`
                }}>
                  NAVIGATION
                </Typography>
                <IconButton onClick={() => setMobileMenuOpen(false)} size="small" sx={{ color: alpha(theme.palette.text.primary, 0.5) }}>
                  <X size={20} />
                </IconButton>
              </Box>

              {/* Drawer Content */}
              <Box sx={{ flex: 1, overflowY: 'auto', p: 2, display: 'flex', flexDirection: 'column', gap: 1 }}>
                {/* Profile Section */}
                <Box sx={{
                  p: 2,
                  mb: 2,
                  borderRadius: 3,
                  bgcolor: alpha(theme.palette.primary.main, 0.05),
                  border: `1px solid ${alpha(theme.palette.primary.main, 0.1)}`,
                  display: 'flex',
                  alignItems: 'center',
                  gap: 2,
                  cursor: 'pointer',
                  '&:hover': { bgcolor: alpha(theme.palette.primary.main, 0.08) }
                }} onClick={(e) => { handleMenuOpen(e); setMobileMenuOpen(false); }}>
                  <Avatar
                    src="https://api.dicebear.com/7.x/bottts-neutral/svg?seed=hacker&backgroundColor=transparent"
                    sx={{
                      width: 48,
                      height: 48,
                      bgcolor: alpha(theme.palette.text.primary, 0.05),
                      border: `1px solid ${alpha(theme.palette.primary.main, 0.3)}`,
                      p: 0.2
                    }}
                  />
                  <Box>
                    <Typography sx={{ fontWeight: 800, fontSize: '1rem', color: theme.palette.text.primary }}>root</Typography>
                    <Typography sx={{ fontSize: '0.7rem', color: alpha(theme.palette.text.primary, 0.5) }}>Administrator</Typography>
                  </Box>
                  <ChevronRight size={16} style={{ marginLeft: 'auto', opacity: 0.5 }} />
                </Box>

                <Typography variant="caption" sx={{ px: 2, mb: 1, color: alpha(theme.palette.text.primary, 0.3), fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase' }}>
                  Quick Actions
                </Typography>

                <ListItemButton
                  component={Link}
                  to={`/${projectSlug}/projects`}
                  onClick={() => setMobileMenuOpen(false)}
                  sx={{ borderRadius: 2, py: 1.5 }}
                >
                  <ListItemIcon sx={{ color: theme.palette.primary.main }}><Folder size={20} /></ListItemIcon>
                  <ListItemText primary={<Typography sx={{ fontWeight: 600, fontSize: '0.9rem' }}>Projects</Typography>} />
                </ListItemButton>

                <ListItemButton
                  onClick={(e) => { handleQuickAddOpen(e); setMobileMenuOpen(false); }}
                  sx={{ borderRadius: 2, py: 1.5 }}
                >
                  <ListItemIcon sx={{ color: theme.palette.primary.main }}><Plus size={20} /></ListItemIcon>
                  <ListItemText primary={<Typography sx={{ fontWeight: 600, fontSize: '0.9rem' }}>Quick Add</Typography>} />
                </ListItemButton>

                <Divider sx={{ my: 2, opacity: 0.1 }} />

                <Typography variant="caption" sx={{ px: 2, mb: 1, color: alpha(theme.palette.text.primary, 0.3), fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase' }}>
                  Tools & Utilities
                </Typography>

                <Box sx={{ display: 'flex', gap: 2, px: 1, mb: 2 }}>
                  <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 1 }}>
                    <HeaderThemeSwitcher />
                    <Typography variant="caption" sx={{ fontSize: '0.6rem', fontWeight: 600 }}>Theme</Typography>
                  </Box>
                  <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 1 }}>
                    <IconButton
                      onClick={(e) => { handleToolboxOpen(e); setMobileMenuOpen(false); }}
                      sx={{
                        bgcolor: alpha(theme.palette.primary.main, 0.1),
                        color: theme.palette.primary.main,
                        width: 48,
                        height: 48
                      }}
                    >
                      <LayoutGrid size={20} />
                    </IconButton>
                    <Typography variant="caption" sx={{ fontSize: '0.6rem', fontWeight: 600 }}>Toolbox</Typography>
                  </Box>
                  <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 1 }}>
                    <IconButton
                      onClick={(e) => { handleNotificationOpen(e); setMobileMenuOpen(false); }}
                      sx={{
                        bgcolor: alpha(theme.palette.primary.main, 0.1),
                        color: theme.palette.primary.main,
                        width: 48,
                        height: 48
                      }}
                    >
                      <Badge badgeContent={unreadData?.count} color="error">
                        <Bell size={20} />
                      </Badge>
                    </IconButton>
                    <Typography variant="caption" sx={{ fontSize: '0.6rem', fontWeight: 600 }}>Alerts</Typography>
                  </Box>
                </Box>
              </Box>

              {/* Drawer Footer */}
              <Box sx={{ p: 3, borderTop: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
                <Button
                  fullWidth
                  variant="outlined"
                  color="error"
                  startIcon={<LogOut size={16} />}
                  href="/logout"
                  sx={{
                    borderRadius: 2,
                    borderColor: alpha(theme.palette.error.main, 0.3),
                    '&:hover': { bgcolor: alpha(theme.palette.error.main, 0.1) }
                  }}
                >
                  Logout
                </Button>
              </Box>
            </Drawer>

            <Menu
              anchorEl={anchorEl}
              open={Boolean(anchorEl)}
              onClose={handleMenuClose}
              slotProps={{
                paper: {
                  sx: {
                    ...getMenuPaperSx(isLight, theme, tokens),
                    minWidth: 240,
                    mt: 1.5,
                    overflow: 'hidden',
                    '& .MuiMenuItem-root': {
                      py: 1.5,
                      px: 2.5,
                      gap: 2,
                      color: theme.palette.text.secondary,
                      fontFamily: 'var(--r3-heading-font)',
                      fontSize: '0.75rem',
                      letterSpacing: '1px',
                      transition: 'all 0.2s',
                      '&:hover': {
                        bgcolor: alpha(tokens.accent.primary, 0.1),
                        color: tokens.accent.primary,
                        '& .menu-icon': {
                          color: tokens.accent.primary,
                          filter: isCyber ? `drop-shadow(0 0 5px ${tokens.accent.primary}aa)` : 'none',
                        }
                      }
                    }
                  }
                }
              }}
              transformOrigin={{ horizontal: 'right', vertical: 'top' }}
              anchorOrigin={{ horizontal: 'right', vertical: 'bottom' }}
            >
              <Box sx={{ px: 2.5, py: 1.5, borderBottom: `1px solid ${theme.palette.divider}`, mb: 1 }}>
                <Typography sx={{ fontSize: '0.7rem', color: theme.palette.text.secondary, fontWeight: 600, letterSpacing: 0.5 }}>
                  Welcome root!
                </Typography>
              </Box>

              <MenuItem onClick={handleMenuClose} component={Link} to={`/${projectSlug}/settings/profile`}>
                <UserIcon size={16} className="menu-icon" style={{ transition: 'all 0.2s' }} />
                <Typography sx={{ fontSize: 'inherit', fontFamily: 'inherit', fontWeight: 600 }}>My Account</Typography>
              </MenuItem>

              <MenuItem onClick={handleMenuClose}>
                <Target size={16} className="menu-icon" style={{ transition: 'all 0.2s' }} />
                <Typography sx={{ fontSize: 'inherit', fontFamily: 'inherit', fontWeight: 600 }}>Disable Bug Bounty Mode</Typography>
              </MenuItem>

              <MenuItem onClick={handleMenuClose} component={Link} to={`/${projectSlug}/settings/admin`}>
                <Settings size={16} className="menu-icon" style={{ transition: 'all 0.2s' }} />
                <Typography sx={{ fontSize: 'inherit', fontFamily: 'inherit', fontWeight: 600 }}>Admin Settings</Typography>
              </MenuItem>

              <Divider sx={{ bgcolor: theme.palette.divider, my: 1 }} />

              <MenuItem onClick={handleUpdateCheckClick}>
                <RefreshCw size={16} className="menu-icon" style={{ transition: 'all 0.2s' }} />
                <Box sx={{ display: 'flex', flexDirection: 'column' }}>
                  <Typography sx={{ fontSize: 'inherit', fontFamily: 'inherit', fontWeight: 600 }}>Check reNgine Update</Typography>
                  {updateAvailable && (
                    <Typography sx={{ fontSize: '0.6rem', color: tokens.accent.error, fontWeight: 800 }}>Update Available!</Typography>
                  )}
                </Box>
              </MenuItem>

              <Divider sx={{ bgcolor: theme.palette.divider, my: 1 }} />

              <MenuItem
                onClick={handleMenuClose}
                component="a"
                href="/logout"
                sx={{ '&:hover': { color: `${tokens.accent.error} !important`, bgcolor: `${alpha(tokens.accent.error, 0.1)} !important` } }}
              >
                <LogOut size={16} className="menu-icon" style={{ transition: 'all 0.2s' }} />
                <Typography sx={{ fontSize: 'inherit', fontFamily: 'inherit', fontWeight: 600 }}>Logout</Typography>
              </MenuItem>
            </Menu>
          </Toolbar>
        </AppBar>

        {/* Page Content */}
        <Box
          component="main"
          sx={{
            flexGrow: 1,
            pt: 12,
            px: { xs: 1, md: 3 },
            pb: 4,
            overflowX: 'hidden',
            overflowY: 'auto',
            position: 'relative',
            width: '100%',
            minWidth: 0
          }}
        >
          <Box sx={{ position: 'relative', zIndex: 1, width: '100%', minWidth: 0 }}>
            {children}
          </Box>
        </Box>
      </Box>
    </Box>
  );
};
