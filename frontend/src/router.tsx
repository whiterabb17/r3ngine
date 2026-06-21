import { createRootRouteWithContext, createRoute, createRouter, Outlet, Link, redirect, lazyRouteComponent, useParams } from "@tanstack/react-router";
import { Shell } from "./components/Shell";
// Lazy loaded components below

import { Box, Typography, Button, CircularProgress } from "@mui/material";
import PluginPageLoader from './features/plugins/components/PluginPageLoader';
import { useQuery } from '@tanstack/react-query';
import axios from 'axios';
import { AlertCircle, Home, RefreshCw } from "lucide-react";
import { useRouterState } from "@tanstack/react-router";
import { LoginPage } from "./features/auth/components/LoginPage";
import { LogoutPage } from "./features/auth/components/LogoutPage";
import { OnboardingPage } from "./features/auth/components/OnboardingPage";

// Lazy Routes
const DashboardPage = lazyRouteComponent(() => import("./features/dashboard").then(m => ({ default: m.DashboardPage })));
const ProjectsPage = lazyRouteComponent(() => import("./features/projects").then(m => ({ default: m.ProjectsPage })));
const MonitoringPage = lazyRouteComponent(() => import("./features/monitoring").then(m => ({ default: m.MonitoringPage })));
const EnginesPage = lazyRouteComponent(() => import("./features/engines").then(m => ({ default: m.EnginesPage })));
const OrganizationPage = lazyRouteComponent(() => import("./features/organizations").then(m => ({ default: m.OrganizationPage })));
const TargetList = lazyRouteComponent(() => import("./features/targets").then(m => ({ default: m.TargetList })));
const TargetSummary = lazyRouteComponent(() => import("./features/targets").then(m => ({ default: m.TargetSummary })));
const EndpointsPage = lazyRouteComponent(() => import("./features/endpoints").then(m => ({ default: m.EndpointsPage })));
const SubdomainsPage = lazyRouteComponent(() => import("./features/subdomains").then(m => ({ default: m.SubdomainsPage })));
const TodoPage = lazyRouteComponent(() => import("./features/todos").then(m => ({ default: m.TodoPage })));
const VulnerabilityList = lazyRouteComponent(() => import("./features/vulnerabilities").then(m => ({ default: m.VulnerabilityList })));
const BountyHubPage = lazyRouteComponent(() => import("./features/bounty/components/BountyHubPage").then(m => ({ default: m.BountyHubPage })));
const SearchPage = lazyRouteComponent(() => import("./features/search/components/SearchPage").then(m => ({ default: m.SearchPage })));
const PluginManagementPage = lazyRouteComponent(() => import("./features/plugins/pages/PluginManagementPage").then(m => ({ default: m.default })));

// Scan Feature Lazy Routes
const ScheduledScansPage = lazyRouteComponent(() => import("./features/scans/components/ScheduledScansPage").then(m => ({ default: m.ScheduledScansPage })));
const SubScansPage = lazyRouteComponent(() => import("./features/scans/components/SubScansPage").then(m => ({ default: m.SubScansPage })));
const ScanHistoryPage = lazyRouteComponent(() => import("./features/scans/components/ScanHistoryPage").then(m => ({ default: m.ScanHistoryPage })));
const ScanDetailPage = lazyRouteComponent(() => import("./features/scans/components/ScanDetailPage").then(m => ({ default: m.ScanDetailPage })));
const AttackSurfacePage = lazyRouteComponent(() => import("./features/scans/components/AttackSurfacePage").then(m => ({ default: m.AttackSurfacePage })));

// Settings Feature Lazy Routes
const ProxySettingsPage = lazyRouteComponent(() => import("./features/settings").then(m => ({ default: m.ProxySettingsPage })));
const OpSecSettingsPage = lazyRouteComponent(() => import("./features/settings").then(m => ({ default: m.OpSecSettingsPage })));
const ToolSettingsPage = lazyRouteComponent(() => import("./features/settings").then(m => ({ default: m.ToolSettingsPage })));
const ToolArsenalPage = lazyRouteComponent(() => import("./features/settings").then(m => ({ default: m.ToolArsenalPage })));
const ApiVaultPage = lazyRouteComponent(() => import("./features/settings").then(m => ({ default: m.ApiVaultPage })));
const LlmToolkitPage = lazyRouteComponent(() => import("./features/settings").then(m => ({ default: m.LlmToolkitPage })));
const ReportSettingsPage = lazyRouteComponent(() => import("./features/settings").then(m => ({ default: m.ReportSettingsPage })));
const ReNgineSettingsPage = lazyRouteComponent(() => import("./features/settings").then(m => ({ default: m.ReNgineSettingsPage })));
const NotificationSettingsPage = lazyRouteComponent(() => import("./features/settings").then(m => ({ default: m.NotificationSettingsPage })));
const ProfileSettingsPage = lazyRouteComponent(() => import("./features/settings").then(m => ({ default: m.ProfileSettingsPage })));
const AdminSettingsPage = lazyRouteComponent(() => import("./features/settings").then(m => ({ default: m.AdminSettingsPage })));
const StressTestingPage = lazyRouteComponent(() => import("./pages/StressTestingPage").then(m => ({ default: m.StressTestingPage })));

interface RouterContext {
  auth: {
    isAuthenticated: boolean;
    isLoading: boolean;
    user: any;
  };
}

// Root Route
const rootRoute = createRootRouteWithContext<RouterContext>()({
  beforeLoad: ({ context, location }) => {
    const isAuthPage = location.pathname.startsWith('/login') ||
      location.pathname.startsWith('/logout') ||
      location.pathname.startsWith('/onboarding');

    if (!context.auth.isAuthenticated && !isAuthPage && !context.auth.isLoading) {
      throw redirect({
        to: '/login',
        search: {
          redirect: location.href,
        },
      });
    }
  },
  component: () => {
    const routerState = useRouterState();
    const isAuthPage = routerState.location.pathname.startsWith('/login') ||
      routerState.location.pathname.startsWith('/logout') ||
      routerState.location.pathname.startsWith('/onboarding');

    if (isAuthPage) {
      return <Outlet />;
    }

    return (
      <Shell>
        <Outlet />
      </Shell>
    );
  },
  notFoundComponent: () => <NotFound />,
  errorComponent: (props) => <ErrorComponent {...props} />,
});

// Project-specific layout route
const projectRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "$projectSlug",
});

const projectsRoute = createRoute({
  getParentRoute: () => projectRoute,
  path: "projects",
  component: ProjectsPage,
});


// Dashboard Route
const dashboardRoute = createRoute({
  getParentRoute: () => projectRoute,
  path: "dashboard",
  component: DashboardPage,
});

// Root to Dashboard redirect
const rootRedirectRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  component: DashboardPage,
});

// Targets Route
const targetListRoute = createRoute({
  getParentRoute: () => projectRoute,
  path: "targets",
  component: TargetList,
});

// Organizations Route
const organizationsRoute = createRoute({
  getParentRoute: () => projectRoute,
  path: "org",
  component: OrganizationPage,
});

// Target Summary Route
const targetSummaryRoute = createRoute({
  getParentRoute: () => projectRoute,
  path: "target/$targetId/summary",
  component: TargetSummary,
});

// Monitoring Route
const monitoringRoute = createRoute({
  getParentRoute: () => projectRoute,
  path: "monitoring",
  component: MonitoringPage,
});

// Engines Route
const enginesRoute = createRoute({
  getParentRoute: () => projectRoute,
  path: "engines",
  component: EnginesPage,
});

// Scans Route
const scansRoute = createRoute({
  getParentRoute: () => projectRoute,
  path: "scans",
  component: ScanHistoryPage,
  loader: async ({ params: { projectSlug } }) => {
    return { projectSlug };
  },
});

// Sub Scans Route
const subScansRoute = createRoute({
  getParentRoute: () => projectRoute,
  path: "scans/sub",
  component: SubScansPage,
  loader: async ({ params: { projectSlug } }) => {
    return { projectSlug };
  },
  pendingComponent: () => (
    <Box sx={{
      height: '80vh',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      gap: 3
    }}>
      <Box sx={{ display: 'flex', gap: 1 }}>
        <Box sx={{ width: 12, height: 12, borderRadius: '50%', bgcolor: '#00f3ff' }} />
        <Box sx={{ width: 12, height: 12, borderRadius: '50%', bgcolor: '#00f3ff' }} />
        <Box sx={{ width: 12, height: 12, borderRadius: '50%', bgcolor: '#00f3ff' }} />
      </Box>
      <Typography sx={{
        fontFamily: 'Orbitron',
        fontWeight: 900,
        letterSpacing: 2,
        fontSize: '14px',
        color: '#00f3ff',
        textAlign: 'center'
      }}>
        ACCESSING TACTICAL REGISTRY... <br />
        <span style={{ fontSize: '10px', opacity: 0.5, color: '#fff' }}>RETRIEVING SUB SCANS... PLEASE WAIT</span>
      </Typography>
      <style>
        {`
          @keyframes pulse {
            0%, 100% { transform: scale(1); opacity: 0.5; }
            50% { transform: scale(1.5); opacity: 1; }
          }
        `}
      </style>
    </Box>
  )
});

// Scheduled Scans Route
const scheduledScansRoute = createRoute({
  getParentRoute: () => projectRoute,
  path: "scans/scheduled",
  component: ScheduledScansPage,
  loader: async ({ params: { projectSlug } }) => {
    return { projectSlug };
  },
  pendingComponent: () => (
    <Box sx={{
      height: '80vh',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      gap: 3
    }}>
      <Box sx={{ display: 'flex', gap: 1 }}>
        <Box sx={{ width: 12, height: 12, borderRadius: '50%', bgcolor: '#00f3ff' }} />
        <Box sx={{ width: 12, height: 12, borderRadius: '50%', bgcolor: '#00f3ff' }} />
        <Box sx={{ width: 12, height: 12, borderRadius: '50%', bgcolor: '#00f3ff' }} />
      </Box>
      <Typography sx={{
        fontFamily: 'Orbitron',
        fontWeight: 900,
        letterSpacing: 2,
        fontSize: '14px',
        color: '#00f3ff',
        textAlign: 'center'
      }}>
        ACCESSING TACTICAL REGISTRY... <br />
        <span style={{ fontSize: '10px', opacity: 0.5, color: '#fff' }}>RETRIEVING SCHEDULED OPERATIONS... PLEASE WAIT</span>
      </Typography>
      {/* <style>
        {`
          @keyframes pulse {
            0%, 100% { transform: scale(1); opacity: 0.5; }
            50% { transform: scale(1.5); opacity: 1; }
          }
        `}
      </style> */}
    </Box>
  )
});

// All Subdomains Route
const subdomainsRoute = createRoute({
  getParentRoute: () => projectRoute,
  path: "subdomains",
  component: SubdomainsPage,
  loader: async ({ params: { projectSlug } }) => {
    // This triggers the pendingComponent while the initial fetch is happening
    // We don't necessarily need to return the data here since useQuery handles it,
    // but having a promise here ensures the "pending" state is active.
    return { projectSlug };
  },
  pendingComponent: () => (
    <Box sx={{
      height: '80vh',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      gap: 3
    }}>
      <Box sx={{ display: 'flex', gap: 1 }}>
        <Box sx={{ width: 12, height: 12, borderRadius: '50%', bgcolor: '#00f3ff' }} />
        <Box sx={{ width: 12, height: 12, borderRadius: '50%', bgcolor: '#00f3ff', opacity: 0.7 }} />
        <Box sx={{ width: 12, height: 12, borderRadius: '50%', bgcolor: '#00f3ff', opacity: 0.4 }} />
      </Box>
      <Typography sx={{
        fontFamily: 'Orbitron',
        fontWeight: 900,
        letterSpacing: 2,
        fontSize: '14px',
        color: '#00f3ff',
        textAlign: 'center'
      }}>
        INITIALIZING TACTICAL DATA... <br />
        <span style={{ fontSize: '10px', opacity: 0.5, color: '#fff' }}>FETCHING SUBDOMAINS... PLEASE WAIT</span>
      </Typography>
      {/* <style>
        {`
          @keyframes pulse {
            0%, 100% { transform: scale(1); opacity: 0.5; }
            50% { transform: scale(1.5); opacity: 1; }
          }
        `}
      </style> */}
    </Box>
  )
});

// All Endpoints Route
const endpointsRoute = createRoute({
  getParentRoute: () => projectRoute,
  path: "endpoints",
  component: EndpointsPage,
});

// Todo Route
const todoRoute = createRoute({
  getParentRoute: () => projectRoute,
  path: "todo",
  component: TodoPage,
});

// Settings Routes
const proxySettingsRoute = createRoute({
  getParentRoute: () => projectRoute,
  path: "settings/proxies",
  component: ProxySettingsPage,
});

const opsecSettingsRoute = createRoute({
  getParentRoute: () => projectRoute,
  path: "settings/opsec",
  component: OpSecSettingsPage,
});

const toolSettingsRoute = createRoute({
  getParentRoute: () => projectRoute,
  path: "settings/tool-settings",
  component: ToolSettingsPage,
});

const toolArsenalRoute = createRoute({
  getParentRoute: () => projectRoute,
  path: "settings/tools-arsenal",
  component: ToolArsenalPage,
});

const apiVaultSettingsRoute = createRoute({
  getParentRoute: () => projectRoute,
  path: "settings/api-vault",
  component: ApiVaultPage,
});

const llmToolkitSettingsRoute = createRoute({
  getParentRoute: () => projectRoute,
  path: "settings/llm-toolkit",
  component: LlmToolkitPage,
});

const reportSettingsRoute = createRoute({
  getParentRoute: () => projectRoute,
  path: "settings/report-settings",
  component: ReportSettingsPage,
});

const rengineSettingsRoute = createRoute({
  getParentRoute: () => projectRoute,
  path: "settings/rengine-settings",
  component: ReNgineSettingsPage,
});

const notificationSettingsRoute = createRoute({
  getParentRoute: () => projectRoute,
  path: "settings/notifications",
  component: NotificationSettingsPage,
});

const profileSettingsRoute = createRoute({
  getParentRoute: () => projectRoute,
  path: "settings/profile",
  component: ProfileSettingsPage,
});

const adminSettingsRoute = createRoute({
  getParentRoute: () => projectRoute,
  path: "settings/admin",
  component: AdminSettingsPage,
});




// Vulnerabilities Route
const vulnsRoute = createRoute({
  getParentRoute: () => projectRoute,
  path: "vulns",
  component: VulnerabilityList,
  loader: async ({ params: { projectSlug } }) => {
    // Add a slight delay to ensure the tactical spinner is visible and smooth
    await new Promise(resolve => setTimeout(resolve, 800));
    return { projectSlug };
  },
  pendingComponent: () => (
    <Box sx={{
      height: '80vh',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      gap: 3
    }}>
      <Box className="tactical-pulse-dots" sx={{ display: 'flex', gap: 1 }}>
        <Box sx={{ width: 12, height: 12, borderRadius: '50%', bgcolor: '#00f3ff' }} />
        <Box sx={{ width: 12, height: 12, borderRadius: '50%', bgcolor: '#00f3ff' }} />
        <Box sx={{ width: 12, height: 12, borderRadius: '50%', bgcolor: '#00f3ff' }} />
      </Box>
      <Typography sx={{
        fontFamily: 'Orbitron',
        fontWeight: 900,
        letterSpacing: 2,
        fontSize: '14px',
        color: '#00f3ff',
        textAlign: 'center'
      }}>
        INITIALIZING TACTICAL DATA... <br />
        <span style={{ fontSize: '10px', opacity: 0.5, color: '#fff' }}>FETCHING VULNERABILITIES... PLEASE WAIT</span>
      </Typography>
    </Box>
  )
});

const bountyHubRoute = createRoute({
  getParentRoute: () => projectRoute,
  path: "bountyhub",
  component: BountyHubPage,
});

const searchRoute = createRoute({
  getParentRoute: () => projectRoute,
  path: "search",
  validateSearch: (search: Record<string, unknown>) => {
    return {
      query: (search.query as string) || undefined,
    }
  },
  component: SearchPage,
});

// Scan History Detail Route
const scanDetailRoute = createRoute({
  getParentRoute: () => projectRoute,
  path: "scan/detail/$scanId",
  component: ScanDetailPage,
});

// Attack Surface Route
const attackSurfaceRoute = createRoute({
  getParentRoute: () => projectRoute,
  path: "attack_surface/$scanId",
  component: AttackSurfacePage,
});

// Stress Testing Route
const stressTestingRoute = createRoute({
  getParentRoute: () => projectRoute,
  path: "stress_testing/$scanId",
  component: StressTestingPage,
});

// Plugins Route
const pluginsRoute = createRoute({
  getParentRoute: () => projectRoute,
  path: "plugins",
  component: PluginManagementPage,
});

// Generic Dynamic Plugin Routes
const pluginMainRoute = createRoute({
  getParentRoute: () => projectRoute,
  path: "p/$pluginSlug",
  component: function PluginMainPage() {
    const { pluginSlug, projectSlug } = useParams({ strict: false });

    if (!pluginSlug) {
      return (
        <Box sx={{ p: 4, textAlign: 'center' }}>
          <Typography color="error" variant="body2">Invalid plugin slug parameter.</Typography>
        </Box>
      );
    }

    const { data: pluginsRegistry, isLoading, error } = useQuery<any[]>({
      queryKey: ['pluginsRegistry'],
      queryFn: async () => {
        const res = await axios.get('/api/plugins/registry/');
        return res.data;
      }
    });

    if (isLoading) {
      return (
        <Box sx={{ p: 10, display: 'flex', justifyContent: 'center' }}>
          <CircularProgress size={24} sx={{ color: '#00f3ff' }} />
        </Box>
      );
    }

    if (error || !pluginsRegistry) {
      return (
        <Box sx={{ p: 4, textAlign: 'center' }}>
          <Typography color="error" variant="body2">Failed to load plugin registry.</Typography>
        </Box>
      );
    }

    const normalizedSlug = pluginSlug.replace(/-/g, '_');
    const plugin = pluginsRegistry.find(p => p.slug === normalizedSlug || p.slug === pluginSlug);
    const entryExport = plugin?.components?.entry_export || 'IndexPage';

    return <PluginPageLoader pluginSlug={normalizedSlug} exportName={entryExport} projectSlug={projectSlug || 'default'} />;
  },
});

const pluginSubpageRoute = createRoute({
  getParentRoute: () => projectRoute,
  path: "p/$pluginSlug/$pageName",
  component: function PluginSubpage() {
    const { pluginSlug, pageName, projectSlug } = useParams({ strict: false });
    
    if (!pluginSlug || !pageName) {
      return (
        <Box sx={{ p: 4, textAlign: 'center' }}>
          <Typography color="error" variant="body2">Invalid plugin or page parameters.</Typography>
        </Box>
      );
    }
    
    const normalizedSlug = pluginSlug.replace(/-/g, '_');
    return <PluginPageLoader pluginSlug={normalizedSlug} exportName={pageName} projectSlug={projectSlug || 'default'} />;
  },
});

// Login Route
const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "login",
  component: LoginPage,
});

const logoutRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "logout",
  component: LogoutPage,
});

const onboardingRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "onboarding",
  component: OnboardingPage,
});

// Route Tree
const routeTree = rootRoute.addChildren([
  rootRedirectRoute,
  projectRoute.addChildren([
    projectsRoute,
    dashboardRoute,
    targetListRoute,
    targetSummaryRoute,
    monitoringRoute,
    enginesRoute,
    scheduledScansRoute,
    subScansRoute,
    scansRoute,
    scanDetailRoute,
    attackSurfaceRoute,
    stressTestingRoute,
    endpointsRoute,
    subdomainsRoute,
    todoRoute,
    organizationsRoute,
    vulnsRoute,
    profileSettingsRoute,
    proxySettingsRoute,
    opsecSettingsRoute,
    toolSettingsRoute,
    toolArsenalRoute,
    apiVaultSettingsRoute,
    llmToolkitSettingsRoute,
    reportSettingsRoute,
    rengineSettingsRoute,
    notificationSettingsRoute,
    adminSettingsRoute,
    bountyHubRoute,
    searchRoute,
    pluginsRoute,
    pluginMainRoute,
    pluginSubpageRoute,
  ]),
  loginRoute,
  logoutRoute,
  onboardingRoute,
]);

// Router Instance
export const router = createRouter({
  routeTree,
  context: {
    auth: undefined!, // This will be provided by the AuthProvider
  },
  defaultNotFoundComponent: () => <NotFound />,
  trailingSlash: 'never',
});

// Type safety
declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}

// Components
function NotFound() {
  return (
    <Box
      sx={{
        height: '80vh',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'center',
        alignItems: 'center',
        textAlign: 'center',
        background: 'radial-gradient(circle at center, rgba(255, 0, 60, 0.05) 0%, transparent 70%)',
      }}
    >
      <Box sx={{ position: 'relative', mb: 4 }}>
        <AlertCircle size={120} color="#ff003c" style={{ opacity: 0.8 }} />
        <Box sx={{
          position: 'absolute',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          boxShadow: '0 0 50px rgba(255, 0, 60, 0.3)',
          borderRadius: '50%'
        }} />
      </Box>

      <Typography variant="h1" sx={{
        fontFamily: 'Orbitron',
        fontWeight: 900,
        fontSize: { xs: '3rem', md: '5rem' },
        letterSpacing: 8,
        mb: 2,
        color: '#fff',
        textShadow: '0 0 20px rgba(255, 0, 60, 0.5)'
      }}>
        SIGNAL LOST
      </Typography>

      <Typography variant="h5" sx={{
        fontFamily: 'Orbitron',
        color: '#ff003c',
        mb: 4,
        letterSpacing: 2,
        fontWeight: 700
      }}>
        NOT FOUND
      </Typography>

      <Typography variant="body1" sx={{ color: 'rgba(255, 255, 255, 0.6)', maxWidth: 500, mb: 6, lineHeight: 1.8 }}>
        This page has not yet been migrated to the new interface.
      </Typography>

      <Box sx={{ display: 'flex', gap: 3 }}>
        <Button
          component={Link}
          to="/"
          variant="outlined"
          startIcon={<Home size={18} />}
          sx={{
            borderColor: 'rgba(255, 255, 255, 0.2)',
            color: '#fff',
            px: 4,
            py: 1.5,
            '&:hover': { borderColor: 'primary.main', bgcolor: 'rgba(0, 243, 255, 0.05)' }
          }}
        >
          RETURN TO DASHBOARD
        </Button>
        <Button
          onClick={() => window.location.reload()}
          variant="outlined"
          startIcon={<RefreshCw size={18} />}
          sx={{
            borderColor: '#ff003c',
            color: '#ff003c',
            px: 4,
            py: 1.5,
            '&:hover': { bgcolor: 'rgba(255, 0, 60, 0.1)', borderColor: '#ff003c' }
          }}
        >
          RECONNECT SIGNAL
        </Button>
      </Box>
    </Box>
  );
}

function ErrorComponent({ error, reset }: { error: Error; reset: () => void }) {
  return (
    <Box
      sx={{
        height: '80vh',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'center',
        alignItems: 'center',
        textAlign: 'center',
        p: 3
      }}
    >
      <AlertCircle size={80} color="#ff003c" style={{ marginBottom: 20 }} />
      <Typography variant="h3" sx={{ fontFamily: 'Orbitron', mb: 2, color: '#fff' }}>SYSTEM_CRASH</Typography>
      <Typography variant="body1" sx={{ color: 'rgba(255,255,255,0.7)', mb: 4, maxWidth: 600 }}>
        An unexpected error occurred in the tactical interface.
        Error: {error.message}
      </Typography>
      <Button
        variant="contained"
        onClick={reset}
        sx={{ bgcolor: '#ff003c', '&:hover': { bgcolor: '#cc0030' } }}
      >
        REBOOT INTERFACE
      </Button>
    </Box>
  );
}
