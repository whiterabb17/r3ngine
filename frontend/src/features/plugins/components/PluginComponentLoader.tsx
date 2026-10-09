import React, { useEffect, useState, Suspense } from 'react';
import { Box, CircularProgress, Typography } from '@mui/material';

/**
 * Props forwarded to a runtime-loaded plugin component. The host cannot know a plugin's prop
 * types, so context such as `projectSlug` / `scanId` is passed through as free-form values.
 */
export type PluginComponentProps = Record<string, unknown>;

interface Props {
  pluginSlug: string;
  componentFile: string;
  [key: string]: unknown;
}

interface PluginModule {
  default?: React.ComponentType<PluginComponentProps>;
}

const PluginComponentLoader: React.FC<Props> = ({ pluginSlug, componentFile, ...rest }) => {
  const [Component, setComponent] = useState<React.ComponentType<PluginComponentProps> | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const loadComponent = async () => {
      try {
        // The UI files are served at /media/plugins/{slug}/ui/{file}
        // We use a dynamic import which works in modern browsers for ESM
        const moduleUrl = `/media/plugins/${pluginSlug}/ui/${componentFile}?v=${Date.now()}`;
        const module: PluginModule = await import(/* @vite-ignore */ moduleUrl);
        
        const component = module.default;
        if (component) {
          setComponent(() => component);
        } else {
          setError('Plugin module does not have a default export.');
        }
      } catch (err) {
        console.error(`Failed to load plugin ${pluginSlug}:`, err);
        setError(`Failed to load plugin component: ${pluginSlug}`);
      }
    };

    loadComponent();
  }, [pluginSlug, componentFile]);

  if (error) {
    return (
      <Box sx={{ p: 4, textAlign: "center" }}>
        <Typography color="error">{error}</Typography>
      </Box>
    );
  }

  if (!Component) {
    return (
      <Box sx={{ p: 10, display: "flex", justifyContent: "center" }}>
        <CircularProgress size={24} />
      </Box>
    );
  }

  return (
    <Suspense fallback={<CircularProgress size={24} />}>
      <Component {...rest} />
    </Suspense>
  );
};

export default PluginComponentLoader;
