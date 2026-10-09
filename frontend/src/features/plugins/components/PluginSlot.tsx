import React from 'react';
import { usePlugins } from '../api/pluginsApi';
import PluginComponentLoader from './PluginComponentLoader';

interface PluginSlotProps {
  name: string;
  context?: Record<string, unknown>;
}

/**
 * A PluginSlot is a named location in the UI where multiple plugins can inject components.
 * This keeps the core components clean and unaware of specific plugin logic.
 */
export const PluginSlot: React.FC<PluginSlotProps> = ({ name, context }) => {
  const { data: plugins } = usePlugins();

  if (!Array.isArray(plugins)) return null;

  return (
    <>
      {plugins
        .filter(p => p.is_enabled && Array.isArray(p.manifest?.ui?.components))
        .map(plugin => (
          (plugin.manifest.ui?.components ?? [])
            .filter((c) => c.type === name)
            .map((comp, cidx) => (
              <PluginComponentLoader 
                key={`${plugin.slug}-${comp.name || cidx}`}
                pluginSlug={plugin.slug}
                componentFile={comp.file}
                {...context}
              />
            ))
        ))}
    </>
  );
};

export default PluginSlot;
