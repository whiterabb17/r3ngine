import React from 'react';
import { usePlugins } from '../api/pluginsApi';
import PluginComponentLoader from './PluginComponentLoader';

/** `name` selects a plugin override; every other prop is forwarded to whichever component renders. */
type PluginComponentProps<P extends object> = P & {
  name: string;
  default: React.ComponentType<P>;
};

/**
 * PluginComponent is a wrapper that allows a plugin to COMPLETELY OVERRIDE a core UI component.
 * If no plugin provides an override for the given name, it renders the default core component.
 */
export const PluginComponent = <P extends object>({
  name,
  default: DefaultComponent,
  ...rest
}: PluginComponentProps<P>) => {
  // The rest of `P & { name, default }` is typed `Omit<…>`, which TS cannot prove is `P`.
  const props = rest as unknown as P;
  const { data: plugins } = usePlugins();

  // Find if any plugin provides an override for this component name
  const override = Array.isArray(plugins)
    ? plugins.find(p => 
        p.is_enabled && (
          p.manifest?.ui?.overrides?.some((o) => o.name === name) ||
          p.manifest?.ui?.components?.some((c) => c.name === name)
        )
      )
    : null;

  if (override) {
    const componentConfig = (override.manifest.ui?.overrides || []).find((o) => o.name === name) ||
                            (override.manifest.ui?.components || []).find((c) => c.name === name);
    return (
      <PluginComponentLoader 
        pluginSlug={override.slug}
        componentFile={componentConfig!.file}
        {...props}
      />
    );
  }

  return <DefaultComponent {...props} />;
};

export default PluginComponent;
