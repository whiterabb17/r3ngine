# r3ngine — Plugin System

## Overview

r3ngine has a first-class plugin architecture that allows third-party and custom modules to extend the core scan pipeline, add new Temporal workflows/activities, and mount React UI panels — all without modifying the core codebase.

---

## Plugin Structure

Every plugin follows this directory layout:

```
plugin_name/
├── backend/
│   ├── __init__.py
│   ├── api.py              # DRF API views
│   ├── api_urls.py         # URL routing
│   ├── apps.py             # Django AppConfig
│   ├── models.py           # Django models
│   ├── serializers.py      # DRF serializers
│   └── temporal_exports.py # Temporal workflow + activity definitions
├── ui/
│   ├── src/                # React TypeScript source
│   ├── package.json
│   └── vite.config.ts
├── manifest.yaml           # Plugin metadata and integration config
├── tools.yaml              # External tool dependencies
└── README.md
```

---

## `manifest.yaml` Reference

```yaml
name: "Plugin Name"
description: "Short description"
version: "1.0.0"

runtime:
  run after: "vulnerability_scan"  # or "standalone"

temporal:
  workflows:
    - "backend.temporal_exports.MyWorkflowClass"
  activities:
    - "backend.temporal_exports.my_activity_function"

ui:
  menu_item: "Display Name"
  menu_path: "/p/my-plugin"
  entry_export: "MyDashboardComponent"

# Optional: MCP tools agents may use when this plugin is installed + enabled.
# Host exposes thin /api/mcp/… wrappers (never raw /api/plugins/{slug}/).
# Sidecar registers these names only after r3ngine_list_plugins reports the slug.
mcp:
  tools:
    - r3ngine_example_plugin_tool
```

### `runtime.run after`

Controls when the plugin is injected into the scan pipeline.

| Value | Behavior |
|---|---|
| `"vulnerability_scan"` | Plugin runs after the vulnerability scan step completes |
| `"subdomain_discovery"` | Plugin runs after subdomain discovery |
| `"standalone"` | Plugin is never injected into the scan pipeline. Must be triggered manually. |

### `temporal.workflows` and `temporal.activities`

Paths relative to the plugin's `backend/` directory, in `module.path.ClassName` format.

### `mcp.tools`

Optional list of MCP tool names this plugin contributes. Discovery endpoints (`r3ngine_list_plugins`, `r3ngine_list_capabilities.plugins`) surface these only for **enabled** installed plugins. Each name must have a matching host view under `/api/mcp/` that calls `require_plugin(slug)` before touching plugin models.

## Plugin Installation (`plugins/utils.py`)

Plugins are installed from zip archives or directories via the Plugin Manager UI. The installer:

1. Copies plugin files to `/usr/src/app/plugins_data/{plugin_slug}/`.
2. Adds the plugin's `backend/` directory to `INSTALLED_APPS` (dynamically).
3. Runs Django migrations for the plugin app in a **subprocess** (to avoid Django app registry conflicts with dynamic app loading):
   ```python
   subprocess.run([
       "python", "manage.py", "migrate", plugin_slug
   ], ...)
   ```
4. Creates a `Plugin` DB record with the parsed `manifest.yaml`.
5. Triggers a worker restart so `PluginTemporalRegistry` reloads.

---

## `PluginTemporalRegistry` (`plugins/temporal_registry.py`)

Dynamically loads Temporal workflows and activities from all enabled plugins at orchestrator startup.

### `get_all_plugin_workflows()`

```python
workflows = PluginTemporalRegistry.get_all_plugin_workflows()
```

For each enabled plugin, reads `manifest.yaml`'s `temporal.workflows` list, constructs the full module path:
```
plugins_data.{plugin_slug}.backend.temporal_exports.{ClassName}
```
And imports the class. Returns a list of all workflow classes to register with the Temporal worker.

### `get_all_plugin_activities()`

Same pattern, returns a list of activity functions.

---

## `PluginOrchestrator` (`plugins/orchestrator.py`)

The legacy orchestrator for injecting plugin tasks into the scan pipeline. Used for Celery-era pipeline injection. In the Temporal era, plugins declare their `run after` anchor and the workflow engine handles ordering.

---

## Plugin Django App

The `plugins` Django app manages:
- `Plugin` model: `slug`, `name`, `manifest` (JSONField), `is_enabled`, `anchor_step`, `runtime_position`, `order_weight`.
- Plugin installation, update, and deletion via management commands and API.
- Plugin enable/disable toggle.

---

## Plugin UI Integration

### Routing

The r3ngine frontend uses a dynamic wildcard route `/p/:pluginSlug` and `/p/:pluginSlug/:pageName` to handle all plugin pages. The router:

1. Converts the hyphenated URL slug to an underscore slug (e.g., `active-exploitation` → `active_exploitation`).
2. Finds the matching enabled plugin in the backend API.
3. Loads the plugin's compiled `dist/plugin.js` bundle.
4. Calls the bundle's `entry_export` (e.g., `ActiveExploitationDashboard`) and mounts it in a React container.

### Building Plugin UI

```bash
cd r3ngine-plugins/{plugin_name}/ui
npm install
npm run build
```

The output `dist/plugin.js` must be placed in:
```
/usr/src/app/plugins_data/{plugin_slug}/ui/dist/plugin.js
```

### Plugin API Communication

Plugin UIs use the host frontend's API client (which injects the JWT token automatically). Plugin API endpoints are available at:
```
/api/plugins/{plugin_slug}/
```

---

## Installed Plugins

| Plugin | Slug | Description |
|---|---|---|
| Active Directory | `active_directory` | AD assessment and identity intelligence |
| Active Exploitation | `active_exploitation` | SQLMap exploitation via Temporal |
| Exploit Readiness Layer | `exploit_readiness_layer` | Vulnerability validation engine |

---

## Writing a New Plugin

See the [DEVELOPERS_GUIDE.md](../../r3ngine-plugins/DEVELOPERS_GUIDE.md) in `r3ngine-plugins/` for a complete guide on creating, building, and installing a new plugin.
