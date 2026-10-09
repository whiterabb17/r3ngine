import os
import subprocess
import threading
import logging
import yaml
from django.core.cache import cache
from .models import Plugin

logger = logging.getLogger(__name__)

_TOOL_VERIFIED_CACHE_TIMEOUT = None  # persistent until explicitly cleared on plugin install/upgrade


def install_plugin_tools(plugin_slug):
    """
    Task to install tools defined in a plugin's tools.yaml.
    Skips tools whose verification result is already cached from a prior startup.
    Cache is invalidated when the plugin is installed or upgraded.
    """
    try:
        plugin = Plugin.objects.get(slug=plugin_slug)
    except Plugin.DoesNotExist:
        logger.error("Plugin %s not found for tool installation.", plugin_slug)
        return

    tools_config = plugin.tools_config
    if not tools_config or 'tools' not in tools_config:
        logger.info("No tools to install for plugin %s.", plugin_slug)
        return

    plugin_dir = os.path.join('/usr/src/app/plugins_data', plugin_slug)

    for tool in tools_config.get('tools', []):
        name = tool.get('name')
        cache_key = f"plugin_{plugin_slug}_tool_{name}_verified"

        if cache.get(cache_key):
            logger.info("Tool %s for plugin %s already verified (cached), skipping.", name, plugin_slug)
            continue

        install_command = tool.get('install_command')
        validation_command = tool.get('validation_command')

        already_installed = False
        if validation_command:
            res = subprocess.run(
                validation_command,
                shell=True,
                cwd=plugin_dir,
                capture_output=True,
                text=True
            )
            if res.returncode == 0:
                logger.info("Tool %s for plugin %s already installed, skipping install.", name, plugin_slug)
                cache.set(cache_key, True, timeout=_TOOL_VERIFIED_CACHE_TIMEOUT)
                already_installed = True

        if not already_installed:
            if not install_command:
                logger.warning("No install command for tool %s in plugin %s", name, plugin_slug)
                continue

            logger.info("Installing tool %s for plugin %s...", name, plugin_slug)
            try:
                subprocess.run(
                    install_command,
                    shell=True,
                    cwd=plugin_dir,
                    check=True,
                    capture_output=True,
                    text=True
                )
                logger.info("Successfully installed tool %s.", name)

                if validation_command:
                    res = subprocess.run(
                        validation_command,
                        shell=True,
                        cwd=plugin_dir,
                        capture_output=True,
                        text=True
                    )
                    if res.returncode == 0:
                        logger.info("Tool %s verified successfully.", name)
                        cache.set(cache_key, True, timeout=_TOOL_VERIFIED_CACHE_TIMEOUT)
                    else:
                        logger.error("Tool %s verification failed: %s", name, res.stderr)
                else:
                    cache.set(cache_key, True, timeout=_TOOL_VERIFIED_CACHE_TIMEOUT)

            except subprocess.CalledProcessError as e:
                logger.error("Failed to install tool %s: %s", name, e.stderr)
            except Exception as e:
                logger.error("Unexpected error installing tool %s: %s", name, str(e))

def verify_all_plugin_tools():
    """
    Background task to verify all enabled plugin tools are installed.
    Runs on startup.
    """
    enabled_plugins = Plugin.objects.filter(is_enabled=True)
    for plugin in enabled_plugins:
        threading.Thread(
            target=install_plugin_tools,
            args=(plugin.slug,),
            daemon=True
        ).start()
