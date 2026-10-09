from django.db.models.signals import post_delete
from django.dispatch import receiver
from .models import Plugin
from .utils import PluginManager
import logging

logger = logging.getLogger(__name__)

@receiver(post_delete, sender=Plugin)
def cleanup_plugin_files(sender, instance, **kwargs):
    """
    Cleanup all files associated with the plugin after it is deleted from the DB.
    """
    try:
        logger.info("Cleaning up files for deleted plugin: %s (%s)", instance.name, instance.slug)
        PluginManager.delete_plugin_files(instance.slug)
    except Exception as e:
        logger.error("Error during plugin file cleanup for %s: %s", instance.slug, str(e))
