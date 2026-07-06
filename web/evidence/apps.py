from django.apps import AppConfig


class EvidenceConfig(AppConfig):
    """Evidence Management Platform — Phase 3 r3ngine feature.

    Handles tamper-proof storage, hashing, chain of custody, and lifecycle
    management for evidence collected during assessments.
    """
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'evidence'
    verbose_name = 'Evidence Platform'

    def ready(self):
        # Register signals when app is ready
        import evidence.signals  # noqa: F401
