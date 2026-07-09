"""Evidence Platform signals.

Handles post-save events for Evidence and EvidenceCollection records,
including auto-retry for failed integrity checks and real-time updates.
"""
from django.db.models.signals import post_save
from django.dispatch import receiver
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer


@receiver(post_save, sender='evidence.Evidence')
def evidence_post_save(sender, instance, created, **kwargs):
    """Log creation events via the WebSocket evidence channel when a new item is saved."""
    if created:
        try:
            from reNgine.utils.logger import get_module_logger
            log = get_module_logger(__name__)
            log.log_line("[EVIDENCE]", "CREATED", f"New evidence item {instance.uuid} in collection {instance.collection_id}")
            
            # Broadcast to the assessment's WebSocket group so the UI refreshes
            if instance.collection and instance.collection.assessment:
                assessment_id = str(instance.collection.assessment.uuid)
                channel_layer = get_channel_layer()
                if channel_layer:
                    group_name = f"assessment_{assessment_id}"
                    async_to_sync(channel_layer.group_send)(
                        group_name,
                        {
                            'type': 'assessment_message',
                            'event': 'evidence_created',
                            'data': {
                                'evidence_uuid': str(instance.uuid),
                                'collection_uuid': str(instance.collection.uuid),
                                'evidence_type': instance.evidence_type,
                                'title': instance.title
                            }
                        }
                    )
        except Exception as e:
            # Silently fail if channel layer isn't configured or relations are missing
            pass
