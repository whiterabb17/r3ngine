import json
import logging
import redis
from django.conf import settings

logger = logging.getLogger(__name__)

class StressTelemetryPublisher:
    """Handles pushing real-time telemetry to Redis Streams."""
    def __init__(self, scan_id):
        self.scan_id = scan_id
        self.stream_key = f"stress:telemetry:{scan_id}"
        try:
            self.redis_client = redis.StrictRedis(
                host=settings.REDIS_HOST,
                port=settings.REDIS_PORT,
                password=settings.REDIS_PASSWORD,
                db=0
            )
        except Exception as e:
            logger.error("Failed to connect to Redis for telemetry: %s", e)
            self.redis_client = None

    def clear_stream(self):
        """Delete the telemetry stream so a fresh test run starts with no stale history."""
        if not self.redis_client:
            return
        try:
            self.redis_client.delete(self.stream_key)
        except Exception as e:
            logger.error("Error clearing telemetry stream: %s", e)

    def publish(self, metrics):
        """Publish a metric packet to the stream."""
        if not self.redis_client:
            return
        
        try:
            # We use '*' for auto-generated ID
            self.redis_client.xadd(self.stream_key, {"data": json.dumps(metrics)})
            # Optional: Limit stream length to prevent memory issues (e.g., last 1000 events)
            self.redis_client.xtrim(self.stream_key, maxlen=1000, approximate=True)
        except Exception as e:
            logger.error("Error publishing telemetry: %s", e)
