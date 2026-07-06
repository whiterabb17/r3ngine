import json
import asyncio
import logging
import redis
from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncWebsocketConsumer
from django.conf import settings

logger = logging.getLogger(__name__)

class StressTelemetryConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        user = self.scope.get('user')
        if not user or not user.is_authenticated:
            await self.close(code=4401)
            return

        self.scan_id = self.scope['url_route']['kwargs']['scan_id']
        self.stream_key = f"stress:telemetry:{self.scan_id}"
        self.group_name = f"stress_test_{self.scan_id}"

        # Join group
        await self.channel_layer.group_add(
            self.group_name,
            self.channel_name
        )

        await self.accept()
        logger.info(f"WebSocket connected for scan {self.scan_id}")

        # Send authoritative current status from DB before replaying stream history.
        # This prevents a page reload from getting stuck in "running" state when the
        # Celery worker was killed before publishing the final "completed" message.
        is_running = await self._is_scan_running()
        await self.send(text_data=json.dumps({
            'type': 'scan_status',
            'status': 'running' if is_running else 'completed'
        }))

        # Start background task to tail Redis Stream
        self.keep_running = True
        self.tail_task = asyncio.create_task(self.tail_redis_stream())

    @database_sync_to_async
    def _is_scan_running(self):
        from startScan.models import ScanHistory
        from reNgine.definitions import RUNNING_TASK
        try:
            scan = ScanHistory.objects.filter(id=self.scan_id).first()
            return scan is not None and scan.scan_status == RUNNING_TASK
        except Exception:
            return False

    async def disconnect(self, close_code):
        self.keep_running = False
        if hasattr(self, 'tail_task'):
            self.tail_task.cancel()

        if hasattr(self, 'group_name'):
            await self.channel_layer.group_discard(
                self.group_name,
                self.channel_name
            )
        if hasattr(self, 'scan_id'):
            logger.info(f"WebSocket disconnected for scan {self.scan_id}")

    async def tail_redis_stream(self):
        """Tails the Redis stream and sends updates to the client."""
        r = redis.StrictRedis(
            host=settings.REDIS_HOST, 
            port=settings.REDIS_PORT, 
            password=settings.REDIS_PASSWORD,
            db=0,
            decode_responses=True
        )
        
        last_id = '0' # Start from the beginning to load history
        loop = asyncio.get_running_loop()
        
        while self.keep_running:
            try:
                # Run the blocking xread in a thread pool to avoid blocking the event loop
                streams = await loop.run_in_executor(
                    None,
                    lambda: r.xread({self.stream_key: last_id}, count=10, block=2000)
                )
                if streams:
                    for stream_name, messages in streams:
                        for msg_id, data in messages:
                            last_id = msg_id
                            payload = json.loads(data['data'])
                            await self.send(text_data=json.dumps({
                                'type': 'telemetry_update',
                                'data': payload
                            }))
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error tailing Redis stream: {e}")
                await asyncio.sleep(1)

    async def stress_message(self, event):
        """Receive message from group (e.g., system alerts, control signals)."""
        await self.send(text_data=json.dumps(event))


class ScanLogConsumer(AsyncWebsocketConsumer):
    """WebSocket consumer for real-time scan logs."""
    async def connect(self):
        user = self.scope.get('user')
        if not user or not user.is_authenticated:
            await self.close(code=4401)
            return

        self.scan_id = self.scope['url_route']['kwargs']['scan_id']
        self.stream_key = f"scan:logs:{self.scan_id}"
        self.group_name = f"scan_logs_{self.scan_id}"

        # Join group
        await self.channel_layer.group_add(
            self.group_name,
            self.channel_name
        )

        await self.accept()
        logger.info(f"ScanLog WebSocket connected for scan {self.scan_id}")

        # Start background task to tail Redis Stream
        self.keep_running = True
        self.tail_task = asyncio.create_task(self.tail_redis_stream())

    async def disconnect(self, close_code):
        self.keep_running = False
        if hasattr(self, 'tail_task'):
            self.tail_task.cancel()

        if hasattr(self, 'group_name'):
            await self.channel_layer.group_discard(
                self.group_name,
                self.channel_name
            )
        if hasattr(self, 'scan_id'):
            logger.info(f"ScanLog WebSocket disconnected for scan {self.scan_id}")

    async def tail_redis_stream(self):
        """Tails the Redis stream and sends updates to the client."""
        r = redis.StrictRedis(
            host=settings.REDIS_HOST, 
            port=settings.REDIS_PORT, 
            password=settings.REDIS_PASSWORD,
            db=0,
            decode_responses=True
        )
        
        last_id = '0' # Start from the beginning to load history
        loop = asyncio.get_running_loop()
        
        while self.keep_running:
            try:
                # Run the blocking xread in a thread pool to avoid blocking the event loop
                streams = await loop.run_in_executor(
                    None,
                    lambda: r.xread({self.stream_key: last_id}, count=50, block=2000)
                )
                if streams:
                    for stream_name, messages in streams:
                        for msg_id, data in messages:
                            last_id = msg_id
                            # The data['data'] is a JSON string from stream_command
                            payload = json.loads(data['data'])
                            await self.send(text_data=json.dumps({
                                'type': 'log_update',
                                'data': payload
                            }))
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error tailing scan log Redis stream: {e}")
                await asyncio.sleep(1)

    async def log_message(self, event):
        """Receive message from group."""
        await self.send(text_data=json.dumps(event))

class AssessmentEventConsumer(AsyncWebsocketConsumer):
    """WebSocket consumer for real-time assessment progress and state changes."""
    async def connect(self):
        user = self.scope.get('user')
        if not user or not user.is_authenticated:
            await self.close(code=4401)
            return

        self.assessment_id = self.scope['url_route']['kwargs']['assessment_id']
        self.group_name = f"assessment_{self.assessment_id}"

        # Join group
        await self.channel_layer.group_add(
            self.group_name,
            self.channel_name
        )

        await self.accept()
        logger.info(f"AssessmentEvent WebSocket connected for assessment {self.assessment_id}")

        # Send authoritative current status from DB
        current_state = await self._get_current_state()
        if current_state:
            await self.send(text_data=json.dumps({
                'type': 'assessment_progress',
                'data': current_state
            }))

    @database_sync_to_async
    def _get_current_state(self):
        from engagements.models import AssessmentWorkflowState
        try:
            state = AssessmentWorkflowState.objects.get(assessment__uuid=self.assessment_id)
            return {
                'assessment_id': self.assessment_id,
                'stage': state.current_stage,
                'progress': state.progress_percent
            }
        except Exception:
            return None

    async def disconnect(self, close_code):
        if hasattr(self, 'group_name'):
            await self.channel_layer.group_discard(
                self.group_name,
                self.channel_name
            )
        logger.info(f"AssessmentEvent WebSocket disconnected for assessment {getattr(self, 'assessment_id', 'unknown')}")

    async def assessment_message(self, event):
        """Receive message from group send and forward to WebSocket."""
        # Clean up the internal type field, forward the actual event name
        await self.send(text_data=json.dumps({
            'type': event['event'],
            'data': event['data']
        }))
