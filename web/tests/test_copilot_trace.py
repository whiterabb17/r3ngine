"""Copilot Trace persistence tests."""
from __future__ import annotations

from django.test import TestCase, tag

from copilot.models import CopilotSession, CopilotTraceEvent
from copilot.trace import emit_trace, list_trace_events, serialize_trace_event


@tag('unit')
class CopilotTraceTests(TestCase):
    def test_emit_and_list(self):
        session = CopilotSession.objects.create(project_slug='demo', title='t')
        ev = emit_trace(
            project_slug='demo',
            session=session,
            turn_id='abc123',
            event_type='retrieve',
            summary='hits=2',
            payload={'memory_hits': 2, 'token': 'should-redact'},
        )
        self.assertIsNotNone(ev)
        self.assertEqual(ev.event_type, CopilotTraceEvent.TYPE_RETRIEVE)
        self.assertEqual(ev.payload.get('token'), '[redacted]')

        events = list_trace_events(project_slug='demo', session_id=session.id)
        self.assertEqual(len(events), 1)
        data = serialize_trace_event(events[0])
        self.assertEqual(data['turn_id'], 'abc123')
        self.assertEqual(data['summary'], 'hits=2')
