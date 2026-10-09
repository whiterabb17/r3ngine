from django.test import TestCase

from reNgine.consumers import AssessmentEventConsumer

# database_sync_to_async closes "old" connections around each call, which would
# drop the test transaction; call the wrapped sync function directly instead.
_current_state = AssessmentEventConsumer.__dict__['_get_current_state'].func


class AssessmentCurrentStateTests(TestCase):

    def _consumer(self, assessment_id: str) -> AssessmentEventConsumer:
        consumer = AssessmentEventConsumer()
        consumer.assessment_id = assessment_id
        return consumer

    def test_route_id_that_is_not_a_uuid_has_no_state(self):
        # The ws route accepts [\w-]+, so a non-UUID id reaches the ORM lookup.
        self.assertIsNone(_current_state(self._consumer('not-a-uuid')))

    def test_unknown_assessment_has_no_state(self):
        self.assertIsNone(_current_state(self._consumer('00000000-0000-4000-8000-000000000000')))
