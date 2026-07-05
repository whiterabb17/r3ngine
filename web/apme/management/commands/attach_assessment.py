"""Backfill assessment_id on APMENodes previously written under scan_id.

Use when a scan was launched before Phase 5 (or launched standalone) and
is being retroactively attached to a new assessment.

Usage:
    python manage.py attach_assessment --scan-id 42 --assessment-uuid <uuid>
"""
from django.core.management.base import BaseCommand, CommandError

from apme.graph.builder import GraphBuilder
from engagements.models import Assessment
from startScan.models import ScanHistory


class Command(BaseCommand):
    help = "Attach an assessment to an already-synced scan's Neo4j nodes"

    def add_arguments(self, parser):
        parser.add_argument('--scan-id', type=int, required=True)
        parser.add_argument('--assessment-uuid', type=str, required=True)

    def handle(self, *args, scan_id, assessment_uuid, **_):
        try:
            scan = ScanHistory.objects.get(id=scan_id)
        except ScanHistory.DoesNotExist as exc:
            raise CommandError("Scan %d not found" % scan_id) from exc

        try:
            assessment = Assessment.objects.get(uuid=assessment_uuid)
        except Assessment.DoesNotExist as exc:
            raise CommandError("Assessment %s not found" % assessment_uuid) from exc

        # Update the Postgres FK too, so future syncs are aware.
        if scan.assessment_id is None or str(scan.assessment.uuid) != str(assessment.uuid):
            scan.assessment = assessment
            scan.save(update_fields=['assessment'])
            self.stdout.write(self.style.SUCCESS(
                "Attached scan %d to assessment %s in Postgres." % (
                    scan_id, assessment_uuid,
                )
            ))

        builder = GraphBuilder()
        try:
            updated = builder.attach_assessment_id(scan_id, str(assessment.uuid))
        finally:
            builder.close()

        self.stdout.write(self.style.SUCCESS(
            "Backfilled assessment_id on %d Neo4j APMENode(s)." % updated
        ))
