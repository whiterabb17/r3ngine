from django.core.management.base import BaseCommand

from reNgine.tool_inventory import sync_installed_tools


class Command(BaseCommand):
    help = 'Reconcile InstalledExternalTool rows against binaries on this host'

    def add_arguments(self, parser):
        parser.add_argument(
            '--no-versions',
            action='store_true',
            help='Skip version probes (presence only)',
        )

    def handle(self, *args, **options):
        result = sync_installed_tools(probe_versions=not options['no_versions'])
        self.stdout.write(self.style.SUCCESS(
            f"Synced tools: present={result['present']} missing={result['missing']} "
            f"errors={result['errors']}"
        ))
