from django.core.management.base import BaseCommand

from reNgine.tool_args import refresh_all_present_schemas


class Command(BaseCommand):
    help = 'Sync installed tools then refresh ToolArgSchemaCache from binary --help'

    def handle(self, *args, **options):
        result = refresh_all_present_schemas()
        sync = result.get('sync') or {}
        self.stdout.write(self.style.SUCCESS(
            f"Inventory: present={sync.get('present')} missing={sync.get('missing')}"
        ))
        self.stdout.write(self.style.SUCCESS(
            f"Schemas refreshed: {', '.join(result.get('refreshed') or []) or '(none)'}"
        ))
        for err in result.get('errors') or []:
            self.stdout.write(self.style.WARNING(f"  {err['tool']}: {err['error']}"))
