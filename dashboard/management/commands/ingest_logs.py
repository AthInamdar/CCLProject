from django.core.management.base import BaseCommand
from dashboard.models import SecurityLog
import json
import os

class Command(BaseCommand):
    help = 'Ingest security logs from JSON files'

    def handle(self, *args, **options):
        folder_path = "/path/to/json_files"
        for filename in os.listdir(folder_path):
            if filename.endswith(".json"):
                with open(os.path.join(folder_path, filename), 'r') as f:
                    data = json.load(f)
                    # For example, let's assume data has a "tool" key
                    log_entry = SecurityLog.objects.create(
                        tool_name=data.get("tool", "Unknown"),
                        raw_data=data
                    )
                    self.stdout.write(self.style.SUCCESS(f"Ingested {filename}"))
