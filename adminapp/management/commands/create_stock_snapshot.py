from django.core.management.base import BaseCommand
from django.utils import timezone
from adminapp.stock_helpers import create_daily_snapshot

class Command(BaseCommand):
    help = 'Create daily stock snapshot for reporting'

    def add_arguments(self, parser):
        parser.add_argument(
            '--date',
            type=str,
            help='Date in YYYY-MM-DD format (default: yesterday)',
        )

    def handle(self, *args, **options):
        if options['date']:
            from datetime import datetime
            date = datetime.strptime(options['date'], '%Y-%m-%d').date()
        else:
            # Default to yesterday
            date = (timezone.now() - timezone.timedelta(days=1)).date()
        
        self.stdout.write(f"Creating stock snapshot for {date}...")
        
        count = create_daily_snapshot(date)
        
        self.stdout.write(
            self.style.SUCCESS(f'Successfully created {count} stock snapshots for {date}')
        )