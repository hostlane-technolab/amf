# adminapp/management/commands/setup_permissions.py

from django.core.management.base import BaseCommand
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from adminapp.models import CustomUser

class Command(BaseCommand):
    help = 'Setup custom permissions for the application'
    
    def handle(self, *args, **options):
        content_type = ContentType.objects.get_for_model(CustomUser)
        
        # Define custom permissions
        custom_permissions = [
            # Master Data Permissions
            ('master_data_view', 'Can view master data'),
            ('master_data_add', 'Can add master data'),
            ('master_data_edit', 'Can edit master data'),
            ('master_data_delete', 'Can delete master data'),
            
            # Purchasing Permissions
            ('purchasing_view', 'Can view purchases'),
            ('purchasing_add', 'Can add purchases'),
            ('purchasing_edit', 'Can edit purchases'),
            ('purchasing_delete', 'Can delete purchases'),
            
            # Processing Permissions
            ('processing_view', 'Can view processing'),
            ('processing_add', 'Can add processing'),
            ('processing_edit', 'Can edit processing'),
            ('processing_delete', 'Can delete processing'),

            # Shipping Permissions
            ('shipping_view', 'Can view shipping'),
            ('shipping_add', 'Can add shipping'),
            ('shipping_edit', 'Can edit shipping'),
            ('shipping_delete', 'Can delete shipping'),

            # Voucher Permissions
            ('voucher_view', 'Can view voucher'),
            ('voucher_add', 'Can add voucher'),
            ('voucher_edit', 'Can edit voucher'),
            ('voucher_delete', 'Can delete voucher'),
            
            # Reports Permissions
            ('reports_view', 'Can view reports'),
            ('reports_export', 'Can export reports'),
            
            # Billing Permissions
            ('billing_view', 'Can view billing'),
            ('billing_add', 'Can add billing'),
            ('billing_edit', 'Can edit billing'),
            ('billing_delete', 'Can delete billing'),
            
            # User Management Permissions
            ('user_management_view', 'Can view users'),
            ('user_management_add', 'Can add users'),
            ('user_management_edit', 'Can edit users'),
            ('user_management_delete', 'Can delete users'),
        ]
        
        created_count = 0
        for codename, name in custom_permissions:
            permission, created = Permission.objects.get_or_create(
                codename=codename,
                name=name,
                content_type=content_type
            )
            if created:
                created_count += 1
                self.stdout.write(f'Created permission: {name}')
            else:
                self.stdout.write(f'Permission already exists: {name}')
        
        self.stdout.write(
            self.style.SUCCESS(f'Setup complete! Created {created_count} new permissions')
        )
        