# context_processors.py - Create this file in your adminapp directory

def permission_processor(request):
    """Add user permissions to template context"""
    if request.user.is_authenticated:
        return {
            'user_permissions': {
                'can_view_master_data': request.user.has_perm('adminapp.master_data_view'),
                'can_add_master_data': request.user.has_perm('adminapp.master_data_add'),
                'can_edit_master_data': request.user.has_perm('adminapp.master_data_edit'),
                'can_delete_master_data': request.user.has_perm('adminapp.master_data_delete'),
                
                'can_view_purchasing': request.user.has_perm('adminapp.purchasing_view'),
                'can_add_purchasing': request.user.has_perm('adminapp.purchasing_add'),
                'can_edit_purchasing': request.user.has_perm('adminapp.purchasing_edit'),
                'can_delete_purchasing': request.user.has_perm('adminapp.purchasing_delete'),
                
                'can_view_processing': request.user.has_perm('adminapp.processing_view'),
                'can_add_processing': request.user.has_perm('adminapp.processing_add'),
                'can_edit_processing': request.user.has_perm('adminapp.processing_edit'),
                'can_delete_processing': request.user.has_perm('adminapp.processing_delete'),
                
                'can_view_reports': request.user.has_perm('adminapp.reports_view'),
                'can_export_reports': request.user.has_perm('adminapp.reports_export'),
                
                'can_view_billing': request.user.has_perm('adminapp.billing_view'),
                'can_add_billing': request.user.has_perm('adminapp.billing_add'),
                'can_edit_billing': request.user.has_perm('adminapp.billing_edit'),
                'can_delete_billing': request.user.has_perm('adminapp.billing_delete'),

                'can_view_freezing': request.user.has_perm('adminapp.freezing_view'),
                'can_add_freezing': request.user.has_perm('adminapp.freezing_add'),
                'can_edit_freezing': request.user.has_perm('adminapp.freezing_edit'),
                'can_delete_freezing': request.user.has_perm('adminapp.freezing_delete'),

                'can_add_voucher': request.user.has_perm('adminapp.voucher_add'),
                'can_view_voucher': request.user.has_perm('adminapp.voucher_view'),
                'can_edit_voucher': request.user.has_perm('adminapp.voucher_edit'),
                'can_delete_voucher': request.user.has_perm('adminapp.voucher_delete'),
                
                'can_manage_users': request.user.has_perm('adminapp.user_management_view'),
                'can_add_users': request.user.has_perm('adminapp.user_management_add'),
                'can_edit_users': request.user.has_perm('adminapp.user_management_edit'),
                'can_delete_users': request.user.has_perm('adminapp.user_management_delete'),
            }
        }
    return {}

# management/commands/setup_permissions.py - Create this management command

import os
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

            # Freezing Permissions
            ('freezing_view', 'Can view freezing'),
            ('freezing_add', 'Can add freezing'),
            ('freezing_edit', 'Can edit freezing'),
            ('freezing_delete', 'Can delete freezing'),

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
        
        self.stdout.write(
            self.style.SUCCESS(f'Successfully created {created_count} permissions')
        )

# Quick setup script - run_setup.py (optional convenience script)