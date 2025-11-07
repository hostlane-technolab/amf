from django.contrib import admin
from .models import *

# Register your models here.
from .models import PackingUnit

@admin.register(PackingUnit)
class UnitAdmin(admin.ModelAdmin):
    list_display = ('unit_code', 'basic_unit', 'precision', 'factor', 'description')
    search_fields = ('unit_code', 'description')


@admin.register(StockMovement)
class StockMovementAdmin(admin.ModelAdmin):
    list_display = [
        'movement_date', 'movement_type', 'voucher_number',
        'item', 'store', 'kg_quantity', 'cs_quantity'
    ]
    list_filter = ['movement_type', 'movement_date', 'store', 'item']
    search_fields = ['voucher_number', 'item__name', 'store__name']
    date_hierarchy = 'movement_date'
    readonly_fields = ['created_at', 'created_by']
    
    def save_model(self, request, obj, form, change):
        if not change:  # If creating new
            obj.created_by = request.user
        super().save_model(request, obj, form, change)


@admin.register(StockSnapshot)
class StockSnapshotAdmin(admin.ModelAdmin):
    list_display = [
        'snapshot_date', 'item', 'store', 'brand',
        'kg_quantity', 'cs_quantity'
    ]
    list_filter = ['snapshot_date', 'store', 'item']
    search_fields = ['item__name', 'store__name']
    date_hierarchy = 'snapshot_date'
    readonly_fields = ['created_at']