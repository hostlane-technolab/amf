from django.contrib import admin

# Register your models here.
from .models import PackingUnit

@admin.register(PackingUnit)
class UnitAdmin(admin.ModelAdmin):
    list_display = ('unit_code', 'basic_unit', 'precision', 'factor', 'description')
    search_fields = ('unit_code', 'description')
