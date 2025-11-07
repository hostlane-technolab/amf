# Add this to a new file: stock_helpers.py

from django.db import transaction
from decimal import Decimal
from .models import *
from django.utils import timezone

def record_stock_movement(
    movement_type,
    store,
    item,
    brand,
    cs_quantity,
    kg_quantity,
    slab_quantity=0,
    item_quality=None,
    freezing_category=None,
    peeling_type=None,
    unit=None,
    glaze=None,
    species=None,
    item_grade=None,
    usd_rate_per_kg=0,
    usd_rate_item=0,
    usd_rate_item_to_inr=0,
    voucher_number=None,
    movement_date=None,
    reference_model=None,
    reference_id=None,
    user=None,
    notes=None
):
    """
    Universal function to record any stock movement
    Call this function whenever stock changes
    
    Args:
        movement_type: One of MOVEMENT_TYPES
        cs_quantity: Positive for IN, Negative for OUT
        kg_quantity: Positive for IN, Negative for OUT
    """
    
    if movement_date is None:
        movement_date = timezone.now().date()
    
    movement = StockMovement.objects.create(
        movement_type=movement_type,
        movement_date=movement_date,
        voucher_number=voucher_number,
        store=store,
        item=item,
        brand=brand,
        item_quality=item_quality,
        freezing_category=freezing_category,
        peeling_type=peeling_type,
        unit=unit,
        glaze=glaze,
        species=species,
        item_grade=item_grade,
        cs_quantity=cs_quantity,
        kg_quantity=kg_quantity,
        slab_quantity=slab_quantity,
        usd_rate_per_kg=usd_rate_per_kg,
        usd_rate_item=usd_rate_item,
        usd_rate_item_to_inr=usd_rate_item_to_inr,
        reference_model=reference_model,
        reference_id=reference_id,
        created_by=user,
        notes=notes
    )
    
    print(f"✓ Stock movement recorded: {movement_type} - {item.name}: CS={cs_quantity}, KG={kg_quantity}")
    return movement


def update_stock_with_tracking(
    store,
    item,
    brand,
    cs_change,
    kg_change,
    movement_type,
    item_quality=None,
    freezing_category=None,
    peeling_type=None,
    unit=None,
    glaze=None,
    species=None,
    item_grade=None,
    usd_rate_per_kg=0,
    usd_rate_item=0,
    usd_rate_item_to_inr=0,
    voucher_number=None,
    movement_date=None,
    slab_quantity=0,
    user=None,
    notes=None
):
    """
    Update stock AND record movement in one transaction
    This is the main function to use when updating stock
    
    Args:
        cs_change: Amount to change (positive = add, negative = subtract)
        kg_change: Amount to change (positive = add, negative = subtract)
    """
    
    with transaction.atomic():
        # Build stock filters
        stock_filters = {
            'store': store,
            'item': item,
            'brand': brand,
            'item_quality': item_quality,
            'unit': unit,
            'glaze': glaze,
            'species': species,
            'item_grade': item_grade,
            'peeling_type': peeling_type,
            'freezing_category': freezing_category,
        }
        # Remove None values
        stock_filters = {k: v for k, v in stock_filters.items() if v is not None}
        
        # Find or create stock
        stock, created = Stock.objects.select_for_update().get_or_create(
            **stock_filters,
            defaults={
                'cs_quantity': 0,
                'kg_quantity': 0,
                'usd_rate_per_kg': 0,
                'usd_rate_item': 0,
                'usd_rate_item_to_inr': 0,
            }
        )
        
        old_kg = stock.kg_quantity
        old_cs = stock.cs_quantity
        
        # Calculate weighted average rates if adding stock
        if kg_change > 0 and usd_rate_per_kg > 0:
            new_total_kg = old_kg + kg_change
            
            if new_total_kg > 0:
                old_usd_per_kg = stock.usd_rate_per_kg or Decimal(0)
                old_usd_item = stock.usd_rate_item or Decimal(0)
                old_inr = stock.usd_rate_item_to_inr or Decimal(0)
                
                # Weighted average
                stock.usd_rate_per_kg = (
                    (old_kg * old_usd_per_kg) + (kg_change * usd_rate_per_kg)
                ) / new_total_kg
                
                stock.usd_rate_item = (
                    (old_kg * old_usd_item) + (kg_change * usd_rate_item)
                ) / new_total_kg
                
                stock.usd_rate_item_to_inr = (
                    (old_kg * old_inr) + (kg_change * usd_rate_item_to_inr)
                ) / new_total_kg
        
        # Update quantities
        stock.cs_quantity += cs_change
        stock.kg_quantity += kg_change
        
        # Check for negative stock
        if stock.cs_quantity < 0 or stock.kg_quantity < 0:
            print(f"⚠ WARNING: Negative stock for {item.name}! CS={stock.cs_quantity}, KG={stock.kg_quantity}")
        
        # Delete if zero
        if stock.cs_quantity == 0 and stock.kg_quantity == 0:
            stock.delete()
            print(f"✓ Stock deleted (zero balance): {item.name}")
        else:
            stock.save()
            print(f"✓ Stock updated: {item.name} - CS: {old_cs} → {stock.cs_quantity}, KG: {old_kg} → {stock.kg_quantity}")
        
        # Record movement
        record_stock_movement(
            movement_type=movement_type,
            store=store,
            item=item,
            brand=brand,
            cs_quantity=cs_change,
            kg_quantity=kg_change,
            slab_quantity=slab_quantity,
            item_quality=item_quality,
            freezing_category=freezing_category,
            peeling_type=peeling_type,
            unit=unit,
            glaze=glaze,
            species=species,
            item_grade=item_grade,
            usd_rate_per_kg=usd_rate_per_kg,
            usd_rate_item=usd_rate_item,
            usd_rate_item_to_inr=usd_rate_item_to_inr,
            voucher_number=voucher_number,
            movement_date=movement_date,
            reference_model=None,
            reference_id=None,
            user=user,
            notes=notes
        )
        
        return stock if not created and stock.pk else None


def create_daily_snapshot(date=None):
    """
    Create snapshot of all stock at end of day
    Run this as a daily cron job
    """
    
    if date is None:
        date = timezone.now().date()
    
    # Delete existing snapshot for this date
    StockSnapshot.objects.filter(snapshot_date=date).delete()
    
    # Get all current stock
    stocks = Stock.objects.all()
    
    snapshots_created = 0
    for stock in stocks:
        StockSnapshot.objects.create(
            snapshot_date=date,
            store=stock.store,
            item=stock.item,
            brand=stock.brand,
            item_quality=stock.item_quality,
            freezing_category=stock.freezing_category,
            peeling_type=stock.peeling_type,
            unit=stock.unit,
            glaze=stock.glaze,
            species=stock.species,
            item_grade=stock.item_grade,
            cs_quantity=stock.cs_quantity,
            kg_quantity=stock.kg_quantity,
        )
        snapshots_created += 1
    
    print(f"✓ Created {snapshots_created} stock snapshots for {date}")
    return snapshots_created


def get_opening_balance(store, item, brand, date, **kwargs):
    """
    Get opening balance for a specific stock item on a given date
    
    kwargs can include: item_quality, unit, glaze, species, item_grade, peeling_type, freezing_category
    """
    
    # Try to get from previous day's snapshot
    previous_date = date - timezone.timedelta(days=1)
    
    filters = {
        'snapshot_date': previous_date,
        'store': store,
        'item': item,
        'brand': brand,
    }
    filters.update(kwargs)
    
    snapshot = StockSnapshot.objects.filter(**filters).first()
    
    if snapshot:
        return {
            'cs_quantity': snapshot.cs_quantity,
            'kg_quantity': snapshot.kg_quantity
        }
    
    # If no snapshot, calculate from movements
    movement_filters = {
        'store': store,
        'item': item,
        'brand': brand,
        'movement_date__lt': date
    }
    movement_filters.update(kwargs)
    
    movements = StockMovement.objects.filter(**movement_filters)
    
    total_cs = sum(m.cs_quantity for m in movements)
    total_kg = sum(m.kg_quantity for m in movements)
    
    return {
        'cs_quantity': total_cs,
        'kg_quantity': total_kg
    }