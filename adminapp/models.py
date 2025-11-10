from django.db import models

# Create your models here.

import uuid
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils import timezone   # ✅ import here



# nammude client paranjhu name chage cheyyan athu too risk anu athukondu html name mathre matittullu
# item category ennu parayunne elam item quality anu  model name itemQuality
# item group ennu parayunne elam item category anu model name itemCategory





class CustomUserManager(BaseUserManager):
    def create_user(self, email, full_name, mobile, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, full_name=full_name, mobile=mobile, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, full_name, mobile, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        return self.create_user(email, full_name, mobile, password, **extra_fields)

class CustomUser(AbstractBaseUser, PermissionsMixin):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    full_name = models.CharField(max_length=150)
    mobile = models.CharField(max_length=15, unique=True)
    email = models.EmailField(unique=True)
    address = models.TextField(blank=True)
    profile_picture = models.ImageField(upload_to='profile_pics/', blank=True, null=True)
    role = models.CharField(max_length=30 )
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(auto_now_add=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['full_name', 'mobile']

    objects = CustomUserManager()

    # Add permission groups for easier management
    PERMISSION_GROUPS = [
        ('master_data', 'Master Data Management'),
        ('purchasing', 'Purchasing Operations'),
        ('processing', 'Processing Operations'),
        ('reports', 'Reports & Analytics'),
        ('billing', 'Billing & Finance'),
        ('freezing', 'Freezing Operations'),
        ('Voucher', 'Voucher Operations'),
        ('shipping', 'Shipping Operations'),
        ('user_management', 'User Management'),
    ]
    
    def has_module_permission(self, module_name):
        """Check if user has permission for a specific module"""
        return self.user_permissions.filter(codename__startswith=module_name).exists()

    def __str__(self):
        return self.email
    
from django.apps import AppConfig
class AdminAppConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'adminapp'
    
    def ready(self):
        # Create custom permissions
        self.create_custom_permissions()
    
    def create_custom_permissions(self):
        from django.contrib.auth.models import Permission
        from django.contrib.contenttypes.models import ContentType
        
        # Get content type for your app
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
        
        for codename, name in custom_permissions:
            Permission.objects.get_or_create(
                codename=codename,
                name=name,
                content_type=content_type
            )
       
import uuid
from django.db import models

# Shared abstract base model with UUID primary key
from django.db import models
from django.utils.crypto import get_random_string

def generate_short_id():
    import random, string
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))

class BaseModel(models.Model):
    id = models.CharField(
        primary_key=True,
        max_length=4,
        editable=False,
        unique=True,
        default=generate_short_id
    )

    class Meta:
        abstract = True


# Operational & Location Masters

class ProcessingCenter(BaseModel):
    name = models.CharField(max_length=150)
    address = models.TextField()
    contact_number = models.CharField(max_length=15, blank=True, unique=True)
    code=models.CharField(null=True,blank=True,unique=True,max_length=15)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.name} - {self.code}"

class Store(BaseModel):
    name = models.CharField(max_length=150)
    address = models.TextField()
    contact_number = models.CharField(max_length=15, blank=True, unique=True)
    code=models.CharField(null=True,blank=True,unique=True,max_length=100)
    store_type = models.CharField(max_length=100, choices=[('Retail', 'Retail'), ('Warehouse', 'Warehouse')])
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.name} - {self.code}"

class PurchasingSpot(BaseModel):
    location_name = models.CharField(max_length=150, unique=True)
    district = models.CharField(max_length=100, blank=True)
    state = models.CharField(max_length=100, blank=True)
    code = models.CharField(null=True,blank=True,unique=True,max_length=100)

    def __str__(self):
        return f"{self.location_name} - {self.code}"
    
class LocalParty(BaseModel):
    party = models.CharField(max_length=150, unique=True)
    district = models.CharField(max_length=100, blank=True)
    state = models.CharField(max_length=100, blank=True)
    code = models.CharField(null=True,blank=True,unique=True,max_length=100)

    def __str__(self):
        return f"{self.party}"
    




class PurchasingSupervisor(models.Model):
    name = models.CharField(max_length=150)
    mobile = models.CharField(max_length=15,blank=True)
    email = models.EmailField(blank=True)
    joining_date = models.DateField(null=True, blank=True)
    commission = models.DecimalField(max_digits=5, decimal_places=2)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"{self.name}"




class PurchasingAgent(BaseModel):
    purchasingSpot = models.ForeignKey(PurchasingSpot, on_delete=models.CASCADE)
    name = models.CharField(max_length=150)
    mobile = models.CharField(max_length=15, unique=True)
    code = models.CharField(null=True,blank=True,unique=True,max_length=100)

    def __str__(self):
        return f"{self.name}"

# Item & Product Masters

class ItemCategory(BaseModel):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    code = models.CharField(null=True,blank=True, unique=True,max_length=100)

    def __str__(self):
        return f"{self.name}"

class Item(BaseModel):
    category = models.ForeignKey(ItemCategory, on_delete=models.CASCADE)
    name = models.CharField(max_length=100, unique=True)
    code = models.CharField(max_length=50, unique=True)
    is_peeling = models.BooleanField(default=False)
    peeling_method = models.CharField(max_length=100, blank=True)

    def __str__(self):
        return f"{self.name}  - {self.code}"

class ItemQuality(BaseModel):
    item = models.ForeignKey(Item, on_delete=models.CASCADE)
    quality = models.CharField(max_length=100 , unique=True)
    code = models.CharField(null=True, blank=True, unique=True,max_length=100)

    def __str__(self):
        return f"{self.quality}"

class Species(BaseModel):
    item = models.ForeignKey(Item, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    code = models.CharField(null=True, blank=True, unique=True,max_length=100)

    def __str__(self):
        return f"{self.name}"

class ItemGrade(BaseModel):
    item = models.ForeignKey(Item, on_delete=models.CASCADE)
    species = models.ForeignKey(Species, on_delete=models.CASCADE, null=True, blank=True)
    grade = models.CharField(max_length=100)
    order_code = models.PositiveIntegerField(null=True, blank=True)
    date = models.DateField(auto_created=True, auto_now=True) 

    def __str__(self):
        return f"{self.grade}"
    
class FreezingCategory(BaseModel):
    name = models.CharField(max_length=100)
    code = models.CharField(null=True,blank=True,max_length=100)
    tariff = models.PositiveIntegerField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(default=timezone.now) 


    def __str__(self):
        return f"{self.name}"

class PackingUnit(BaseModel):

    unit_code = models.CharField(max_length=50, unique=True)  # e.g., '10X0.350GRAM'
    basic_unit = models.CharField(max_length=20, choices=[
        ('KG', 'Kilogram'),
        ('GRAM', 'Gram'),
        ('LTR', 'Liter'),
        # Add more as needed
    ], default='KG')
    precision = models.DecimalField(max_digits=100, decimal_places=2)  # e.g., 10.00
    factor = models.DecimalField(max_digits=100, decimal_places=5)     # e.g., 0.35
    description = models.CharField(max_length=100)

    def __str__(self):
        return f"{self.unit_code}"

class GlazePercentage(BaseModel):
    percentage = models.CharField(max_length=5, unique=True)  # e.g., '10.00' for 10%

    def __str__(self):
        return f"{self.percentage}%"

class ItemBrand(BaseModel):
    name = models.CharField(max_length=100, unique=True)
    code = models.CharField(max_length=50, unique=True, blank=True, null=True)

    def __str__(self):
        return f"{self.name}"

class ItemType(BaseModel):
    item = models.ForeignKey(Item, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    code = models.CharField(max_length=50, unique=True, blank=True, null=True)

    def __str__(self):
        return f"{self.name}"


#  Financial & Expense Masters

class Tenant(models.Model):
    company_name = models.CharField(max_length=150, null=True, blank=True)
    address = models.TextField(blank=True, null=True)
    contact_person = models.CharField(max_length=100, null=True, blank=True)
    email = models.EmailField(blank=True, null=True)
    phone = models.CharField(max_length=15, blank=True, null=True)

    def __str__(self):
        return self.company_name or "Unnamed Tenant"

    def __str__(self):
        return self.company_name
    
class TenantFreezingTariff(models.Model):
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name="freezing_tariffs")
    category = models.ForeignKey(FreezingCategory, on_delete=models.CASCADE, related_name="tenant_tariffs")
    tariff = models.PositiveIntegerField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(default=timezone.now) 

    class Meta:
        unique_together = ("tenant", "category")  # one tariff per tenant-category

    def __str__(self):
        return f"{self.tenant} - {self.category} : {self.tariff}"

class PurchaseOverhead(BaseModel):
    category_name = models.CharField(max_length=100)
    other_expenses = models.DecimalField(max_digits=100, decimal_places=2)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(default=timezone.now)  # ✅ uses current datetime

class PeelingOverhead(BaseModel):
    category_name = models.CharField(max_length=100)
    other_expenses = models.DecimalField(max_digits=100, decimal_places=2)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(default=timezone.now)  # ✅ uses current datetime

class ProcessingOverhead(BaseModel):
    category_name = models.CharField(max_length=100)
    amount = models.DecimalField(max_digits=100, decimal_places=2)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(default=timezone.now)  # ✅ uses current datetime



class ShipmentOverhead(BaseModel):
    category_name = models.CharField(max_length=100)
    amount = models.DecimalField(max_digits=100, decimal_places=2)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(default=timezone.now)  # ✅ uses current datetime


# settings
class Settings(BaseModel):
    dollar_rate_to_inr = models.DecimalField(max_digits=100, decimal_places=2)
    vehicle_rent_km = models.DecimalField(max_digits=100, decimal_places=2)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(default=timezone.now)  # ✅ uses current datetime

# shed creation

class Shed(models.Model):
    name = models.CharField(max_length=100, unique=True)
    code = models.CharField(max_length=50, unique=True)
    address = models.TextField()
    contact_number = models.CharField(max_length=20)
    capacity_per_day_kg = models.DecimalField(max_digits=100, decimal_places=3)

    def __str__(self):
        return self.name

class ShedItem(models.Model):
    shed = models.ForeignKey(Shed, on_delete=models.CASCADE, related_name='shed_items')
    item = models.ForeignKey(Item, on_delete=models.CASCADE, limit_choices_to={'is_peeling': True})
    item_type = models.ForeignKey(ItemType, on_delete=models.CASCADE, null=True, blank=True)
    amount = models.DecimalField(max_digits=100, decimal_places=2)
    unit = models.CharField(max_length=50, default='kg')

    def __str__(self):
        return f'{self.shed.name} - {self.item_type}'

# Spot Purchase Models

class BaseModel(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True

class SpotPurchase(BaseModel):
    date = models.DateField()
    voucher_number = models.CharField(max_length=20, unique=True)
    spot = models.ForeignKey('PurchasingSpot', on_delete=models.CASCADE)
    supervisor = models.ForeignKey('PurchasingSupervisor', on_delete=models.CASCADE)
    agent = models.ForeignKey('PurchasingAgent', on_delete=models.CASCADE)

    total_amount = models.DecimalField(max_digits=100, decimal_places=2, default=0)
    total_quantity = models.DecimalField(max_digits=100, decimal_places=3, default=0)
    total_items = models.IntegerField(null=True, blank=True)
    total_purchase_amount = models.DecimalField(max_digits=100, decimal_places=2, default=0)
    total_purchase_amount_per_kg = models.DecimalField(max_digits=100, decimal_places=20, default=0)

    def calculate_totals(self):
        """Calculate and save all purchase totals"""
        # Calculate totals from items
        items = self.items.all()
        self.total_quantity = sum(item.quantity for item in items)
        self.total_amount = sum(item.amount for item in items)
        self.total_items = items.count()
        
        # Add expense total if expense exists
        try:
            expense_total = self.expense.total_expense
        except SpotPurchaseExpense.DoesNotExist:
            expense_total = 0
            
        self.total_purchase_amount = self.total_amount + expense_total
        
        # Fix division by zero issue and calculate per kg amount
        if self.total_quantity > 0:
            self.total_purchase_amount_per_kg = self.total_purchase_amount / self.total_quantity
        else:
            self.total_purchase_amount_per_kg = 0
        
        # Save ALL the calculated fields including total_purchase_amount_per_kg
        super().save(update_fields=[
            'total_quantity', 
            'total_amount', 
            'total_items', 
            'total_purchase_amount',
            'total_purchase_amount_per_kg'  # This was missing!
        ])
        
        # Debug print to check values
        print(f"Debug - total_amount: {self.total_amount}, expense_total: {expense_total}")
        print(f"Debug - total_purchase_amount: {self.total_purchase_amount}")
        print(f"Debug - total_quantity: {self.total_quantity}")
        print(f"Debug - total_purchase_amount_per_kg: {self.total_purchase_amount_per_kg}")
        
        def __str__(self):
            return f"Voucher {self.voucher_number} on {self.date} at {self.spot.location_name}"

class SpotPurchaseItem(BaseModel):
    purchase = models.ForeignKey(SpotPurchase, on_delete=models.CASCADE, related_name='items')
    item = models.ForeignKey('Item', on_delete=models.CASCADE)
    quantity = models.DecimalField(max_digits=100, decimal_places=3)
    boxes = models.DecimalField(max_digits=100, decimal_places=3, null=True, blank=True)
    total_rate = models.DecimalField(max_digits=100, decimal_places=2)
    rate = models.DecimalField(max_digits=100, decimal_places=2)
    amount = models.DecimalField(max_digits=100, decimal_places=2)

    def save(self, *args, **kwargs):
        # Ensure amount equals total_rate and rate is calculated
        self.amount = self.total_rate
        if self.quantity > 0:
            self.rate = self.total_rate / self.quantity
        else:
            self.rate = 0
            
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.item.name} - {self.quantity}kg @ {self.rate}"

class SpotPurchaseExpense(BaseModel):
    purchase = models.OneToOneField(SpotPurchase, on_delete=models.CASCADE, related_name='expense')
    ice_expense = models.DecimalField(max_digits=100, decimal_places=2, default=0)
    vehicle_rent = models.DecimalField(max_digits=100, decimal_places=2, default=0)
    loading_and_unloading = models.DecimalField(max_digits=100, decimal_places=2, default=0)
    peeling_charge = models.DecimalField(max_digits=100, decimal_places=2, default=0)
    other_expense = models.DecimalField(max_digits=100, decimal_places=2, default=0)
    total_expense = models.DecimalField(max_digits=100, decimal_places=2, default=0)

    def save(self, *args, **kwargs):
        # Calculate total expense
        self.total_expense = (
            self.ice_expense +
            self.vehicle_rent +
            self.loading_and_unloading +
            self.peeling_charge +
            self.other_expense
        )
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Expense for {self.purchase.voucher_number} at {self.purchase.spot.location_name}"


# local purchase models

class LocalPurchase(BaseModel):
    date = models.DateField()
    voucher_number = models.CharField(max_length=20, unique=True)
    party_name = models.ForeignKey('LocalParty', on_delete=models.CASCADE)
    total_amount = models.DecimalField(max_digits=100, decimal_places=2, default=0)
    total_quantity = models.DecimalField(max_digits=100, decimal_places=3, default=0)
    total_items = models.IntegerField(null=True, blank=True)

    def __str__(self):
        return f"{self.party_name} - {self.voucher_number}"
    
class LocalPurchaseItem(BaseModel):
    purchase = models.ForeignKey(LocalPurchase, on_delete=models.CASCADE, related_name='items')
    item = models.ForeignKey(Item, on_delete=models.CASCADE)
    item_quality = models.ForeignKey('ItemQuality', on_delete=models.CASCADE, null=True, blank=True , default=None)
    species = models.ForeignKey(Species, on_delete=models.CASCADE,null=True, blank=True)
    item_type = models.ForeignKey(ItemType, on_delete=models.CASCADE, null=True, blank=True)
    grade = models.ForeignKey(ItemGrade, on_delete=models.CASCADE, null=True, blank=True)
    quantity = models.DecimalField(max_digits=100, decimal_places=3)
    rate = models.DecimalField(max_digits=100, decimal_places=2)
    amount = models.DecimalField(max_digits=100, decimal_places=2)

    def save(self, *args, **kwargs):
        # Calculate amount before saving
        self.amount = self.quantity * self.rate
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.item.name} - {self.quantity}kg @ {self.rate}"
    

# Peeling Shead Supply Entry

class PeelingShedSupply(models.Model):
    date = models.DateField()
    voucher_number = models.CharField(max_length=50, unique=True)
    shed = models.ForeignKey('shed', on_delete=models.CASCADE)
    vehicle_number = models.CharField(max_length=50)
    spot_purchase_date = models.DateField(null=True, blank=True)
    spot_purchase = models.ForeignKey('SpotPurchase', on_delete=models.CASCADE)
    spot_purchase_item = models.ForeignKey('SpotPurchaseItem', on_delete=models.CASCADE)
    SpotPurchase_total_boxes = models.PositiveIntegerField()
    SpotPurchase_quantity = models.DecimalField(max_digits=100, decimal_places=3)
    SpotPurchase_average_box_weight = models.DecimalField(max_digits=100, decimal_places=50, default=0)
    boxes_received_shed = models.PositiveIntegerField(default=0)
    SpotPurchase_balance_boxes = models.PositiveIntegerField(default=0)
    quantity_received_shed = models.DecimalField(max_digits=100, decimal_places=10, default=0)


    def __str__(self):
        return f"{self.voucher_number} - {self.date}"

class PeelingShedPeelingType(models.Model):
    supply = models.ForeignKey(PeelingShedSupply, on_delete=models.CASCADE, related_name='peeling_types')
    item = models.ForeignKey(Item, on_delete=models.CASCADE)
    item_type = models.ForeignKey(ItemType, on_delete=models.CASCADE, null=True, blank=True)
    amount = models.DecimalField(max_digits=100, decimal_places=2)
    unit = models.CharField(max_length=50)


# freezing entry by spot purchase 

class BaseModel(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True

class FreezingEntrySpot(BaseModel):
    freezing_date = models.DateField()
    voucher_number = models.CharField(max_length=50, unique=True)

    spot_purchase_date = models.DateField(null=True, blank=True)
    spot = models.ForeignKey('SpotPurchase', on_delete=models.CASCADE, related_name='freezing_entries')
    spot_agent = models.ForeignKey('PurchasingAgent', on_delete=models.CASCADE, related_name='freezing_entries')
    spot_supervisor = models.ForeignKey('PurchasingSupervisor', on_delete=models.CASCADE, related_name='freezing_entries')
    total_yield_percentage = models.DecimalField(max_digits=100, decimal_places=2)
    total_usd = models.DecimalField(max_digits=100, decimal_places=2)
    total_inr = models.DecimalField(max_digits=100, decimal_places=2)
    total_slab = models.DecimalField(max_digits=100, decimal_places=2)
    total_c_s = models.DecimalField(max_digits=100, decimal_places=2)
    total_kg = models.DecimalField(max_digits=100, decimal_places=3)

    FREEZING_STATUS_CHOICES = [
        ('complete', 'Complete'),
        ('incomplete', 'Incomplete'),
    ]
    freezing_status = models.CharField(max_length=50, choices=FREEZING_STATUS_CHOICES , default='incomplete')

    def __str__(self):
        return f"Freezing Entry - {self.freezing_date} - {self.spot}"

class FreezingEntrySpotItem(BaseModel):
    freezing_entry = models.ForeignKey(FreezingEntrySpot, on_delete=models.CASCADE, related_name='items')

    processing_center = models.ForeignKey('ProcessingCenter', on_delete=models.CASCADE, null=True)
    store = models.ForeignKey('Store', on_delete=models.CASCADE, null=True )
    shed = models.ForeignKey('shed', on_delete=models.CASCADE, related_name='freezing_shed_items', null=True, blank=True , default=None )
    item = models.ForeignKey('Item', on_delete=models.CASCADE, related_name='freezing_item_entries')
    item_quality = models.ForeignKey('ItemQuality', on_delete=models.CASCADE, null=True, blank=True , default=None)
    unit = models.ForeignKey('PackingUnit', on_delete=models.CASCADE)
    glaze = models.ForeignKey('GlazePercentage', on_delete=models.CASCADE)
    freezing_category = models.ForeignKey('FreezingCategory', on_delete=models.CASCADE)
    brand = models.ForeignKey('ItemBrand', on_delete=models.CASCADE, null=True, blank=True )
    species = models.ForeignKey('Species', on_delete=models.CASCADE,null=True, blank=True  )
    peeling_type = models.ForeignKey('ItemType', on_delete=models.CASCADE, null=True, blank=True )
    grade = models.ForeignKey('ItemGrade', on_delete=models.CASCADE, null=True, blank=True  )
    slab_quantity = models.DecimalField(max_digits=100, decimal_places=2)
    c_s_quantity = models.DecimalField(max_digits=100, decimal_places=2)
    kg = models.DecimalField(max_digits=100, decimal_places=3)
    usd_rate_per_kg = models.DecimalField(max_digits=100, decimal_places=2)
    usd_rate_item = models.DecimalField(max_digits=100, decimal_places=2)
    usd_rate_item_to_inr = models.DecimalField(max_digits=100, decimal_places=2)
    yield_percentage = models.DecimalField(max_digits=100, decimal_places=2)

    def __str__(self):
        return f"{self.item} - {self.kg} KG"



    def __str__(self):
        return f"{self.item} - {self.kg} KG"


# freezing entry by local purchase 
class FreezingEntryLocal(BaseModel):
    freezing_date = models.DateField()
    voucher_number = models.CharField(max_length=50, unique=True)

    local_purchase_date = models.DateField(null=True, blank=True)
    party = models.ForeignKey('LocalPurchase', on_delete=models.CASCADE)
    total_usd = models.DecimalField(max_digits=100, decimal_places=2, default=0)
    total_inr = models.DecimalField(max_digits=100, decimal_places=2, default=0)
    total_slab = models.DecimalField(max_digits=100, decimal_places=2, default=0)
    total_c_s = models.DecimalField(max_digits=100, decimal_places=2, default=0)
    total_kg = models.DecimalField(max_digits=100, decimal_places=3, default=0)

    FREEZING_STATUS_CHOICES = [
        ('complete', 'Complete'),
        ('incomplete', 'Incomplete'),
    ]
    freezing_status = models.CharField(
        max_length=50,
        choices=FREEZING_STATUS_CHOICES,
        default='incomplete'
    )

    def __str__(self):
        return f"Freezing Entry Local - {self.freezing_date} - {self.voucher_number}"

class FreezingEntryLocalItem(BaseModel):
    freezing_entry = models.ForeignKey(
        FreezingEntryLocal,
        on_delete=models.CASCADE,
        related_name='items'
    )

    processing_center = models.ForeignKey('ProcessingCenter', on_delete=models.CASCADE, null=True, blank=True)
    store = models.ForeignKey('Store', on_delete=models.CASCADE, null=True, blank=True)
    item = models.ForeignKey('Item', on_delete=models.CASCADE)
    item_quality = models.ForeignKey('ItemQuality', on_delete=models.CASCADE, null=True, blank=True , default=None)
    unit = models.ForeignKey('PackingUnit', on_delete=models.CASCADE)
    glaze = models.ForeignKey('GlazePercentage', on_delete=models.CASCADE)
    freezing_category = models.ForeignKey('FreezingCategory', on_delete=models.CASCADE)

    brand = models.ForeignKey('ItemBrand', on_delete=models.CASCADE, null=True, blank=True )
    species = models.ForeignKey('Species', on_delete=models.CASCADE,null=True, blank=True  )
    peeling_type = models.ForeignKey('ItemType', on_delete=models.CASCADE, null=True, blank=True )
    grade = models.ForeignKey('ItemGrade', on_delete=models.CASCADE, null=True, blank=True  )

    slab_quantity = models.DecimalField(max_digits=100, decimal_places=2, default=0)
    c_s_quantity = models.DecimalField(max_digits=100, decimal_places=2, default=0)
    kg = models.DecimalField(max_digits=100, decimal_places=3, default=0)
    usd_rate_per_kg = models.DecimalField(max_digits=100, decimal_places=2, default=0)
    usd_rate_item = models.DecimalField(max_digits=100, decimal_places=2, default=0)
    usd_rate_item_to_inr = models.DecimalField(max_digits=100, decimal_places=2, default=0)

    def __str__(self):
        return f"{self.item} - {self.kg} KG"


class TenantStock(BaseModel):
    """
    Tracks stock returned by tenants and available for reuse/resale
    """
    # Tenant reference - ALLOW NULL TEMPORARILY for migration
    tenant_company_name = models.ForeignKey(
        'Tenant', 
        on_delete=models.CASCADE,
        null=True,  # ✅ Temporarily allow null for migration
        blank=True
    )
    
    # Stock location
    processing_center = models.ForeignKey(
        'ProcessingCenter', 
        on_delete=models.CASCADE, 
        null=True, 
        blank=True
    )
    store = models.ForeignKey(
        'Store', 
        on_delete=models.CASCADE, 
        null=True, 
        blank=True
    )
    
    # Item details (denormalized for quick access)
    item = models.ForeignKey('Item', on_delete=models.CASCADE)
    item_quality = models.ForeignKey(
        'ItemQuality', 
        on_delete=models.CASCADE, 
        null=True, 
        blank=True
    )
    unit = models.ForeignKey('PackingUnit', on_delete=models.CASCADE)
    glaze = models.ForeignKey('GlazePercentage', on_delete=models.CASCADE)
    freezing_category = models.ForeignKey('FreezingCategory', on_delete=models.CASCADE)
    brand = models.ForeignKey('ItemBrand', on_delete=models.CASCADE)
    species = models.ForeignKey('Species', on_delete=models.CASCADE, null=True, blank=True)
    grade = models.ForeignKey('ItemGrade', on_delete=models.CASCADE)
    peeling_type = models.ForeignKey('ItemType', on_delete=models.CASCADE, null=True, blank=True)
    
    # Quantities
    available_slab = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    available_c_s = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    available_kg = models.DecimalField(max_digits=12, decimal_places=3, default=0)
    
    # Original quantities (for tracking)
    original_slab = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    original_c_s = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    original_kg = models.DecimalField(max_digits=12, decimal_places=3, default=0)
    
    remarks = models.TextField(blank=True, null=True)
    
    class Meta:
        # Note: unique_together will be added after data migration
        indexes = [
            models.Index(fields=['tenant_company_name', 'item']),
            models.Index(fields=['processing_center', 'store']),
        ]
    
    def __str__(self):
        tenant_name = self.tenant_company_name.name if self.tenant_company_name else "No Tenant"
        return f"{tenant_name} - {self.item} - {self.available_kg} KG"


class FreezingEntryTenant(BaseModel):
    freezing_date = models.DateField()
    voucher_number = models.CharField(max_length=50, unique=True)
    tenant_company_name = models.ForeignKey('Tenant', on_delete=models.CASCADE)

    total_slab = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    total_c_s = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    total_kg = models.DecimalField(max_digits=12, decimal_places=3, default=0)
    total_amount = models.DecimalField(max_digits=12, decimal_places=2, default=0)

    FREEZING_STATUS_CHOICES = [
        ('complete', 'Complete'),
        ('incomplete', 'Incomplete'),
    ]
    freezing_status = models.CharField(
        max_length=50,
        choices=FREEZING_STATUS_CHOICES,
        default='complete'
    )

    def __str__(self):
        return f"Freezing Entry Tenant - {self.freezing_date} - {self.voucher_number}"

class FreezingEntryTenantItem(BaseModel):
    freezing_entry = models.ForeignKey(
        FreezingEntryTenant,
        on_delete=models.CASCADE,
        related_name='items'
    )
    processing_center = models.ForeignKey('ProcessingCenter', on_delete=models.CASCADE, null=True, blank=True)
    store = models.ForeignKey('Store', on_delete=models.CASCADE, null=True, blank=True)
    item = models.ForeignKey('Item', on_delete=models.CASCADE)
    item_quality = models.ForeignKey('ItemQuality', on_delete=models.CASCADE, null=True, blank=True, default=None)
    unit = models.ForeignKey('PackingUnit', on_delete=models.CASCADE)
    glaze = models.ForeignKey('GlazePercentage', on_delete=models.CASCADE)
    freezing_category = models.ForeignKey('FreezingCategory', on_delete=models.CASCADE)
    brand = models.ForeignKey('ItemBrand', on_delete=models.CASCADE)
    species = models.ForeignKey('Species', on_delete=models.CASCADE, null=True, blank=True )
    peeling_type = models.ForeignKey('ItemType', on_delete=models.CASCADE, null=True, blank=True )
    grade = models.ForeignKey('ItemGrade', on_delete=models.CASCADE)

    slab_quantity = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    c_s_quantity = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    kg = models.DecimalField(max_digits=12, decimal_places=3, default=0)

    def __str__(self):
        return f"{self.item} - {self.kg} KG"


class ReturnTenant(BaseModel):
    return_date = models.DateField()  # Changed from freezing_date
    voucher_number = models.CharField(max_length=50, unique=True)
    tenant_company_name = models.ForeignKey('Tenant', on_delete=models.CASCADE)

    total_slab = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    total_c_s = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    total_kg = models.DecimalField(max_digits=12, decimal_places=3, default=0)
    total_amount = models.DecimalField(max_digits=12, decimal_places=2, default=0)

    RETURN_STATUS_CHOICES = [  # Changed from FREEZING_STATUS_CHOICES
        ('complete', 'Complete'),
        ('incomplete', 'Incomplete'),
    ]
    return_status = models.CharField(  # Changed from freezing_status
        max_length=50,
        choices=RETURN_STATUS_CHOICES,
        default='incomplete'
    )

    def __str__(self):
        return f"Return Tenant - {self.return_date} - {self.voucher_number}"

class ReturnTenantItem(BaseModel):
    return_entry = models.ForeignKey(  # Changed from freezing_entry
        ReturnTenant,
        on_delete=models.CASCADE,
        related_name='items'
    )

    processing_center = models.ForeignKey('ProcessingCenter', on_delete=models.CASCADE, null=True, blank=True)
    store = models.ForeignKey('Store', on_delete=models.CASCADE, null=True, blank=True)
    item = models.ForeignKey('Item', on_delete=models.CASCADE)
    item_quality = models.ForeignKey('ItemQuality', on_delete=models.CASCADE, null=True, blank=True, default=None)
    unit = models.ForeignKey('PackingUnit', on_delete=models.CASCADE)
    glaze = models.ForeignKey('GlazePercentage', on_delete=models.CASCADE)
    freezing_category = models.ForeignKey('FreezingCategory', on_delete=models.CASCADE)
    brand = models.ForeignKey('ItemBrand', on_delete=models.CASCADE)
    species = models.ForeignKey('Species', on_delete=models.CASCADE, null=True, blank=True )
    peeling_type = models.ForeignKey('ItemType', on_delete=models.CASCADE, null=True, blank=True )
    grade = models.ForeignKey('ItemGrade', on_delete=models.CASCADE)

    slab_quantity = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    c_s_quantity = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    kg = models.DecimalField(max_digits=12, decimal_places=3, default=0)

    def __str__(self):
        return f"{self.item} - {self.kg} KG (Returned)"



# PRE SHIPMENT WORK OUT model
class PreShipmentWorkOut(BaseModel):
    item = models.ForeignKey('Item', on_delete=models.CASCADE)
    item_quality = models.ForeignKey('ItemQuality', on_delete=models.CASCADE)

    unit = models.ForeignKey('PackingUnit', on_delete=models.CASCADE)
    glaze = models.ForeignKey('GlazePercentage', on_delete=models.CASCADE)
    category = models.ForeignKey('FreezingCategory', on_delete=models.CASCADE)
    brand = models.ForeignKey('ItemBrand', on_delete=models.CASCADE)

    def __str__(self):
        return f"Workout for {self.item}"

class PreShipmentWorkOutItem(BaseModel):
    workout = models.ForeignKey(PreShipmentWorkOut, on_delete=models.CASCADE, related_name="items")
    species = models.ForeignKey('Species', on_delete=models.CASCADE, null=True, blank=True)
    peeling_type = models.ForeignKey('ItemType', on_delete=models.CASCADE, null=True, blank=True)
    grade = models.ForeignKey('ItemGrade', on_delete=models.CASCADE)
    cartons = models.DecimalField(max_digits=100, decimal_places=2, default=0)
    quantity = models.DecimalField(max_digits=100, decimal_places=3, default=0)

    # we want rate
    usd_rate_per_kg = models.DecimalField(max_digits=100, decimal_places=2, default=0)
    usd_rate_item = models.DecimalField(max_digits=100, decimal_places=2, default=0)
    usd_rate_item_to_inr = models.DecimalField(max_digits=100, decimal_places=2, default=0)

    # we get rate
    usd_rate_per_kg_get = models.DecimalField(max_digits=100, decimal_places=2, default=0)
    usd_rate_item_get = models.DecimalField(max_digits=100, decimal_places=2, default=0)
    usd_rate_item_to_inr_get = models.DecimalField(max_digits=100, decimal_places=2, default=0)

    profit = models.DecimalField(max_digits=100, decimal_places=2, default=0, blank=True, null=True)
    loss = models.DecimalField(max_digits=100, decimal_places=2, default=0, blank=True, null=True)

    @property
    def profit_amount(self):
        return max(self.usd_rate_item_get - self.usd_rate_item, 0)

    @property
    def loss_amount(self):
        return max(self.usd_rate_item - self.usd_rate_item_get, 0)

    def __str__(self):
        return f"{self.species} - {self.grade} ({self.cartons} cartons)"



# models.py - Additional models for billing system

from django.db import models
from django.utils import timezone
from datetime import timedelta
from decimal import Decimal
from django.db import models
from django.utils import timezone
from django.db.models import Sum
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from decimal import Decimal, ROUND_HALF_UP
from datetime import timedelta


class TenantBillingConfiguration(models.Model):
    tenant = models.OneToOneField(
        'Tenant',
        on_delete=models.CASCADE,
        related_name='billing_config'
    )
    billing_start_date = models.DateField()
    billing_frequency_days = models.PositiveIntegerField(
        help_text="Number of days between automatic bill generation"
    )
    last_bill_generated_date = models.DateField(null=True, blank=True)
    next_bill_date = models.DateField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs):
        if not self.next_bill_date and self.billing_start_date:
            self.next_bill_date = self.billing_start_date + timedelta(days=self.billing_frequency_days)
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.tenant.company_name} - Every {self.billing_frequency_days} days"


class TenantBill(models.Model):
    BILL_STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('finalized', 'Finalized'),
        ('sent', 'Sent'),
        ('paid', 'Paid'),
        ('cancelled', 'Cancelled'),
    ]

    tenant = models.ForeignKey('Tenant', on_delete=models.CASCADE, related_name='bills')
    bill_number = models.CharField(max_length=50, unique=True)
    bill_date = models.DateField(default=timezone.now)
    from_date = models.DateField()
    to_date = models.DateField()

    total_slabs = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    total_c_s = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    total_kg = models.DecimalField(max_digits=12, decimal_places=3, default=0)
    total_amount = models.DecimalField(max_digits=12, decimal_places=2, default=0)

    status = models.CharField(max_length=20, choices=BILL_STATUS_CHOICES, default='draft')

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs):
        if not self.bill_number:
            self.bill_number = self.generate_bill_number()
        super().save(*args, **kwargs)

    def generate_bill_number(self):
        from datetime import datetime
        date_str = datetime.now().strftime('%Y%m%d')
        last_bill = TenantBill.objects.filter(
            bill_number__startswith=f'BILL-{date_str}'
        ).order_by('-bill_number').first()

        if last_bill:
            last_num = int(last_bill.bill_number.split('-')[-1])
            new_num = last_num + 1
        else:
            new_num = 1

        return f'BILL-{date_str}-{new_num:04d}'

    def recalc_totals(self):
        """Recalculate bill totals from items."""
        totals = self.items.aggregate(
            amt=Sum('line_total'),
            slabs=Sum('slab_quantity'),
            cs=Sum('c_s_quantity'),
            kg=Sum('kg_quantity'),
        )
        self.total_amount = totals['amt'] or Decimal('0.00')
        self.total_slabs = totals['slabs'] or Decimal('0.00')
        self.total_c_s = totals['cs'] or Decimal('0.00')
        self.total_kg = totals['kg'] or Decimal('0.00')
        self.save(update_fields=['total_amount', 'total_slabs', 'total_c_s', 'total_kg'])

    def __str__(self):
        return f"Bill {self.bill_number} - {self.tenant.company_name}"


class TenantBillItem(models.Model):
    bill = models.ForeignKey(TenantBill, on_delete=models.CASCADE, related_name='items')
    freezing_entry = models.ForeignKey('FreezingEntryTenant', on_delete=models.CASCADE)
    freezing_entry_item = models.ForeignKey('FreezingEntryTenantItem', on_delete=models.CASCADE)

    days_stored = models.PositiveIntegerField()
    tariff_per_day = models.DecimalField(max_digits=8, decimal_places=2)

    slab_quantity = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    c_s_quantity = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    kg_quantity = models.DecimalField(max_digits=12, decimal_places=3, default=0)

    line_total = models.DecimalField(max_digits=12, decimal_places=2, default=0)

    def save(self, *args, **kwargs):
        # Always recalc line_total with Decimal
        kg = Decimal(str(self.kg_quantity or 0))
        days = Decimal(str(self.days_stored or 0))
        tariff = Decimal(str(self.tariff_per_day or 0))

        if days < 1:
            days = Decimal('1')

        self.line_total = (kg * days * tariff).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.bill.bill_number} - {self.freezing_entry_item.item}"


# --- Signals to auto-update bill totals when items change ---
@receiver(post_save, sender=TenantBillItem)
def _update_bill_on_item_save(sender, instance, **kwargs):
    instance.bill.recalc_totals()


@receiver(post_delete, sender=TenantBillItem)
def _update_bill_on_item_delete(sender, instance, **kwargs):
    instance.bill.recalc_totals()






class Stock(models.Model):
    store = models.ForeignKey(Store, on_delete=models.CASCADE)
    brand = models.ForeignKey(ItemBrand, on_delete=models.CASCADE)
    item = models.ForeignKey(Item, on_delete=models.CASCADE)
    item_quality = models.ForeignKey(ItemQuality, on_delete=models.CASCADE, null=True, blank=True)
    freezing_category = models.ForeignKey(FreezingCategory, on_delete=models.CASCADE, null=True, blank=True)
    peeling_type = models.ForeignKey(ItemType, on_delete=models.CASCADE, null=True, blank=True)

    # Changed from CharField to ForeignKey
    unit = models.ForeignKey(PackingUnit, on_delete=models.SET_NULL, null=True, blank=True)
    glaze = models.ForeignKey(GlazePercentage, on_delete=models.SET_NULL, null=True, blank=True)
    species = models.ForeignKey(Species, on_delete=models.SET_NULL, null=True, blank=True)
    item_grade = models.ForeignKey(ItemGrade, on_delete=models.SET_NULL, null=True, blank=True)

    cs_quantity = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    kg_quantity = models.DecimalField(max_digits=10, decimal_places=3, default=0)

    usd_rate_per_kg = models.DecimalField(max_digits=100, decimal_places=2, default=0)
    usd_rate_item = models.DecimalField(max_digits=100, decimal_places=2, default=0)
    usd_rate_item_to_inr = models.DecimalField(max_digits=100, decimal_places=2, default=0)

    class Meta:
        # Added freezing_category to unique constraint
        unique_together = [
            'store', 'item', 'brand', 'item_quality', 'unit', 'glaze', 
            'species', 'item_grade', 'peeling_type', 'freezing_category'
        ]

    def __str__(self):
        return f"{self.item.name} ({self.store.name})"



class StoreTransfer(models.Model):
    voucher_no = models.CharField(max_length=50, unique=True)
    date = models.DateField()
    from_store = models.ForeignKey(Store, on_delete=models.CASCADE, related_name='transfers_from')
    to_store = models.ForeignKey(Store, on_delete=models.CASCADE, related_name='transfers_to')

    def __str__(self):
        return f"{self.voucher_no} ({self.date})"

class StoreTransferItem(models.Model):
    transfer = models.ForeignKey(StoreTransfer, on_delete=models.CASCADE, related_name='items')
    item = models.ForeignKey(Item, on_delete=models.CASCADE)
    brand = models.ForeignKey(ItemBrand, on_delete=models.CASCADE, null=True, blank=True)
    category = models.ForeignKey(ItemCategory, on_delete=models.CASCADE, null=True, blank=True)
    item_quality = models.ForeignKey(ItemQuality, on_delete=models.CASCADE, null=True, blank=True)
    freezing_category = models.ForeignKey(FreezingCategory, on_delete=models.CASCADE, null=True, blank=True)

    # Changed from CharField to ForeignKey
    unit = models.ForeignKey(PackingUnit, on_delete=models.SET_NULL, null=True, blank=True)
    glaze = models.ForeignKey(GlazePercentage, on_delete=models.SET_NULL, null=True, blank=True)
    species = models.ForeignKey(Species, on_delete=models.SET_NULL, null=True, blank=True)
    item_grade = models.ForeignKey(ItemGrade, on_delete=models.SET_NULL, null=True, blank=True)

    cs_quantity = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    kg_quantity = models.DecimalField(max_digits=10, decimal_places=3, default=0)







# --- Spot Agent Voucher --- fix
class SpotAgentVoucher(models.Model):
    voucher_no = models.CharField(max_length=50, unique=True)
    agent = models.ForeignKey('PurchasingAgent', on_delete=models.CASCADE)
    date = models.DateField(default=timezone.now)
    description = models.TextField(blank=True, null=True)
    remain_amount = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    receipt = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    payment = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    total_amount = models.DecimalField(max_digits=12, decimal_places=2, default=0)

    def __str__(self):
        return f"Spot Agent Voucher {self.voucher_no} - {self.agent.name}"


# --- Supervisor Voucher ---
class SupervisorVoucher(models.Model):
    voucher_no = models.CharField(max_length=50, unique=True)
    supervisor = models.ForeignKey('PurchasingSupervisor', on_delete=models.CASCADE)
    date = models.DateField(default=timezone.now)
    description = models.TextField(blank=True, null=True)
    remain_amount = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    receipt = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    payment = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    total_amount = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    def __str__(self):

        return f"Supervisor Voucher {self.voucher_no} - {self.supervisor.name}"


# --- Local Purchase Voucher ---
class LocalPurchaseVoucher(models.Model):
    voucher_no = models.CharField(max_length=50, unique=True)
    party = models.ForeignKey('LocalPurchase', on_delete=models.CASCADE)
    date = models.DateField(default=timezone.now)
    description = models.TextField(blank=True, null=True)
    remain_amount = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    receipt = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    payment = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    total_amount = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    def __str__(self):

        return f"Local Purchase Voucher {self.voucher_no} - {self.party}"


# --- Peeling Shed Voucher ---
class PeelingShedVoucher(models.Model):
    voucher_no = models.CharField(max_length=50, unique=True)
    shed = models.ForeignKey('Shed', on_delete=models.CASCADE)
    date = models.DateField(default=timezone.now)
    description = models.TextField(blank=True, null=True)
    remain_amount = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    receipt = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    payment = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    total_amount = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    def __str__(self):

        return f"Peeling Shed Voucher {self.voucher_no} - {self.shed.name}"


# --- Tenant Voucher ---
class TenantVoucher(models.Model):
    voucher_no = models.CharField(max_length=50, unique=True)
    tenant = models.ForeignKey("Tenant", on_delete=models.CASCADE)  # assuming you already have a Tenant model
    date = models.DateField(default=timezone.now)
    description = models.TextField(blank=True, null=True)
    remain_amount = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    receipt = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    payment = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    total_amount = models.DecimalField(max_digits=12, decimal_places=2, default=0)

    def __str__(self):
        return f"Tenant Voucher {self.voucher_no} - {self.tenant.name}"


# sale data base models






class Buyer(BaseModel):
    """Buyer/Consignee Information"""
    name = models.CharField(max_length=200)
    address = models.TextField()
    country = models.CharField(max_length=100)
    contact_person = models.CharField(max_length=150, blank=True, null=True)
    email = models.EmailField(blank=True, null=True)
    phone = models.CharField(max_length=20, blank=True, null=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.name} - {self.country}"


class ShipmentDestination(BaseModel):
    """Port and Destination Information"""
    country = models.CharField(max_length=100)
    port_of_loading = models.CharField(max_length=150)
    port_of_discharge = models.CharField(max_length=150)
    final_destination = models.CharField(max_length=150, blank=True, null=True)

    def __str__(self):
        return f"{self.port_of_loading} to {self.port_of_discharge}"




class SalesEntry(BaseModel):
    """Main Sales/Shipment Entry (Commercial Invoice)"""
    
    # Invoice Details
    voucher_no = models.CharField(max_length=50, unique=True)
    date = models.DateField(default=timezone.now)
    invoice_no = models.CharField(max_length=50, unique=True)
    hs_code = models.CharField(max_length=50, blank=True, null=True)
    
    # Buyer Information
    buyer = models.ForeignKey(Buyer, on_delete=models.CASCADE, related_name='sales_entries')
    buyer_order_no = models.CharField(max_length=100, blank=True, null=True)
    purchase_order_date = models.DateField(blank=True, null=True)
    
    # Exporter Information
    exporter_name = models.CharField(max_length=200, default="AM FISHERIES")
    exporter_address = models.TextField(blank=True, null=True)
    exporter_iec_code = models.CharField(max_length=50, blank=True, null=True)
    
    # Shipping Details
    exporters_ref_no = models.CharField(max_length=100, blank=True, null=True)
    steamer_line_no = models.CharField(max_length=100, blank=True, null=True)
    customs_seal_no = models.CharField(max_length=100, blank=True, null=True)
    container_no = models.CharField(max_length=100, blank=True, null=True)
    rex_reg_no = models.CharField(max_length=100, blank=True, null=True)
    narrative = models.TextField(blank=True, null=True)
    
    # Port/Destination (simplified)
    country_of_origin = models.CharField(max_length=100, default="COCHIN, INDIA")
    country_of_destination = models.CharField(max_length=100)  # Port of Discharge
    
    # Tax/Financial
    gstin_number = models.CharField(max_length=50, blank=True, null=True)
    igst_number = models.CharField(max_length=50, blank=True, null=True)
    
    # Totals
    total_quantity = models.DecimalField(max_digits=12, decimal_places=3, default=0)
    total_amount_usd = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    total_taxable_value = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    total_tax_amount = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    total_amount_after_tax = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    
    # Additional
    processed_by = models.TextField(blank=True, null=True)
    declaration_text = models.TextField(blank=True, null=True)
    bank_details = models.TextField(blank=True, null=True)


    # products
    item = models.ForeignKey('Item', on_delete=models.CASCADE, related_name='sales_entries_items')
    item_quality = models.ForeignKey('ItemQuality', on_delete=models.CASCADE, null=True, blank=True , default=None)
    unit = models.ForeignKey('PackingUnit', on_delete=models.CASCADE)
    glaze = models.ForeignKey('GlazePercentage', on_delete=models.CASCADE)
    freezing_category = models.ForeignKey('FreezingCategory', on_delete=models.CASCADE)
    brand = models.ForeignKey('ItemBrand', on_delete=models.CASCADE, null=True, blank=True , default=None)



    
    # Status
    STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('confirmed', 'Confirmed'),
        ('shipped', 'Shipped'),
        ('delivered', 'Delivered'),
        ('cancelled', 'Cancelled'),
    ]
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='draft')
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class SalesEntryItem(BaseModel):
    """
    Individual Items in Sales Entry
    Only fields highlighted in yellow from the invoice
    """
    
    sales_entry = models.ForeignKey(
        SalesEntry, 
        on_delete=models.CASCADE, 
        related_name='items'
    )
    
    # Core Item Information (Yellow highlighted fields only)
  
    species = models.ForeignKey(Species, on_delete=models.CASCADE, null=True, blank=True)
    peeling_type = models.ForeignKey(ItemType, on_delete=models.SET_NULL, null=True, blank=True)
    grade = models.ForeignKey(ItemGrade, on_delete=models.SET_NULL, null=True, blank=True)
    
    # Quantities (Yellow highlighted)
    cartons = models.DecimalField(max_digits=10, decimal_places=2)
    quantity = models.DecimalField(max_digits=10, decimal_places=3)  # This is "Quantity" in invoice
    
    # Pricing (Yellow highlighted)
    price_usd_per_kg = models.DecimalField(max_digits=10, decimal_places=2)
    amount_usd = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    
    # Tax (Yellow highlighted)
    taxable_value = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    tax_rate = models.DecimalField(max_digits=5, decimal_places=2, default=5.00)
    tax_amount = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    total_amount = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    
    # Stock Reference (for inventory tracking)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)




class Notification(models.Model):
    """
    Store system-wide notifications for activities
    """
    
    NOTIFICATION_TYPES = [
        ('success', 'Success'),
        ('info', 'Info'),
        ('warning', 'Warning'),
        ('danger', 'Danger'),
        ('primary', 'Primary'),
    ]
    
    ACTION_TYPES = [
        ('create', 'Created'),
        ('update', 'Updated'),
        ('delete', 'Deleted'),
        ('purchase', 'Purchase'),
        ('sale', 'Sale'),
        ('transfer', 'Transfer'),
        ('freezing', 'Freezing'),
        ('billing', 'Billing'),
        ('payment', 'Payment'),
        ('voucher', 'Voucher'),
        ('login', 'Login'),
        ('other', 'Other'),
    ]
    
    # Who performed the action
    user = models.ForeignKey(
        CustomUser, 
        on_delete=models.CASCADE, 
        related_name='created_notifications'
    )
    
    # Notification details
    notification_type = models.CharField(
        max_length=20, 
        choices=NOTIFICATION_TYPES,
        default='info'
    )
    
    action_type = models.CharField(
        max_length=20,
        choices=ACTION_TYPES,
        default='other'
    )
    
    title = models.CharField(max_length=255)
    message = models.TextField()
    
    # Optional: link to related page
    link_url = models.CharField(max_length=500, blank=True, null=True)
    link_text = models.CharField(max_length=100, blank=True, null=True)
    
    # Read/Unread tracking
    read_by = models.ManyToManyField(
        CustomUser, 
        related_name='read_notifications',
        blank=True
    )
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    is_active = models.BooleanField(default=True, db_index=True)
    
    # Optional: Target specific users (leave empty for all users)
    target_users = models.ManyToManyField(
        CustomUser,
        related_name='received_notifications',
        blank=True
    )
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['-created_at']),
            models.Index(fields=['user', '-created_at']),
            models.Index(fields=['is_active', '-created_at']),
        ]
    
    def __str__(self):
        return f"{self.title} - {self.created_at.strftime('%Y-%m-%d %H:%M')}"
    
    def mark_as_read(self, user):
        """Mark notification as read for a specific user"""
        self.read_by.add(user)
    
    def is_read_by(self, user):
        """Check if notification is read by user"""
        return self.read_by.filter(id=user.id).exists()
    
    @property
    def get_icon(self):
        """Get Bootstrap icon based on action type"""
        icons = {
            'create': 'bi-plus-circle-fill',
            'update': 'bi-pencil-fill',
            'delete': 'bi-trash-fill',
            'purchase': 'bi-cart-fill',
            'sale': 'bi-cash-coin',
            'transfer': 'bi-arrow-left-right',
            'freezing': 'bi-snow',
            'billing': 'bi-receipt',
            'payment': 'bi-credit-card',
            'voucher': 'bi-file-earmark-text',
            'login': 'bi-box-arrow-in-right',
            'other': 'bi-bell-fill',
    }
        return icons.get(self.action_type, 'bi-bell-fill')
    
    @property
    def time_since(self):
        """Human readable time since creation"""
        from django.utils.timesince import timesince
        return timesince(self.created_at)










# Add these new models to your models.py


class StockMovement(models.Model):
    """
    Track all stock movements for reporting
    This creates an audit trail of every stock change
    """
    
    MOVEMENT_TYPES = [
        ('opening', 'Opening Balance'),
        ('freezing_spot', 'Freezing - Spot Purchase'),
        ('freezing_local', 'Freezing - Local Purchase'),
        ('freezing_tenant', 'Freezing - Tenant'),
        ('shipment', 'Shipment/Sale'),
        ('transfer_in', 'Transfer IN'),
        ('transfer_out', 'Transfer OUT'),
        ('adjustment_plus', 'Adjustment +'),
        ('adjustment_minus', 'Adjustment -'),
        ('return_tenant', 'Return from Tenant'),
    ]
    
    # Reference fields
    movement_type = models.CharField(max_length=50, choices=MOVEMENT_TYPES)
    movement_date = models.DateField(default=timezone.now)
    voucher_number = models.CharField(max_length=100, blank=True, null=True)
    
    # Stock identification (same as Stock model)
    store = models.ForeignKey('Store', on_delete=models.CASCADE)
    item = models.ForeignKey('Item', on_delete=models.CASCADE)
    brand = models.ForeignKey('ItemBrand', on_delete=models.CASCADE)
    item_quality = models.ForeignKey('ItemQuality', on_delete=models.CASCADE, null=True, blank=True)
    freezing_category = models.ForeignKey('FreezingCategory', on_delete=models.CASCADE, null=True, blank=True)
    peeling_type = models.ForeignKey('ItemType', on_delete=models.CASCADE, null=True, blank=True)
    unit = models.ForeignKey('PackingUnit', on_delete=models.SET_NULL, null=True, blank=True)
    glaze = models.ForeignKey('GlazePercentage', on_delete=models.SET_NULL, null=True, blank=True)
    species = models.ForeignKey('Species', on_delete=models.SET_NULL, null=True, blank=True)
    item_grade = models.ForeignKey('ItemGrade', on_delete=models.SET_NULL, null=True, blank=True)
    
    # Quantities (can be positive or negative)
    cs_quantity = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    kg_quantity = models.DecimalField(max_digits=12, decimal_places=3, default=0)
    slab_quantity = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    
    # Rates at time of movement
    usd_rate_per_kg = models.DecimalField(max_digits=100, decimal_places=2, default=0)
    usd_rate_item = models.DecimalField(max_digits=100, decimal_places=2, default=0)
    usd_rate_item_to_inr = models.DecimalField(max_digits=100, decimal_places=2, default=0)
    
    # Reference to source transaction (optional)
    reference_model = models.CharField(max_length=100, blank=True, null=True)  # e.g., 'FreezingEntrySpot'
    reference_id = models.CharField(max_length=50, blank=True, null=True)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey('CustomUser', on_delete=models.SET_NULL, null=True, blank=True)
    notes = models.TextField(blank=True, null=True)
    
    class Meta:
        ordering = ['movement_date', 'created_at']
        indexes = [
            models.Index(fields=['store', 'item', 'movement_date']),
            models.Index(fields=['movement_type', 'movement_date']),
            models.Index(fields=['voucher_number']),
        ]
    
    def __str__(self):
        return f"{self.movement_type} - {self.item.name} ({self.movement_date})"


class StockSnapshot(models.Model):
    """
    Daily snapshot of stock for fast reporting
    Run this at end of each day to capture closing balances
    """
    
    snapshot_date = models.DateField(unique=True)
    
    # Stock identification
    store = models.ForeignKey('Store', on_delete=models.CASCADE)
    item = models.ForeignKey('Item', on_delete=models.CASCADE)
    brand = models.ForeignKey('ItemBrand', on_delete=models.CASCADE)
    item_quality = models.ForeignKey('ItemQuality', on_delete=models.CASCADE, null=True, blank=True)
    freezing_category = models.ForeignKey('FreezingCategory', on_delete=models.CASCADE, null=True, blank=True)
    peeling_type = models.ForeignKey('ItemType', on_delete=models.CASCADE, null=True, blank=True)
    unit = models.ForeignKey('PackingUnit', on_delete=models.SET_NULL, null=True, blank=True)
    glaze = models.ForeignKey('GlazePercentage', on_delete=models.SET_NULL, null=True, blank=True)
    species = models.ForeignKey('Species', on_delete=models.SET_NULL, null=True, blank=True)
    item_grade = models.ForeignKey('ItemGrade', on_delete=models.SET_NULL, null=True, blank=True)
    
    # Closing balances
    cs_quantity = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    kg_quantity = models.DecimalField(max_digits=12, decimal_places=3, default=0)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = [
            'snapshot_date', 'store', 'item', 'brand', 'item_quality', 
            'unit', 'glaze', 'species', 'item_grade', 'peeling_type', 'freezing_category'
        ]
        ordering = ['-snapshot_date']
        indexes = [
            models.Index(fields=['snapshot_date', 'store']),
        ]
    
    def __str__(self):
        return f"{self.item.name} - {self.snapshot_date} ({self.store.name})"








