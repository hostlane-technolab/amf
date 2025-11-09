from django import forms
from django.contrib.auth.forms import ReadOnlyPasswordHashField
from adminapp.models import CustomUser  # adjust if CustomUser is elsewhere
from django.forms import inlineformset_factory
from django.utils.timezone import now
from .models import *
from django.core.exceptions import ValidationError




# nammude client paranjhu name chage cheyyan athu too risk anu athukondu html name mathre matittullu
# item category ennu parayunne elam item quality anu  model name itemQuality
# item group ennu parayunne elam item category anu model name itemCategory


class CustomUserCreationForm(forms.ModelForm):
    password = forms.CharField(label='Password', widget=forms.PasswordInput)

    class Meta:
        model = CustomUser
        fields = [ 'role','full_name', 'mobile', 'email', 'address', 'profile_picture', 'password']

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password"])
        if commit:
            user.save()
        return user
    
class CustomUserUpdateForm(forms.ModelForm):
    password = forms.CharField(
        label='Password', 
        widget=forms.PasswordInput(attrs={'placeholder': 'Leave blank to keep current password'}),
        required=False,
        help_text="Leave blank to keep current password"
    )
    
    class Meta:
        model = CustomUser
        fields = [
            'role', 'full_name', 'mobile', 'email', 
            'address', 'profile_picture', 'is_active'
        ]
        widgets = {
            'address': forms.Textarea(attrs={'rows': 3}),
            'email': forms.EmailInput(),
            'mobile': forms.TextInput(attrs={'maxlength': 15}),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Password is not in Meta.fields, so we add it manually
        self.fields['password'].required = False
        
        # Add CSS classes if needed
        for field_name, field in self.fields.items():
            field.widget.attrs.update({'class': 'form-control'})
    
    def clean_email(self):
        email = self.cleaned_data.get('email')
        if email:
            # Check if email exists for other users (excluding current instance)
            qs = CustomUser.objects.filter(email=email)
            if self.instance and self.instance.pk:
                qs = qs.exclude(pk=self.instance.pk)
            if qs.exists():
                raise forms.ValidationError("A user with this email already exists.")
        return email
    
    def clean_mobile(self):
        mobile = self.cleaned_data.get('mobile')
        if mobile:
            # Check if mobile exists for other users (excluding current instance)
            qs = CustomUser.objects.filter(mobile=mobile)
            if self.instance and self.instance.pk:
                qs = qs.exclude(pk=self.instance.pk)
            if qs.exists():
                raise forms.ValidationError("A user with this mobile number already exists.")
        return mobile
    
    def clean_password(self):
        """Additional validation for password"""
        password = self.cleaned_data.get('password')
        # Strip whitespace to handle cases where user enters only spaces
        if password:
            password = password.strip()
            if len(password) < 8:
                raise forms.ValidationError("Password must be at least 8 characters long.")
        return password or None  # Return None instead of empty string
    
    def save(self, commit=True):
        user = super().save(commit=False)
        
        # Only update password if it's provided and not empty
        password = self.cleaned_data.get("password")
        if password:  # This will be None or a non-empty string
            user.set_password(password)
        # If password is None or empty, the existing password remains unchanged
        
        if commit:
            user.save()
        return user


# Operational & Location
class ProcessingCenterForm(forms.ModelForm):
    class Meta:
        model = ProcessingCenter
        fields = '__all__'

class StoreForm(forms.ModelForm):
    class Meta:
        model = Store
        fields = '__all__'

class ShedForm(forms.ModelForm):
    class Meta:
        model = Shed
        fields = ['name', 'code', 'address', 'contact_number', 'capacity_per_day_kg']

class ShedItemForm(forms.ModelForm):
    class Meta:
        model = ShedItem
        fields = ['item', 'item_type', 'amount', 'unit']

ShedItemFormSet = inlineformset_factory(
    parent_model=Shed,
    model=ShedItem,
    form=ShedItemForm,
    extra=1,
    can_delete=True
)

class PurchasingSpotForm(forms.ModelForm):
    class Meta:
        model = PurchasingSpot
        fields = '__all__'

class LocalPartyForm(forms.ModelForm):
    class Meta:
        model = LocalParty
        fields = '__all__'




# Personnel
class PurchasingSupervisorForm(forms.ModelForm):
    joining_date = forms.DateField(
        input_formats=['%d/%m/%Y'],   # accepts DD/MM/YYYY
        widget=forms.DateInput(format='%d/%m/%Y', attrs={'placeholder': 'DD/MM/YYYY'})
    )
    class Meta:
        model = PurchasingSupervisor
        fields = '__all__'
        exclude = ['is_active', 'created_at']


class PurchasingAgentForm(forms.ModelForm):
    class Meta:
        model = PurchasingAgent
        fields = '__all__'

# Item & Product
class ItemCategoryForm(forms.ModelForm):
    class Meta:
        model = ItemCategory
        fields = '__all__'

class ItemForm(forms.ModelForm):
    class Meta:
        model = Item
        fields = '__all__'

class ItemQualityForm(forms.ModelForm):
    class Meta:
        model = ItemQuality
        fields = '__all__'

# forms.py
class SpeciesForm(forms.ModelForm):
    class Meta:
        model = Species
        fields = ['item', 'name', 'code']

class ItemGradeForm(forms.ModelForm):
    class Meta:
        model = ItemGrade
        fields = '__all__'
        exclude = ['species']


    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        item_id = None

        # Try getting item from bound form data (POST)
        if 'item' in self.data:
            item_id = self.data.get('item')

        # Or from initial data (GET with initial value)
        elif 'item' in self.initial:
            item_id = self.initial.get('item')

        # Or from instance (if editing existing object)
        elif self.instance and self.instance.pk:
            item_id = self.instance.item_id

        # if item_id:
        #     self.fields['species'].queryset = Species.objects.filter(item_id=item_id)
        # else:
        #     self.fields['species'].queryset = Species.objects.none()

class FreezingCategoryForm(forms.ModelForm):
    class Meta:
        model = FreezingCategory
        exclude = ['created_at','is_active']
        fields = '__all__'

class PackingUnitForm(forms.ModelForm):
    class Meta:
        model = PackingUnit
        fields = '__all__'

class GlazePercentageForm(forms.ModelForm):
    class Meta:
        model = GlazePercentage
        fields = '__all__'

class ItemBrandForm(forms.ModelForm):
    class Meta:
        model = ItemBrand
        fields = '__all__'

class ItemTypeForm(forms.ModelForm):
    class Meta:
        model = ItemType
        fields = '__all__'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.fields['item'].queryset = Item.objects.filter(is_peeling=True)



# Financial & Expense
class TenantForm(forms.ModelForm):
    class Meta:
        model = Tenant
        fields = '__all__'

class TenantFreezingTariffForm(forms.ModelForm):
    class Meta:
        model = TenantFreezingTariff
        fields = ['category', 'tariff']
        widgets = {
            'category': forms.Select(attrs={
                'class': 'form-control',
            }),
            'tariff': forms.NumberInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter tariff amount',
                'min': '0',
                'step': '0.01',  # Allow decimal values
            }),
        }
        labels = {
            'category': 'Freezing Category',
            'tariff': 'Tariff (₹/kg)',
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # ✅ FIXED: Use 'category' not 'freezing_category'
        self.fields['category'].queryset = FreezingCategory.objects.filter(is_active=True)
        
TenantFreezingTariffFormSet = inlineformset_factory(
    Tenant,
    TenantFreezingTariff,
    form=TenantFreezingTariffForm,
    fields=['category', 'tariff'],
    extra=1,
    can_delete=True,
    validate_min=False,
    validate_max=False,
)




class PurchaseOverheadForm(forms.ModelForm):
    class Meta:
        model = PurchaseOverhead
        exclude = ['created_at','is_active']        
        fields = '__all__'

class PeelingOverheadForm(forms.ModelForm):
    class Meta:
        model = PeelingOverhead
        exclude = ['created_at','is_active']
        fields = '__all__'

class ProcessingOverheadForm(forms.ModelForm):
    class Meta:
        model = ProcessingOverhead
        exclude = ['created_at','is_active']
        fields = '__all__'

class ShipmentOverheadForm(forms.ModelForm):
    class Meta:
        model = ShipmentOverhead
        exclude = ['created_at','is_active']
        fields = '__all__'

class SettingsForm(forms.ModelForm):
    class Meta:
        model = Settings
        fields = ['dollar_rate_to_inr', 'vehicle_rent_km']

# forms for create a Purchase Entry 
class SpotPurchaseForm(forms.ModelForm):

    class Meta:
        model = SpotPurchase
        fields = ['date', 'voucher_number', 'spot', 'supervisor', 'agent']
        widgets = {
            'date': forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),
            'voucher_number': forms.TextInput(attrs={'class': 'form-control'}),
            'spot': forms.Select(attrs={'class': 'form-control'}),
            'supervisor': forms.Select(attrs={'class': 'form-control'}),
            'agent': forms.Select(attrs={'class': 'form-control'}),
        }
        
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Only show active supervisors
        self.fields['supervisor'].queryset = PurchasingSupervisor.objects.filter(is_active=True)


class SpotPurchaseItemForm(forms.ModelForm):
    class Meta:
        model = SpotPurchaseItem
        fields = ['item','total_rate', 'quantity', 'rate', 'boxes']
        widgets = {
            'item': forms.Select(attrs={'class': 'form-control'}),
            'quantity': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.001'}),
            'boxes': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.001'}),
            'total_rate': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01'}),
            'rate': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01'}),
        }

SpotPurchaseItemFormSet = inlineformset_factory(
    SpotPurchase,
    SpotPurchaseItem,
    form=SpotPurchaseItemForm,
    extra=1,
    can_delete=True
)

class SpotPurchaseExpenseForm(forms.ModelForm):
    class Meta:
        model = SpotPurchaseExpense
        fields = [
            'ice_expense',
            'vehicle_rent',
            'loading_and_unloading',
            'peeling_charge',
            'other_expense'
        ]
        widgets = {
            'ice_expense': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01'}),
            'vehicle_rent': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01'}),
            'loading_and_unloading': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01'}),
            'peeling_charge': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01'}),
            'other_expense': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01'}),
        }

# local purchase forms
class LocalPurchaseForm(forms.ModelForm):


    class Meta:
        model = LocalPurchase
        fields = ['date', 'voucher_number', 'party_name']
        widgets = {
            'date': forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),
            'voucher_number': forms.TextInput(attrs={'class': 'form-control'}),
            'party_name': forms.Select(attrs={'class': 'form-control'}),
        }

class LocalPurchaseItemForm(forms.ModelForm):
    class Meta:
        model = LocalPurchaseItem
        exclude = ['purchase', 'amount','species']
        widgets = {
            'item': forms.Select(attrs={'class': 'form-control'}),
            'item_quality': forms.Select(attrs={'class': 'form-control', 'id': 'id_item_quality'}),
            'grade': forms.Select(attrs={'class': 'form-control'}),
            'item_type': forms.Select(attrs={'class': 'form-control'}),
            'quantity': forms.NumberInput(attrs={'class': 'form-control quantity-input', 'step': '0.001'}),
            'rate': forms.NumberInput(attrs={'class': 'form-control rate-input', 'step': '0.01'}),
        }

LocalPurchaseItemFormSet = inlineformset_factory(
    LocalPurchase,
    LocalPurchaseItem,
    form=LocalPurchaseItemForm,
    extra=1,
    can_delete=True
)






# Peeling Shed Supply Form
class PeelingShedSupplyForm(forms.ModelForm):
    class Meta:
        model = PeelingShedSupply
        fields = '__all__'
        widgets = {
            'date': forms.DateInput(attrs={'type': 'date'}),
            'spot_purchase_date': forms.DateInput(attrs={'type': 'date'}),
        }

PeelingShedPeelingTypeFormSet = inlineformset_factory(
    PeelingShedSupply,
    PeelingShedPeelingType,
    fields=('item', 'item_type', 'amount', 'unit'),
    extra=0,
    can_delete=False
)



# Freezing Entry Spot Form


class FreezingEntrySpotForm(forms.ModelForm):
    class Meta:
        model = FreezingEntrySpot
        fields = '__all__'
        widgets = {
            'freezing_date': forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),
            'voucher_number': forms.TextInput(attrs={'class': 'form-control'}),

            'spot_purchase_date': forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),
            'spot': forms.Select(attrs={'class': 'form-control'}),
            'spot_agent': forms.Select(attrs={'class': 'form-control'}),
            'spot_supervisor': forms.Select(attrs={'class': 'form-control'}),
            'total_usd': forms.NumberInput(attrs={'readonly': 'readonly', 'class': 'form-control'}),
            'total_inr': forms.NumberInput(attrs={'readonly': 'readonly', 'class': 'form-control'}),
            'total_slab': forms.NumberInput(attrs={'readonly': 'readonly', 'class': 'form-control'}),
            'total_c_s': forms.NumberInput(attrs={'readonly': 'readonly', 'class': 'form-control'}),
            'total_kg': forms.NumberInput(attrs={'readonly': 'readonly', 'class': 'form-control'}),
            'total_yield_percentage': forms.NumberInput(attrs={'readonly': 'readonly', 'class': 'form-control'}),

            'freezing_status': forms.Select(attrs={'class': 'form-control'}),
        }

class FreezingEntrySpotItemForm(forms.ModelForm):
    class Meta:
        model = FreezingEntrySpotItem
        fields = '__all__'
        widgets = {
            'processing_center': forms.Select(attrs={'class': 'form-control'}),
            'store': forms.Select(attrs={'class': 'form-control'}),
            'shed': forms.Select(attrs={'class': 'form-control'}),

            # 🔹 Add "item-select" for AJAX binding
            'item': forms.Select(attrs={'class': 'form-control item-select'}),
            'item_quality': forms.Select(attrs={'class': 'form-control'}),

            'unit': forms.Select(attrs={'class': 'form-control unit-select', 'data-units': '{}'}),
            'glaze': forms.Select(attrs={'class': 'form-control'}),
            'freezing_category': forms.Select(attrs={'class': 'form-control'}),
            'brand': forms.Select(attrs={'class': 'form-control'}),

            # 🔹 Add "species-select" + "peeling-select" for AJAX population
            'species': forms.Select(attrs={'class': 'form-control species-select'}),
            'peeling_type': forms.Select(attrs={'class': 'form-control peeling-select'}),

            'grade': forms.Select(attrs={'class': 'form-control'}),

            'slab_quantity': forms.NumberInput(attrs={'class': 'form-control slab-quantity'}),
            'c_s_quantity': forms.NumberInput(attrs={'class': 'form-control cs-quantity'}),
            'kg': forms.NumberInput(attrs={'class': 'form-control kg'}),

            'usd_rate_per_kg': forms.NumberInput(attrs={'class': 'form-control usd-rate-per-kg'}),
            'usd_rate_item': forms.NumberInput(attrs={'class': 'form-control usd-rate-item'}),
            'usd_rate_item_to_inr': forms.NumberInput(attrs={'class': 'form-control usd-rate-item-inr'}),
            'yield_percentage': forms.NumberInput(attrs={'class': 'form-control'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # ✅ Show only active freezing categories
        self.fields['freezing_category'].queryset = FreezingCategory.objects.filter(is_active=True)

FreezingEntrySpotItemFormSet = inlineformset_factory(
    FreezingEntrySpot,
    FreezingEntrySpotItem,
    form=FreezingEntrySpotItemForm,
    extra=1,
    can_delete=True
)



# Freezing Entry local Form
class FreezingEntryLocalForm(forms.ModelForm):
    class Meta:
        model = FreezingEntryLocal
        fields = "__all__" 
        widgets = {
            'freezing_date': forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),
            'local_purchase_date': forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),
            'voucher_number': forms.TextInput(attrs={'class': 'form-control'}),
            'party': forms.Select(attrs={'class': 'form-control'}),
            'total_usd': forms.NumberInput(attrs={'readonly': 'readonly', 'class': 'form-control'}),
            'total_inr': forms.NumberInput(attrs={'readonly': 'readonly', 'class': 'form-control'}),
            'total_slab': forms.NumberInput(attrs={'readonly': 'readonly', 'class': 'form-control'}),
            'total_c_s': forms.NumberInput(attrs={'readonly': 'readonly', 'class': 'form-control'}),
            'total_kg': forms.NumberInput(attrs={'readonly': 'readonly', 'class': 'form-control'}),

            'freezing_status': forms.Select(attrs={'class': 'form-control'}),
        }

class FreezingEntryLocalItemForm(forms.ModelForm):
    class Meta:
        model = FreezingEntryLocalItem
        fields = '__all__'
        widgets = {

            'processing_center': forms.Select(attrs={'class': 'form-control'}),
            'store': forms.Select(attrs={'class': 'form-control'}),
            "item": forms.Select(attrs={"class": "form-control item-select"}),
            "item_quality": forms.Select(attrs={"class": "form-control quality-select"}),
            'unit': forms.Select(attrs={'class': 'form-control unit-select', 'data-units': '{}'}),
            'glaze': forms.Select(attrs={'class': 'form-control'}),
            'freezing_category': forms.Select(attrs={'class': 'form-control'}),
            'brand': forms.Select(attrs={'class': 'form-control'}),
            'species': forms.Select(attrs={'class': 'form-control'}),
            'peeling_type': forms.Select(attrs={'class': 'form-control'}),
            'grade': forms.Select(attrs={'class': 'form-control'}),

            'slab_quantity': forms.NumberInput(attrs={'class': 'form-control slab-quantity'}),
            'c_s_quantity': forms.NumberInput(attrs={'class': 'form-control cs-quantity'}),
            'kg': forms.NumberInput(attrs={'class': 'form-control kg'}),

            'usd_rate_per_kg': forms.NumberInput(attrs={'class': 'form-control usd-rate-per-kg'}),
            'usd_rate_item': forms.NumberInput(attrs={'class': 'form-control usd-rate-item'}),
            'usd_rate_item_to_inr': forms.NumberInput(attrs={'class': 'form-control usd-rate-item-inr'}),
        }
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Ensure item_quality shows qualities, not item names
        self.fields['item_quality'].queryset = ItemQuality.objects.all().select_related('item')
        self.fields['item_quality'].label_from_instance = lambda obj: f"{obj.quality} ({obj.item.name})"
        self.fields['freezing_category'].queryset = FreezingCategory.objects.filter(is_active=True)



FreezingEntryLocalItemFormSet = inlineformset_factory(
    FreezingEntryLocal,
    FreezingEntryLocalItem,
    form=FreezingEntryLocalItemForm,
    extra=1,
    can_delete=True
)






class PreShipmentWorkOutForm(forms.ModelForm):
    """Main form for PreShipmentWorkOut"""
    
    class Meta:
        model = PreShipmentWorkOut
        fields = ['item', 'item_quality', 'unit', 'glaze', 'category', 'brand']
        widgets = {
            'item': forms.Select(attrs={
                'class': 'form-select',
                'id': 'id_item', 
            }),
            'item_quality': forms.Select(attrs={
                'class': 'form-select',
                'id': 'id_item_quality'
            }),
            'unit': forms.Select(attrs={
                'class': 'form-select',
                'id': 'id_unit'
            }),
            'glaze': forms.Select(attrs={
                'class': 'form-select',
                'id': 'id_glaze'
            }),
            'category': forms.Select(attrs={
                'class': 'form-select',
                'id': 'id_category'
            }),
            'brand': forms.Select(attrs={
                'class': 'form-select',
                'id': 'id_brand'
            }),
        }

    def clean(self):
        cleaned_data = super().clean()
        # Add cross-field validation if needed
        return cleaned_data
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # ✅ Show only active freezing categories
        self.fields['category'].queryset = FreezingCategory.objects.filter(is_active=True)

class PreShipmentWorkOutItemForm(forms.ModelForm):
    """Form for individual workout items"""
    
    class Meta:
        model = PreShipmentWorkOutItem
        fields = [
            'species', 'peeling_type', 'grade', 'cartons', 'quantity',
            'usd_rate_per_kg', 'usd_rate_item', 'usd_rate_item_to_inr',
            'usd_rate_per_kg_get', 'usd_rate_item_get', 'usd_rate_item_to_inr_get',
            'profit', 'loss'
        ]
        widgets = {
            'species': forms.Select(attrs={
                'class': 'form-select species',
            }),
            'peeling_type': forms.Select(attrs={
                'class': 'form-select'
            }),
            'grade': forms.Select(attrs={
                'class': 'form-select'
            }),
            'cartons': forms.NumberInput(attrs={
                'class': 'form-control cartons',
                'step': '0.01',
                'min': '0'
            }),
            'quantity': forms.NumberInput(attrs={
                'class': 'form-control quantity',
                'step': '0.001',
                'readonly': True
            }),
            'usd_rate_per_kg': forms.NumberInput(attrs={
                'class': 'form-control usd-rate-per-kg',
                'step': '0.01',
                'min': '0'
            }),
            'usd_rate_item': forms.NumberInput(attrs={
                'class': 'form-control usd-rate-item',
                'step': '0.01',
                'readonly': True
            }),
            'usd_rate_item_to_inr': forms.NumberInput(attrs={
                'class': 'form-control usd-rate-item-inr',
                'step': '0.01',
                'readonly': True
            }),
            'usd_rate_per_kg_get': forms.NumberInput(attrs={
                'class': 'form-control usd-rate-per-kg-get',
                'step': '0.01',
                'min': '0'
            }),
            'usd_rate_item_get': forms.NumberInput(attrs={
                'class': 'form-control usd-rate-item-get',
                'step': '0.01',
                'readonly': True
            }),
            'usd_rate_item_to_inr_get': forms.NumberInput(attrs={
                'class': 'form-control usd-rate-item-inr-get',
                'step': '0.01',
                'readonly': True
            }),
            'profit': forms.NumberInput(attrs={
                'class': 'form-control profit',
                'readonly': True,
                'step': '0.01'
            }),
            'loss': forms.NumberInput(attrs={
                'class': 'form-control loss',
                'readonly': True,
                'step': '0.01'
            }),
        }


PreShipmentWorkOutItemFormSet = inlineformset_factory(
    PreShipmentWorkOut,
    PreShipmentWorkOutItem,
    form=PreShipmentWorkOutItemForm,
    extra=1,
    can_delete=True,
   
)







# Freezing Entry Tenant Form

class FreezingEntryTenantForm(forms.ModelForm):

    class Meta:
        model = FreezingEntryTenant
        fields = "__all__"
        exclude = ['total_amount']  
        widgets = {
            'freezing_date': forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),
            'voucher_number': forms.TextInput(attrs={'class': 'form-control'}),
            'tenant_company_name': forms.Select(attrs={'class': 'form-control'}),

            'total_slab': forms.NumberInput(attrs={'readonly': 'readonly', 'class': 'form-control'}),
            'total_c_s': forms.NumberInput(attrs={'readonly': 'readonly', 'class': 'form-control'}),
            'total_kg': forms.NumberInput(attrs={'readonly': 'readonly', 'class': 'form-control'}),

            'freezing_status': forms.Select(attrs={'class': 'form-control'}),
        }

class FreezingEntryTenantItemForm(forms.ModelForm):
    class Meta:
        model = FreezingEntryTenantItem
        fields = "__all__"
        widgets = {
            'processing_center': forms.Select(attrs={'class': 'form-control'}),
            'store': forms.Select(attrs={'class': 'form-control'}),

            # 🔹 For AJAX population
            'item': forms.Select(attrs={'class': 'form-control item-select'}),
            'item_quality': forms.Select(attrs={'class': 'form-control'}),

            'unit': forms.Select(attrs={'class': 'form-control unit-select'}),
            'glaze': forms.Select(attrs={'class': 'form-control'}),
            'freezing_category': forms.Select(attrs={'class': 'form-control'}),
            'brand': forms.Select(attrs={'class': 'form-control'}),

            # 🔹 Add "species-select" for dependent dropdowns
            'species': forms.Select(attrs={'class': 'form-control species-select'}),
            'grade': forms.Select(attrs={'class': 'form-control'}),

            'slab_quantity': forms.NumberInput(attrs={'class': 'form-control slab-quantity'}),
            'c_s_quantity': forms.NumberInput(attrs={'class': 'form-control cs-quantity'}),
            'kg': forms.NumberInput(attrs={'class': 'form-control kg'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # ✅ Show only active freezing categories
        self.fields['freezing_category'].queryset = FreezingCategory.objects.filter(is_active=True)

FreezingEntryTenantItemFormSet = inlineformset_factory(
    FreezingEntryTenant,
    FreezingEntryTenantItem,
    form=FreezingEntryTenantItemForm,
    extra=1,
    can_delete=True
)


# return to Tenant Forms

class ReturnTenantForm(forms.ModelForm):
    class Meta:
        model = ReturnTenant
        fields = "__all__"
        exclude = ['total_amount']
        widgets = {
            'return_date': forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),
            'voucher_number': forms.TextInput(attrs={'class': 'form-control'}),
            'tenant_company_name': forms.Select(attrs={'class': 'form-control', 'id': 'id_tenant_company_name'}),
            'total_slab': forms.NumberInput(attrs={'readonly': 'readonly', 'class': 'form-control'}),
            'total_c_s': forms.NumberInput(attrs={'readonly': 'readonly', 'class': 'form-control'}),
            'total_kg': forms.NumberInput(attrs={'readonly': 'readonly', 'class': 'form-control'}),
            'return_status': forms.Select(attrs={'class': 'form-control'}),
        }


class ReturnTenantItemForm(forms.ModelForm):
    class Meta:
        model = ReturnTenantItem
        fields = "__all__"
        exclude = ['peeling_type']
        widgets = {
            'processing_center': forms.Select(attrs={'class': 'form-control'}),
            'store': forms.Select(attrs={'class': 'form-control'}),
            'item': forms.Select(attrs={'class': 'form-control item-select'}),
            'item_quality': forms.Select(attrs={'class': 'form-control'}),
            'unit': forms.Select(attrs={'class': 'form-control unit-select'}),
            'glaze': forms.Select(attrs={'class': 'form-control'}),
            'freezing_category': forms.Select(attrs={'class': 'form-control freezing-category-select'}),
            'brand': forms.Select(attrs={'class': 'form-control'}),
            'species': forms.Select(attrs={'class': 'form-control species-select'}),
            'grade': forms.Select(attrs={'class': 'form-control'}),
            'slab_quantity': forms.NumberInput(attrs={'class': 'form-control slab-quantity', 'step': '0.01'}),
            'c_s_quantity': forms.NumberInput(attrs={'class': 'form-control cs-quantity', 'step': '0.01'}),
            'kg': forms.NumberInput(attrs={'class': 'form-control kg', 'step': '0.001'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # ✅ Show only active freezing categories
        self.fields['freezing_category'].queryset = FreezingCategory.objects.filter(is_active=True)


ReturnTenantItemFormSet = inlineformset_factory(
    ReturnTenant,
    ReturnTenantItem,
    form=ReturnTenantItemForm,
    extra=1,
    can_delete=True
)




# forms.py

from django import forms
from django.forms import modelformset_factory

class TenantBillingConfigurationForm(forms.ModelForm):
    class Meta:
        model = TenantBillingConfiguration
        fields = ['tenant', 'billing_start_date', 'billing_frequency_days', 'is_active']
        widgets = {
            'billing_start_date': forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),
            'billing_frequency_days': forms.NumberInput(attrs={'class': 'form-control', 'min': '1'}),
            'tenant': forms.Select(attrs={'class': 'form-control'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['billing_frequency_days'].help_text = "Enter number of days (e.g., 2 for every 2 days, 7 for weekly)"

class BillGenerationForm(forms.Form):
    tenant = forms.ModelChoiceField(
        queryset=Tenant.objects.all(),
        widget=forms.Select(attrs={'class': 'form-control'}),
        empty_label="Select Tenant"
    )
    from_date = forms.DateField(
        widget=forms.DateInput(attrs={'type': 'date', 'class': 'form-control'})
    )
    to_date = forms.DateField(
        widget=forms.DateInput(attrs={'type': 'date', 'class': 'form-control'})
    )

class TenantBillForm(forms.ModelForm):
    class Meta:
        model = TenantBill
        fields = ['tenant', 'from_date', 'to_date', 'status']
        widgets = {
            'tenant': forms.Select(attrs={'class': 'form-control'}),
            'from_date': forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),
            'to_date': forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),
            'status': forms.Select(attrs={'class': 'form-control'}),
        }











from django import forms
from django.forms import inlineformset_factory
from decimal import Decimal
from .models import StoreTransfer, StoreTransferItem, Stock, PackingUnit, GlazePercentage, Species, ItemGrade

class StoreTransferForm(forms.ModelForm):
    class Meta:
        model = StoreTransfer
        fields = ['voucher_no', 'date', 'from_store', 'to_store']
        widgets = {
            'voucher_no': forms.TextInput(attrs={'class': 'form-control'}),
            'date': forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),
            'from_store': forms.Select(attrs={'class': 'form-control'}),
            'to_store': forms.Select(attrs={'class': 'form-control'}),
        }

class StoreTransferItemForm(forms.ModelForm):
    selected_stock_id = forms.IntegerField(widget=forms.HiddenInput(), required=False)

    class Meta:
        model = StoreTransferItem
        fields = [
            "item", "brand", "item_quality", "freezing_category",
            "unit", "glaze", "species", "item_grade", "cs_quantity", "kg_quantity"
        ]
        widgets = {
            "item": forms.Select(attrs={"class": "form-control item-select"}),
            "item_quality": forms.Select(attrs={"class": "form-control quality-select"}),
            "brand": forms.Select(attrs={"class": "form-control brand-select"}),
            "freezing_category": forms.Select(attrs={"class": "form-control freezing-select"}),
            "unit": forms.Select(attrs={"class": "form-control unit-select"}),
            "glaze": forms.Select(attrs={"class": "form-control glaze-select"}),
            "species": forms.Select(attrs={"class": "form-control species-select"}),
            "item_grade": forms.Select(attrs={"class": "form-control grade-select"}),
            "cs_quantity": forms.NumberInput(attrs={"class": "form-control", "step": "0.01"}),
            "kg_quantity": forms.NumberInput(attrs={"class": "form-control", "step": "0.001"}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # ✅ Show only active freezing categories
        self.fields['freezing_category'].queryset = FreezingCategory.objects.filter(is_active=True)


StoreTransferItemFormSet = inlineformset_factory(
    StoreTransfer,
    StoreTransferItem,
    form=StoreTransferItemForm,
    extra=1,
    can_delete=True
)









# --- Spot Agent Voucher Form ---
class SpotAgentVoucherForm(forms.ModelForm):
    class Meta:
        model = SpotAgentVoucher
        fields = ["voucher_no", "agent", "date", "description", "remain_amount", "receipt", "payment","total_amount"]
        widgets = {
            "voucher_no": forms.TextInput(attrs={"class": "form-control"}),
            "agent": forms.Select(attrs={"class": "form-control"}),
            "date": forms.DateInput(attrs={"type": "date", "class": "form-control"}),
            "description": forms.Textarea(attrs={"class": "form-control", "rows": 2}),
            "remain_amount": forms.NumberInput(attrs={'readonly': 'readonly', 'class': 'form-control'}),
            "receipt": forms.NumberInput(attrs={"class": "form-control"}),
            "payment": forms.NumberInput(attrs={"class": "form-control"}),
            "total_amount": forms.NumberInput(attrs={'readonly': 'readonly', 'class': 'form-control'}),
        }


# --- Supervisor Voucher Form ---
# --- Supervisor Voucher Form ---
from django import forms
from .models import SupervisorVoucher, PurchasingSupervisor

class SupervisorVoucherForm(forms.ModelForm):
    class Meta:
        model = SupervisorVoucher
        fields = ["voucher_no", "supervisor", "date", "description", "remain_amount", "receipt", "payment", "total_amount"]
        widgets = {
            "voucher_no": forms.TextInput(attrs={"class": "form-control"}),
            "supervisor": forms.Select(attrs={"class": "form-control"}),
            "date": forms.DateInput(attrs={"type": "date", "class": "form-control"}),
            "description": forms.Textarea(attrs={"class": "form-control", "rows": 2}),
            "remain_amount": forms.NumberInput(attrs={'readonly': 'readonly', 'class': 'form-control'}),
            "receipt": forms.NumberInput(attrs={"class": "form-control"}),
            "payment": forms.NumberInput(attrs={"class": "form-control"}),
            "total_amount": forms.NumberInput(attrs={'readonly': 'readonly', 'class': 'form-control'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Get active supervisors and create choices
        supervisors = PurchasingSupervisor.objects.filter(
            is_active=True
        ).order_by('name')
        
        supervisor_choices = [('', '--- Select Supervisor ---')]
        
        for supervisor in supervisors:
            display_name = supervisor.name
            if supervisor.mobile:
                display_name += f" - {supervisor.mobile}"
            if supervisor.email:
                display_name += f" ({supervisor.email})"
            supervisor_choices.append((supervisor.id, display_name))
        
        # Update form choices
        self.fields['supervisor'].choices = supervisor_choices




# --- Local Purchase Voucher Form ---
class LocalPurchaseVoucherForm(forms.ModelForm):
    class Meta:
        model = LocalPurchaseVoucher
        fields = ["voucher_no", "party", "date", "description", "remain_amount", "receipt", "payment", "total_amount"]
        widgets = {
            "voucher_no": forms.TextInput(attrs={"class": "form-control"}),
            "party": forms.Select(attrs={"class": "form-control"}),
            "date": forms.DateInput(attrs={"type": "date", "class": "form-control"}),
            "description": forms.Textarea(attrs={"class": "form-control", "rows": 2}),
            "remain_amount": forms.NumberInput(attrs={'readonly': 'readonly', 'class': 'form-control'}),
            "receipt": forms.NumberInput(attrs={"class": "form-control"}),
            "payment": forms.NumberInput(attrs={"class": "form-control"}),
            "total_amount": forms.NumberInput(attrs={'readonly': 'readonly', 'class': 'form-control'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Get unique party names and create choices
        unique_parties = LocalPurchase.objects.select_related('party_name').values(
            'party_name__party', 'party_name__district', 'party_name__state'
        ).distinct().order_by('party_name__party')
        
        party_choices = [('', '--- Select Party ---')]
        party_mapping = {}
        
        for party_data in unique_parties:
            party_name = party_data['party_name__party']
            if party_name not in party_mapping:
                # Get the first LocalPurchase object for this party name
                representative_purchase = LocalPurchase.objects.filter(
                    party_name__party=party_name
                ).first()
                
                if representative_purchase:
                    party_mapping[party_name] = representative_purchase
                    display_name = f"{party_name}"
                    if party_data['party_name__district']:
                        display_name += f" - {party_data['party_name__district']}"
                    if party_data['party_name__state']:
                        display_name += f", {party_data['party_name__state']}"
                    
                    party_choices.append((representative_purchase.id, display_name))
        
        # Update form choices
        self.fields['party'].choices = party_choices


# --- Peeling Shed Voucher Form ---
class PeelingShedVoucherForm(forms.ModelForm):
    class Meta:
        model = PeelingShedVoucher
        fields = ["voucher_no", "shed", "date", "description", "receipt", "payment"]
        widgets = {
            "voucher_no": forms.TextInput(attrs={"class": "form-control"}),
            "shed": forms.Select(attrs={"class": "form-control"}),
            "date": forms.DateInput(attrs={"type": "date", "class": "form-control"}),
            "description": forms.Textarea(attrs={"class": "form-control", "rows": 2}),
            "receipt": forms.NumberInput(attrs={"class": "form-control"}),
            "payment": forms.NumberInput(attrs={"class": "form-control"}),
        }



# --- Tenant Voucher Form ---
class TenantVoucherForm(forms.ModelForm):
    class Meta:
        model = TenantVoucher
        fields = ["voucher_no", "tenant", "date", "description", "remain_amount", "receipt", "payment", "total_amount"]
        widgets = {
            "voucher_no": forms.TextInput(attrs={"class": "form-control"}),
            "tenant": forms.Select(attrs={"class": "form-control"}),
            "date": forms.DateInput(attrs={"type": "date", "class": "form-control"}),
            "description": forms.Textarea(attrs={"class": "form-control", "rows": 2}),
            "remain_amount": forms.NumberInput(attrs={'readonly': 'readonly', 'class': 'form-control'}),
            "receipt": forms.NumberInput(attrs={"class": "form-control"}),
            "payment": forms.NumberInput(attrs={"class": "form-control"}),
            "total_amount": forms.NumberInput(attrs={'readonly': 'readonly', 'class': 'form-control'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Make remain_amount and total_amount not required in the form
        self.fields['remain_amount'].required = False
        self.fields['total_amount'].required = False
        
        # Get unique tenants and create choices (in case of duplicate company names)
        unique_tenants = Tenant.objects.values(
            'id', 'company_name', 'contact_person', 'phone'
        ).distinct().order_by('company_name')
        
        tenant_choices = [('', '--- Select Tenant ---')]
        tenant_mapping = {}
        
        for tenant_data in unique_tenants:
            company_name = tenant_data['company_name'] or "Unnamed Tenant"
            tenant_id = tenant_data['id']
            
            # Create unique identifier for duplicate company names
            if company_name not in tenant_mapping:
                tenant_mapping[company_name] = []
            tenant_mapping[company_name].append(tenant_data)
        
        # Build choices with unique display names
        for company_name, tenant_list in tenant_mapping.items():
            if len(tenant_list) == 1:
                tenant = tenant_list[0]
                display_name = company_name
                if tenant['contact_person']:
                    display_name += f" - {tenant['contact_person']}"
                tenant_choices.append((tenant['id'], display_name))
            else:
                # Handle duplicate company names
                for tenant in tenant_list:
                    display_name = company_name
                    if tenant['contact_person']:
                        display_name += f" - {tenant['contact_person']}"
                    if tenant['phone']:
                        display_name += f" ({tenant['phone']})"
                    tenant_choices.append((tenant['id'], display_name))
        
        # Update form choices
        self.fields['tenant'].choices = tenant_choices

# --- Stock Form ---  

class StockForm(forms.ModelForm):
    class Meta:
        model = Stock
        fields = [
            'store', 'brand', 'item', 'item_quality', 'freezing_category',
            'unit', 'glaze', 'species', 'item_grade','peeling_type', 
            'cs_quantity', 'kg_quantity', 
            'usd_rate_per_kg', 'usd_rate_item', 'usd_rate_item_to_inr'
        ]
        
        widgets = {
            'store': forms.Select(attrs={
                'class': 'form-control',
                'required': True
            }),
            'brand': forms.Select(attrs={
                'class': 'form-control',
                'required': True
            }),
            'item': forms.Select(attrs={
                'class': 'form-control',
                'required': True
            }),
            'item_quality': forms.Select(attrs={
                'class': 'form-control'
            }),
            'freezing_category': forms.Select(attrs={
                'class': 'form-control'
            }),
            'unit': forms.Select(attrs={
                'class': 'form-control'
            }),
            'glaze': forms.Select(attrs={
                'class': 'form-control'
            }),
            'species': forms.Select(attrs={
                'class': 'form-control'
            }),
            'item_grade': forms.Select(attrs={
                'class': 'form-control'
            }),
            'peeling_type': forms.Select(attrs={
                'class': 'form-control'
            }),
            'cs_quantity': forms.NumberInput(attrs={
                'class': 'form-control',
                'step': '0.01',
                
            }),
            'kg_quantity': forms.NumberInput(attrs={
                'class': 'form-control',
                'step': '0.001',
          
            }),
            'usd_rate_per_kg': forms.NumberInput(attrs={
                'class': 'form-control',
                'step': '0.01',
     
            }),
            'usd_rate_item': forms.NumberInput(attrs={
                'class': 'form-control',
                'step': '0.01',

            }),
            'usd_rate_item_to_inr': forms.NumberInput(attrs={
                'class': 'form-control',
                'step': '0.01',
      
            }),
        }
        
        labels = {
            'store': 'Store *',
            'brand': 'Brand *',
            'item': 'Item *',
            'item_quality': 'Item Quality',
            'freezing_category': 'Freezing Category',
            'unit': 'Packing Unit',
            'glaze': 'Glaze Percentage',
            'species': 'Species',
            'item_grade': 'Item Grade',
            'cs_quantity': 'CS Quantity',
            'kg_quantity': 'KG Quantity',
            'usd_rate_per_kg': 'USD Rate per KG',
            'usd_rate_item': 'USD Rate Item',
            'usd_rate_item_to_inr': 'USD Rate Item to INR',
        }

    def _init_(self, *args, **kwargs):
        super()._init_(*args, **kwargs)
        
        # Set empty labels for optional dropdowns
        self.fields['item_quality'].empty_label = "Select Item Quality (Optional)"
        self.fields['freezing_category'].empty_label = "Select Freezing Category (Optional)"
        self.fields['unit'].empty_label = "Select Packing Unit (Optional)"
        self.fields['glaze'].empty_label = "Select Glaze Percentage (Optional)"
        self.fields['species'].empty_label = "Select Species (Optional)"
        self.fields['item_grade'].empty_label = "Select Item Grade (Optional)"

    def clean(self):
        cleaned_data = super().clean()
        
        # Check for unique constraint
        store = cleaned_data.get('store')
        item = cleaned_data.get('item')
        brand = cleaned_data.get('brand')
        item_quality = cleaned_data.get('item_quality')
        unit = cleaned_data.get('unit')
        glaze = cleaned_data.get('glaze')
        species = cleaned_data.get('species')
        item_grade = cleaned_data.get('item_grade')
        
        if all([store, item, brand]):
            # Check if this combination already exists
            existing_stock = Stock.objects.filter(
                store=store,
                item=item,
                brand=brand,
                item_quality=item_quality,
                unit=unit,
                glaze=glaze,
                species=species,
                item_grade=item_grade
            )
            
            # If updating, exclude current instance
            if self.instance.pk:
                existing_stock = existing_stock.exclude(pk=self.instance.pk)
                
            if existing_stock.exists():
                raise forms.ValidationError(
                    "Stock with this combination of Store, Item, Brand, Item Quality, "
                    "Unit, Glaze, Species, and Item Grade already exists."
                )
        
        return cleaned_data

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # ✅ Show only active freezing categories
        self.fields['freezing_category'].queryset = FreezingCategory.objects.filter(is_active=True)




class StockAdjustmentForm(forms.Form):  # Changed from ModelForm to Form
    # Stock identification fields
    store = forms.ModelChoiceField(
        queryset=Store.objects.all(),
        widget=forms.Select(attrs={'class': 'form-control', 'required': True, 'id': 'id_store'}),
        label='Store *'
    )
    brand = forms.ModelChoiceField(
        queryset=ItemBrand.objects.all(),
        widget=forms.Select(attrs={'class': 'form-control', 'required': True, 'id': 'id_brand'}),
        label='Brand *'
    )
    item = forms.ModelChoiceField(
        queryset=Item.objects.all(),
        widget=forms.Select(attrs={'class': 'form-control', 'required': True, 'id': 'id_item'}),
        label='Item *'
    )
    item_quality = forms.ModelChoiceField(
        queryset=ItemQuality.objects.all(),
        required=False,
        empty_label="Select Item Quality (Optional)",
        widget=forms.Select(attrs={'class': 'form-control', 'id': 'id_item_quality'}),
        label='Item Sub'
    )
    freezing_category = forms.ModelChoiceField(
        queryset=FreezingCategory.objects.filter(is_active=True),
        required=False,
        empty_label="Select Freezing Category (Optional)",
        widget=forms.Select(attrs={'class': 'form-control'}),
        label='Freezing Category'
    )
    unit = forms.ModelChoiceField(
        queryset=PackingUnit.objects.all(),
        required=False,
        empty_label="Select Packing Unit (Optional)",
        widget=forms.Select(attrs={'class': 'form-control', 'id': 'id_unit'}),
        label='Packing Unit'
    )
    glaze = forms.ModelChoiceField(
        queryset=GlazePercentage.objects.all(),
        required=False,
        empty_label="Select Glaze Percentage (Optional)",
        widget=forms.Select(attrs={'class': 'form-control', 'id': 'id_glaze'}),
        label='Glaze Percentage'
    )
    species = forms.ModelChoiceField(
        queryset=Species.objects.all(),
        required=False,
        empty_label="Select Species (Optional)",
        widget=forms.Select(attrs={'class': 'form-control', 'id': 'id_species'}),
        label='Species'
    )
    item_grade = forms.ModelChoiceField(
        queryset=ItemGrade.objects.all(),
        required=False,
        empty_label="Select Item Grade (Optional)",
        widget=forms.Select(attrs={'class': 'form-control', 'id': 'id_item_grade'}),
        label='Item Grade'
    )
    peeling_type = forms.ModelChoiceField(
        queryset=ItemType.objects.all(),
        required=False,
        empty_label="Select Peeling Type (Optional)",
        widget=forms.Select(attrs={'class': 'form-control', 'id': 'id_peeling_type'}),
        label='Peeling Type'
    )
    
    # Adjustment fields
    cs_adjustment = forms.DecimalField(
        max_digits=10,
        decimal_places=2,
        initial=0,
        required=False,
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'step': '0.01',
            'placeholder': 'e.g., 10 or -5'
        }),
        help_text="Enter positive to add, negative to reduce",
        label='CS Adjustment *'
    )
    kg_adjustment = forms.DecimalField(
        max_digits=10,
        decimal_places=2,
        initial=0,
        required=False,
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'step': '0.001',
            'placeholder': 'e.g., 100 or -50'
        }),
        help_text="Enter positive to add, negative to reduce",
        label='KG Adjustment *'
    )
    
    # Rate fields
    usd_rate_per_kg = forms.DecimalField(
        max_digits=100,
        decimal_places=2,
        required=False,
        initial=0,
        widget=forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01', 'id': 'id_usd_rate_per_kg'}),
        label='USD Rate per KG'
    )
    usd_rate_item = forms.DecimalField(
        max_digits=100,
        decimal_places=2,
        required=False,
        initial=0,
        widget=forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01', 'id': 'id_usd_rate_item'}),
        label='USD Rate Item'
    )
    usd_rate_item_to_inr = forms.DecimalField(
        max_digits=100,
        decimal_places=2,
        required=False,
        initial=0,
        widget=forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01', 'id': 'id_usd_rate_item_to_inr'}),
        label='USD Rate Item to INR'
    )

    def clean(self):
        cleaned_data = super().clean()
        
        cs_adjustment = cleaned_data.get('cs_adjustment', 0) or 0
        kg_adjustment = cleaned_data.get('kg_adjustment', 0) or 0
        
        # At least one adjustment must be provided
        if cs_adjustment == 0 and kg_adjustment == 0:
            raise forms.ValidationError(
                "Please provide at least one adjustment value (CS or KG)."
            )
        
        return cleaned_data




# Added in 02/10/2025

class BuyerForm(forms.ModelForm):
    """Form for creating/editing Buyer"""
    
    class Meta:
        model = Buyer
        fields = [
            'name', 'address', 'country', 'contact_person', 
            'email', 'phone', 'is_active'
        ]
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter buyer name'
            }),
            'address': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'Enter complete address'
            }),
            'country': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'e.g., JAPAN'
            }),
            'contact_person': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Contact person name'
            }),
            'email': forms.EmailInput(attrs={
                'class': 'form-control',
                'placeholder': 'buyer@example.com'
            }),
            'phone': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': '+81-xxx-xxxx-xxxx'
            }),
            'is_active': forms.CheckboxInput(attrs={
                'class': 'form-check-input'
            }),
        }

class ShipmentDestinationForm(forms.ModelForm):
    """Form for creating/editing Shipment Destination"""
    
    class Meta:
        model = ShipmentDestination
        fields = ['country', 'port_of_loading', 'port_of_discharge', 'final_destination']
        widgets = {
            'country': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Country'
            }),
            'port_of_loading': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'e.g., COCHIN, INDIA'
            }),
            'port_of_discharge': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'e.g., NAGOYA, JAPAN'
            }),
            'final_destination': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Final destination (if different)'
            }),
        }



# sales Entry Forms 

class SalesEntryForm(forms.ModelForm):
    """Form for SalesEntry (Commercial Invoice)"""
    
    class Meta:
        model = SalesEntry
        fields = [
            'voucher_no', 'date', 'invoice_no', 'hs_code',
            'buyer', 'buyer_order_no', 'purchase_order_date',
            'exporter_name', 'exporter_address', 'exporter_iec_code',
            'exporters_ref_no', 'steamer_line_no', 'customs_seal_no',
            'container_no', 'rex_reg_no', 'narrative',
            'country_of_origin', 'country_of_destination',
            'gstin_number', 'igst_number',
            'item', 'item_quality', 'unit', 'glaze', 'freezing_category', 'brand',
            'processed_by', 'declaration_text', 'bank_details',
            'status'
        ]
        widgets = {
            'voucher_no': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter voucher number'
            }),
            'date': forms.DateInput(attrs={
                'class': 'form-control',
                'type': 'date'
            }),
            'invoice_no': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter invoice number'
            }),
            'hs_code': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'HS Code'
            }),
            'buyer': forms.Select(attrs={
                'class': 'form-control'
            }),
            'buyer_order_no': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Buyer order number'
            }),
            'purchase_order_date': forms.DateInput(attrs={
                'class': 'form-control',
                'type': 'date'
            }),
            'exporter_name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Exporter name'
            }),
            'exporter_address': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'Exporter address'
            }),
            'exporter_iec_code': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'IEC Code'
            }),
            'exporters_ref_no': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Exporters reference number'
            }),
            'steamer_line_no': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Steamer line number'
            }),
            'customs_seal_no': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Customs seal number'
            }),
            'container_no': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Container number'
            }),
            'rex_reg_no': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'REX registration number'
            }),
            'narrative': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'Additional notes'
            }),
            'country_of_origin': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Country of origin'
            }),
            'country_of_destination': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Country of destination'
            }),
            'gstin_number': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'GSTIN number'
            }),
            'igst_number': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'IGST number'
            }),
            'item': forms.Select(attrs={
                'class': 'form-control'
            }),
            'item_quality': forms.Select(attrs={
                'class': 'form-control'
            }),
            'unit': forms.Select(attrs={
                'class': 'form-control'
            }),
            'glaze': forms.Select(attrs={
                'class': 'form-control'
            }),
            'freezing_category': forms.Select(attrs={
                'class': 'form-control'
            }),
            'brand': forms.Select(attrs={
                'class': 'form-control'
            }),
            'processed_by': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'Processed by'
            }),
            'declaration_text': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'Declaration text'
            }),
            'bank_details': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'Bank details'
            }),
            'status': forms.Select(attrs={
                'class': 'form-control'
            }),
        }
    
    def clean(self):
        cleaned_data = super().clean()
        
        # Validate unique voucher_no
        voucher_no = cleaned_data.get('voucher_no')
        invoice_no = cleaned_data.get('invoice_no')
        
        # Check for duplicates (excluding current instance in update)
        if voucher_no:
            qs = SalesEntry.objects.filter(voucher_no=voucher_no)
            if self.instance.pk:
                qs = qs.exclude(pk=self.instance.pk)
            if qs.exists():
                raise forms.ValidationError({
                    'voucher_no': 'This voucher number already exists.'
                })
        
        if invoice_no:
            qs = SalesEntry.objects.filter(invoice_no=invoice_no)
            if self.instance.pk:
                qs = qs.exclude(pk=self.instance.pk)
            if qs.exists():
                raise forms.ValidationError({
                    'invoice_no': 'This invoice number already exists.'
                })
        
        return cleaned_data

class SalesEntryItemForm(forms.ModelForm):
    """Form for SalesEntryItem (Line items in invoice)"""
    
    class Meta:
        model = SalesEntryItem
        fields = [
       
            'species','peeling_type','grade','cartons','quantity','price_usd_per_kg',
            'amount_usd','taxable_value','tax_rate','tax_amount','total_amount' 

        ]

        widgets = {
            'species': forms.Select(attrs={
                'class': 'form-control form-select'
            }),
            'peeling_type': forms.Select(attrs={
                'class': 'form-control form-select'
            }),
            'grade': forms.Select(attrs={
                'class': 'form-control form-select'
            }),
            'cartons': forms.NumberInput(attrs={
                'class': 'form-control',
                'step': '0.01',
                'placeholder': 'Number of cartons'
            }),
            'quantity': forms.NumberInput(attrs={
                'class': 'form-control',
                'step': '0.001',
                'placeholder': 'Quantity (kg)'
            }),
            'price_usd_per_kg': forms.NumberInput(attrs={
                'class': 'form-control',
                'step': '0.01',
                'placeholder': 'Price per kg (USD)'
            }),
            'tax_rate': forms.NumberInput(attrs={
                'class': 'form-control',
                'step': '0.01',
                'placeholder': 'Tax rate (%)',
                'value': '5.00'
            }),
            'tax_amount': forms.NumberInput(attrs={
                'class': 'form-control',
                'step': '0.01',
                'placeholder': 'Tax amount',
          
            }),
            'total_amount': forms.NumberInput(attrs={
                'class': 'form-control',
                'step': '0.01',
                'placeholder': 'Total amount',
   
            }),
            'amount_usd': forms.NumberInput(attrs={
                'class': 'form-control',
                'step': '0.01',
                'placeholder': 'Amount (USD)',
   
            }),
            'taxable_value': forms.NumberInput(attrs={
                'class': 'form-control',
                'step': '0.01',
                'placeholder': 'Taxable value',
   
            }),

         

        }
   
SalesEntryItemFormSet = inlineformset_factory(
    SalesEntry,
    SalesEntryItem,
    form=SalesEntryItemForm,
    extra=1,  # Number of empty forms to display
    can_delete=True,

)



class TenantStockForm(forms.ModelForm):
    """ModelForm for creating/editing tenant stock"""
    
    class Meta:
        model = TenantStock
        fields = [
            'tenant_company_name', 'processing_center', 'store', 'brand', 'item', 
            'item_quality', 'freezing_category', 'unit', 'glaze', 'species', 'grade',
            'peeling_type', 'available_slab', 'available_c_s', 'available_kg', 'remarks'
        ]
        
        widgets = {
            'tenant_company_name': forms.Select(attrs={
                'class': 'form-control',
                'required': True
            }),
            'processing_center': forms.Select(attrs={
                'class': 'form-control'
            }),
            'store': forms.Select(attrs={
                'class': 'form-control'
            }),
            'brand': forms.Select(attrs={
                'class': 'form-control',
                'required': True
            }),
            'item': forms.Select(attrs={
                'class': 'form-control',
                'required': True
            }),
            'item_quality': forms.Select(attrs={
                'class': 'form-control'
            }),
            'freezing_category': forms.Select(attrs={
                'class': 'form-control',
                'required': True
            }),
            'unit': forms.Select(attrs={
                'class': 'form-control'
            }),
            'glaze': forms.Select(attrs={
                'class': 'form-control'
            }),
            'species': forms.Select(attrs={
                'class': 'form-control'
            }),
            'grade': forms.Select(attrs={
                'class': 'form-control'
            }),
            'available_slab': forms.NumberInput(attrs={
                'class': 'form-control',
                'step': '0.01'
            }),
            'available_c_s': forms.NumberInput(attrs={
                'class': 'form-control',
                'step': '0.01'
            }),
            'available_kg': forms.NumberInput(attrs={
                'class': 'form-control',
                'step': '0.001'
            }),
            'remarks': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 4
            })
        }
        
        labels = {
            'tenant_company_name': 'Tenant Company *',
            'processing_center': 'Processing Center',
            'store': 'Store',
            'brand': 'Brand *',
            'item': 'Item *',
            'item_quality': 'Item Quality',
            'freezing_category': 'Freezing Category *',
            'unit': 'Packing Unit',
            'glaze': 'Glaze Percentage',
            'species': 'Species',
            'grade': 'Grade',
            'available_slab': 'Available Slab',
            'available_c_s': 'Available CS',
            'available_kg': 'Available KG',
            'remarks': 'Remarks'
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Set empty labels for optional dropdowns
        self.fields['item_quality'].empty_label = "Select Item Quality (Optional)"
        self.fields['unit'].empty_label = "Select Packing Unit (Optional)"
        self.fields['glaze'].empty_label = "Select Glaze Percentage (Optional)"
        self.fields['species'].empty_label = "Select Species (Optional)"
        self.fields['grade'].empty_label = "Select Grade (Optional)"
        self.fields['processing_center'].empty_label = "Select Processing Center (Optional)"
        self.fields['store'].empty_label = "Select Store (Optional)"
        
        # Show only active freezing categories
        self.fields['freezing_category'].queryset = FreezingCategory.objects.filter(is_active=True)

    def clean(self):
        cleaned_data = super().clean()
        
        # Check that either processing_center or store is selected
        processing_center = cleaned_data.get('processing_center')
        store = cleaned_data.get('store')
        
        if not processing_center and not store:
            raise forms.ValidationError(
                "Please select either a Processing Center or Store."
            )
        
        if processing_center and store:
            raise forms.ValidationError(
                "Please select only one location (Processing Center or Store), not both."
            )
        
        # Check for unique constraint
        tenant = cleaned_data.get('tenant_company_name')
        item = cleaned_data.get('item')
        brand = cleaned_data.get('brand')
        item_quality = cleaned_data.get('item_quality')
        unit = cleaned_data.get('unit')
        glaze = cleaned_data.get('glaze')
        species = cleaned_data.get('species')
        grade = cleaned_data.get('grade')
        
        if all([tenant, item, brand]):
            # Check if this combination already exists
            existing_stock = TenantStock.objects.filter(
                tenant_company_name=tenant,
                item=item,
                brand=brand,
                item_quality=item_quality,
                unit=unit,
                glaze=glaze,
                species=species,
                grade=grade,
                processing_center=processing_center,
                store=store
            )
            
            # If updating, exclude current instance
            if self.instance.pk:
                existing_stock = existing_stock.exclude(pk=self.instance.pk)
                
            if existing_stock.exists():
                raise forms.ValidationError(
                    "Tenant stock with this combination already exists."
                )
        
        return cleaned_data


class TenantStockAdjustmentForm(forms.Form):
    """Form for adjusting tenant stock - uses Form instead of ModelForm for custom fields"""
    
    # Required fields (matching your model)
    tenant_company_name = forms.ModelChoiceField(
        queryset=None,  # Will be set in __init__
        required=True,
        label="Tenant Company",
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    
    item = forms.ModelChoiceField(
        queryset=None,
        required=True,
        label="Item",
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    
    brand = forms.ModelChoiceField(
        queryset=None,
        required=True,
        label="Brand",
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    
    unit = forms.ModelChoiceField(
        queryset=None,
        required=True,
        label="Unit",
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    
    glaze = forms.ModelChoiceField(
        queryset=None,
        required=True,
        label="Glaze Percentage",
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    
    freezing_category = forms.ModelChoiceField(
        queryset=None,
        required=True,
        label="Freezing Category",
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    
    grade = forms.ModelChoiceField(
        queryset=None,
        required=True,
        label="Grade",
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    
    # Optional fields (null=True, blank=True in model)
    item_quality = forms.ModelChoiceField(
        queryset=None,
        required=False,
        label="Item Quality",
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    
    
    # Location fields - both can be selected now
    processing_center = forms.ModelChoiceField(
        queryset=None,
        required=False,
        label="Processing Center",
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    
    store = forms.ModelChoiceField(
        queryset=None,
        required=False,
        label="Store",
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    
    # Adjustment fields
    slab_adjustment = forms.DecimalField(
        required=False,
        initial=0,
        max_digits=12,
        decimal_places=2,
        label="Slab Adjustment",
        help_text="Enter positive value to add, negative to subtract",
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'step': '0.01',
            'placeholder': '0.00'
        })
    )
    
    cs_adjustment = forms.DecimalField(
        required=False,
        initial=0,
        max_digits=12,
        decimal_places=2,
        label="CS Adjustment",
        help_text="Enter positive value to add, negative to subtract",
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'step': '0.01',
            'placeholder': '0.00'
        })
    )
    
    kg_adjustment = forms.DecimalField(
        required=False,
        initial=0,
        max_digits=12,
        decimal_places=2,
        label="KG Adjustment",
        help_text="Enter positive value to add, negative to subtract",
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'step': '0.001',
            'placeholder': '0.00'
        })
    )
    
    remarks = forms.CharField(
        required=False,
        label="Remarks",
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 1,
            'placeholder': 'Enter any remarks...'
        })
    )
    
    def __init__(self, *args, **kwargs):
        """Initialize form with querysets from models"""
        super().__init__(*args, **kwargs)

        # Assign querysets for all dropdown fields
        self.fields['tenant_company_name'].queryset = Tenant.objects.all()
        self.fields['item'].queryset = Item.objects.all()
        self.fields['brand'].queryset = ItemBrand.objects.all()
        self.fields['item_quality'].queryset = ItemQuality.objects.all()
        self.fields['unit'].queryset = PackingUnit.objects.all()
        self.fields['glaze'].queryset = GlazePercentage.objects.all()
        self.fields['grade'].queryset = ItemGrade.objects.all()
        self.fields['processing_center'].queryset = ProcessingCenter.objects.all()
        self.fields['store'].queryset = Store.objects.all()

        # Filter freezing_category to only active ones
        self.fields['freezing_category'].queryset = FreezingCategory.objects.filter(is_active=True)

    def clean(self):
        cleaned_data = super().clean()
        
        # Validation: At least one adjustment value must be non-zero
        slab_adj = cleaned_data.get('slab_adjustment') or Decimal('0')
        cs_adj = cleaned_data.get('cs_adjustment') or Decimal('0')
        kg_adj = cleaned_data.get('kg_adjustment') or Decimal('0')
        
        if slab_adj == 0 and cs_adj == 0 and kg_adj == 0:
            raise ValidationError(
                "Please enter at least one adjustment value (Slab, CS, or KG)."
            )
        
        return cleaned_data









