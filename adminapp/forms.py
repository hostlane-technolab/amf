from django import forms
from django.contrib.auth.forms import ReadOnlyPasswordHashField
from adminapp.models import CustomUser  # adjust if CustomUser is elsewhere
from django.forms import inlineformset_factory
from django.utils.timezone import now
from .models import *




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
        widget=forms.PasswordInput,
        required=False,
        help_text="Leave blank to keep current password"
    )
    
    class Meta:
        model = CustomUser
        fields = [
            'role', 'full_name', 'mobile', 'email', 
            'address', 'profile_picture', 'password', 'is_active'
        ]
        widgets = {
            'address': forms.Textarea(attrs={'rows': 3}),
            'email': forms.EmailInput(),
            'mobile': forms.TextInput(attrs={'maxlength': 15}),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Make password field not required for updates
        self.fields['password'].required = False
        
        # Add CSS classes if needed
        for field_name, field in self.fields.items():
            field.widget.attrs.update({'class': 'form-control'})
    
    def clean_email(self):
        email = self.cleaned_data.get('email')
        if email:
            # Check if email exists for other users (excluding current instance)
            qs = CustomUser.objects.filter(email=email)
            if self.instance:
                qs = qs.exclude(pk=self.instance.pk)
            if qs.exists():
                raise forms.ValidationError("A user with this email already exists.")
        return email
    
    def clean_mobile(self):
        mobile = self.cleaned_data.get('mobile')
        if mobile:
            # Check if mobile exists for other users (excluding current instance)
            qs = CustomUser.objects.filter(mobile=mobile)
            if self.instance:
                qs = qs.exclude(pk=self.instance.pk)
            if qs.exists():
                raise forms.ValidationError("A user with this mobile number already exists.")
        return mobile
    
    def save(self, commit=True):
        user = super().save(commit=False)
        
        # Only update password if it's provided
        password = self.cleaned_data.get("password")
        if password:
            user.set_password(password)
        
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

        if item_id:
            self.fields['species'].queryset = Species.objects.filter(item_id=item_id)
        else:
            self.fields['species'].queryset = Species.objects.none()

class FreezingCategoryForm(forms.ModelForm):
    class Meta:
        model = FreezingCategory
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

TenantFreezingTariffFormSet = inlineformset_factory(
    Tenant,
    TenantFreezingTariff,
    form=TenantFreezingTariffForm,
    extra=1,
    can_delete=True
)



class PurchaseOverheadForm(forms.ModelForm):
    class Meta:
        model = PurchaseOverhead
        fields = '__all__'

class PeelingOverheadForm(forms.ModelForm):
    class Meta:
        model = PeelingOverhead
        fields = '__all__'

class ProcessingOverheadForm(forms.ModelForm):
    class Meta:
        model = ProcessingOverhead
        fields = '__all__'

class ShipmentOverheadForm(forms.ModelForm):
    class Meta:
        model = ShipmentOverhead
        fields = '__all__'

class SettingsForm(forms.ModelForm):
    class Meta:
        model = Settings
        fields = ['dollar_rate_to_inr', 'vehicle_rent_km']

# forms for create a Purchase Entry 
class SpotPurchaseForm(forms.ModelForm):
    date = forms.DateField(
        widget=forms.TextInput(attrs={
            'class': 'form-control datepicker',
            'placeholder': 'dd/mm/yyyy'
        }),
        input_formats=['%d/%m/%Y'],  # ✅ Accept dd/mm/yyyy
        initial=now
    )

    class Meta:
        model = SpotPurchase
        fields = ['date', 'voucher_number', 'spot', 'supervisor', 'agent']
        widgets = {
            'voucher_number': forms.TextInput(attrs={'class': 'form-control'}),
            'spot': forms.Select(attrs={'class': 'form-control'}),
            'supervisor': forms.Select(attrs={'class': 'form-control'}),
            'agent': forms.Select(attrs={'class': 'form-control'}),
        }

class SpotPurchaseItemForm(forms.ModelForm):
    class Meta:
        model = SpotPurchaseItem
        fields = ['item','total_rate', 'quantity', 'rate', 'boxes']
        widgets = {
            'item': forms.Select(attrs={'class': 'form-control'}),
            'quantity': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01'}),
            'boxes': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01'}),
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
    date = forms.DateField(
        widget=forms.TextInput(attrs={
            'class': 'form-control datepicker',
            'placeholder': 'dd/mm/yyyy'
        }),
        input_formats=['%d/%m/%Y'],  # ✅ Accept dd/mm/yyyy
        initial=now
    )

    class Meta:
        model = LocalPurchase
        fields = ['date', 'voucher_number', 'party_name']
        widgets = {
            'voucher_number': forms.TextInput(attrs={'class': 'form-control'}),
            'party_name': forms.Select(attrs={'class': 'form-control'}),
        }

class LocalPurchaseItemForm(forms.ModelForm):
    class Meta:
        model = LocalPurchaseItem
        exclude = ['purchase', 'amount']
        widgets = {
            'item': forms.Select(attrs={'class': 'form-control'}),
            'item_quality': forms.Select(attrs={'class': 'form-control', 'id': 'id_item_quality'}),
            'species': forms.Select(attrs={'class': 'form-control'}),
            'grade': forms.Select(attrs={'class': 'form-control'}),
            'item_type': forms.Select(attrs={'class': 'form-control'}),
            'quantity': forms.NumberInput(attrs={'class': 'form-control quantity-input', 'step': '0.01'}),
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

FreezingEntryLocalItemFormSet = inlineformset_factory(
    FreezingEntryLocal,
    FreezingEntryLocalItem,
    form=FreezingEntryLocalItemForm,
    extra=1,
    can_delete=True
)





# Main form for PreShipmentWorkOut
class PreShipmentWorkOutForm(forms.ModelForm):
    class Meta:
        model = PreShipmentWorkOut
        fields = "__all__"
        exclude = ['remark']
        widgets = {
            'item': forms.Select(attrs={'class': 'form-control'}),
            'unit': forms.Select(attrs={'class': 'form-control'}),
            'glaze': forms.Select(attrs={'class': 'form-control'}),
            'category': forms.Select(attrs={'class': 'form-control'}),
            'brand': forms.Select(attrs={'class': 'form-control'}),
        }

# Inline form for PreShipmentWorkOutItem
class PreShipmentWorkOutItemForm(forms.ModelForm):
    class Meta:
        model = PreShipmentWorkOutItem
        fields = "__all__"
        exclude = ['remark']  # Exclude remark field
        widgets = {
            'item_quality': forms.Select(attrs={'class': 'form-control quality'}),
            'species': forms.Select(attrs={'class': 'form-control species'}),            
            'peeling_type': forms.Select(attrs={'class': 'form-control'}),
            'grade': forms.Select(attrs={'class': 'form-control'}),

            'cartons': forms.NumberInput(attrs={'class': 'form-control cartons'}),
            'quantity': forms.NumberInput(attrs={'class': 'form-control quantity'}),

            # "We want rate" fields
            'usd_rate_per_kg': forms.NumberInput(attrs={'class': 'form-control usd-rate-per-kg'}),
            'usd_rate_item': forms.NumberInput(attrs={'class': 'form-control usd-rate-item'}),
            'usd_rate_item_to_inr': forms.NumberInput(attrs={'class': 'form-control usd-rate-item-inr'}),

            # "We get rate" fields
            'usd_rate_per_kg_get': forms.NumberInput(attrs={'class': 'form-control usd-rate-per-kg-get'}),
            'usd_rate_item_get': forms.NumberInput(attrs={'class': 'form-control usd-rate-item-get'}),
            'usd_rate_item_to_inr_get': forms.NumberInput(attrs={'class': 'form-control usd-rate-item-inr-get'}),

            'profit': forms.NumberInput(attrs={'readonly': 'readonly', 'class': 'form-control profit'}),
            'loss': forms.NumberInput(attrs={'readonly': 'readonly', 'class': 'form-control loss'}),
        }

    def __init__(self, *args, **kwargs):
        item_id = kwargs.pop('item_id', None)
        super().__init__(*args, **kwargs)
        if item_id:
            self.fields['species'].queryset = Species.objects.filter(item_id=item_id)
        else:
            self.fields['species'].queryset = Species.objects.none()
            
# Inline formset to attach PreShipmentWorkOutItem to PreShipmentWorkOut
PreShipmentWorkOutItemFormSet = inlineformset_factory(
    PreShipmentWorkOut,
    PreShipmentWorkOutItem,
    form=PreShipmentWorkOutItemForm,
    extra=1,
    can_delete=True
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
        exclude = ['total_amount']  # Exclude if calculated automatically
        widgets = {
            'return_date': forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),  # Fixed field name
            'voucher_number': forms.TextInput(attrs={'class': 'form-control'}),
            'tenant_company_name': forms.Select(attrs={'class': 'form-control'}),

            'total_slab': forms.NumberInput(attrs={'readonly': 'readonly', 'class': 'form-control'}),
            'total_c_s': forms.NumberInput(attrs={'readonly': 'readonly', 'class': 'form-control'}),
            'total_kg': forms.NumberInput(attrs={'readonly': 'readonly', 'class': 'form-control'}),

            'return_status': forms.Select(attrs={'class': 'form-control'}),  # Fixed field name
        }

class ReturnTenantItemForm(forms.ModelForm):
    class Meta:
        model = ReturnTenantItem
        fields = "__all__"
        widgets = {
            'original_item': forms.Select(attrs={'class': 'form-control original-item-select'}),  # Added for traceability
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
        
        # Filter original_item to show only items from the same tenant
        if 'tenant_company_name' in self.initial:
            tenant = self.initial['tenant_company_name']
            self.fields['original_item'].queryset = FreezingEntryTenantItem.objects.filter(
                freezing_entry__tenant_company_name=tenant
            ).select_related('item', 'freezing_entry')
        
        # Make original_item optional but helpful
        self.fields['original_item'].required = False
        self.fields['original_item'].help_text = "Link to original stock lot (optional)"

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
            "kg_quantity": forms.NumberInput(attrs={"class": "form-control", "step": "0.01"}),
        }

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
class SupervisorVoucherForm(forms.ModelForm):
    class Meta:
        model = SupervisorVoucher
        fields = ["voucher_no", "supervisor", "date", "description", "receipt", "payment"]
        widgets = {
            "voucher_no": forms.TextInput(attrs={"class": "form-control"}),
            "supervisor": forms.Select(attrs={"class": "form-control"}),
            "date": forms.DateInput(attrs={"type": "date", "class": "form-control"}),
            "description": forms.Textarea(attrs={"class": "form-control", "rows": 2}),
            "receipt": forms.NumberInput(attrs={"class": "form-control"}),
            "payment": forms.NumberInput(attrs={"class": "form-control"}),
        }


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






