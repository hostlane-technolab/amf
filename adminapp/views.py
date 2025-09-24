# Create your views here.
from .models import *
from .forms import *
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from .forms import CustomUserCreationForm
from django.contrib.auth import authenticate, login, logout
from django.db import transaction
from django.urls import reverse_lazy
from django.views.generic.edit import CreateView, UpdateView, DeleteView 
from django.views.generic import DetailView, ListView
from decimal import Decimal
from django.views import View
from django.db.models import Sum, Count, Avg, DecimalField, Value as V
from django.db.models.functions import Coalesce
from django.http import JsonResponse
from django.utils.timezone import now
from datetime import timedelta, datetime
import xlsxwriter
from django.db.models import Sum, F, FloatField
from django.http import HttpResponse
from datetime import datetime, timedelta
import csv
import io
from django.db.models import Sum, Avg, F, Value, CharField, DecimalField, FloatField
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from .models import ItemQuality
from django.db import transaction
from django.urls import reverse
import io
from django.shortcuts import get_object_or_404
from django.http import HttpResponse
from django.template.loader import get_template
from xhtml2pdf import pisa
from collections import defaultdict
from django.contrib import messages
from django.db import transaction
from django.http import JsonResponse, HttpResponse
from django.utils import timezone
from datetime import timedelta
from decimal import Decimal
import logging
from django.contrib import messages
from django.db import transaction
from django.utils import timezone
from django.http import JsonResponse
from django.views.generic import ListView
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from .models import StoreTransfer, StoreTransferItem, Stock, Store
from .forms import StoreTransferForm, StoreTransferItemFormSet
from django.views.generic import ListView, DetailView, TemplateView
from django.db.models import Q, F, Sum
from django.core.paginator import Paginator
from django.forms import formset_factory
from .forms import StoreTransferForm, StoreTransferItemFormSet
from django.views.generic import ListView, DetailView, TemplateView
from django.db.models import Q, F, Sum
from django.core.paginator import Paginator
from django.forms import formset_factory
from datetime import datetime, timedelta, date
from decimal import Decimal
import json
import re




logger = logging.getLogger(__name__)

# Import your models and forms - change names/paths if different in your project
from adminapp.models import (
    TenantBill, TenantBillItem, TenantBillingConfiguration,
    TenantFreezingTariff, FreezingEntryTenant
)
from adminapp.forms import TenantBillingConfigurationForm, BillGenerationForm

from decimal import Decimal
import logging

logger = logging.getLogger(__name__)


# nammude client paranjhu name chage cheyyan athu too risk anu athukondu html name mathre matittullu
# item category ennu parayunne elam item quality anu  model name itemQuality
# item group ennu parayunne elam item category anu model name itemCategory

# views.py - Permission checking decorators and mixins

from django.contrib.auth.decorators import permission_required
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.core.exceptions import PermissionDenied
from django.shortcuts import redirect
from django.contrib import messages
from django.contrib.auth.models import Permission
from django.shortcuts import get_object_or_404, render, redirect
from django.contrib import messages

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import permission_required
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.contrib.auth.models import Permission
from django.core.exceptions import PermissionDenied
from django.contrib.contenttypes.models import ContentType

def check_permission(permission_name):
    """Decorator to check custom permissions"""
    def decorator(view_func):
        def wrapper(request, *args, **kwargs):
            if not request.user.has_perm(f'adminapp.{permission_name}'):
                messages.error(request, 'You do not have permission to access this page.')
                return redirect('adminapp:admin_dashboard')
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator

class CustomPermissionMixin(PermissionRequiredMixin):
    """Custom permission mixin for class-based views"""
    def handle_no_permission(self):
        messages.error(self.request, 'You do not have permission to access this page.')
        return redirect('adminapp:admin_dashboard')

@check_permission('user_management_edit')
def assign_user_permissions(request, user_id):
    user = get_object_or_404(CustomUser, id=user_id)
    
    if request.method == 'POST':
        selected_permissions = request.POST.getlist('permissions')
        
        # Clear existing permissions
        user.user_permissions.clear()
        
        # Add selected permissions
        for perm_id in selected_permissions:
            try:
                permission = Permission.objects.get(id=perm_id)
                user.user_permissions.add(permission)
            except Permission.DoesNotExist:
                continue
        
        messages.success(request, f'Permissions updated for {user.full_name}')
        return redirect('adminapp:users_list')
    
    # Get all custom permissions grouped by category
    all_permissions = Permission.objects.filter(
        content_type__app_label='adminapp'
    ).order_by('name')
    
    print(f"Found {all_permissions.count()} permissions")  # Debug line
    for perm in all_permissions:
        print(f"- {perm.codename}: {perm.name}")  # Debug line
    
    user_permissions = user.user_permissions.all()
    
    # Group permissions by category
    permission_groups = {
        'Master Data': all_permissions.filter(codename__startswith='master_data'),
        'Purchasing': all_permissions.filter(codename__startswith='purchasing'),
        'Processing': all_permissions.filter(codename__startswith='processing'),
        'Shipping': all_permissions.filter(codename__startswith='shipping'),
        'Reports': all_permissions.filter(codename__startswith='reports'),
        'Billing': all_permissions.filter(codename__startswith='billing'),
        'Freezing': all_permissions.filter(codename__startswith='freezing'),
        'Voucher': all_permissions.filter(codename__startswith='voucher'),
        'User Management': all_permissions.filter(codename__startswith='user_management'),
    }
    
    # Debug: Check what's in each group
    for group_name, perms in permission_groups.items():
        print(f"{group_name}: {perms.count()} permissions")
    
    context = {
        'user': user,
        'permission_groups': permission_groups,
        'user_permissions': user_permissions,
        'all_permissions_count': all_permissions.count(),  # Add this for template debugging
    }
    
    return render(request, 'adminapp/assign_permissions.html', context)


# Template context processor to make permissions available in templates
def permission_processor(request):
    """Add user permissions to template context"""
    if request.user.is_authenticated:
        return {
            'user_permissions': {
                'can_view_master_data': request.user.has_perm('adminapp.master_data_view'),
                'can_add_master_data': request.user.has_perm('adminapp.master_data_add'),
                'can_view_purchasing': request.user.has_perm('adminapp.purchasing_view'),
                'can_add_purchasing': request.user.has_perm('adminapp.purchasing_add'),
                'can_view_processing': request.user.has_perm('adminapp.processing_view'),

                'can_add_shipping': request.user.has_perm('adminapp.shipping_add'),
                'can_view_shipping': request.user.has_perm('adminapp.shipping_view'),
                'can_edit_shipping': request.user.has_perm('adminapp.shipping_edit'),
                'can_delete_shipping': request.user.has_perm('adminapp.shipping_delete'),

                'can_add_freezing': request.user.has_perm('adminapp.freezing_add'),
                'can_view_freezing': request.user.has_perm('adminapp.freezing_view'),
                'can_edit_freezing': request.user.has_perm('adminapp.freezing_edit'),
                'can_delete_freezing': request.user.has_perm('adminapp.freezing_delete'),

                'can_add_voucher': request.user.has_perm('adminapp.voucher_add'),
                'can_view_voucher': request.user.has_perm('adminapp.voucher_view'),
                'can_edit_voucher': request.user.has_perm('adminapp.voucher_edit'),
                'can_delete_voucher': request.user.has_perm('adminapp.voucher_delete'),

                'can_view_reports': request.user.has_perm('adminapp.reports_view'),
                'can_export_reports': request.user.has_perm('adminapp.reports_export'),

                'can_view_billing': request.user.has_perm('adminapp.billing_view'),
                'can_delete_billing': request.user.has_perm('adminapp.billing_delete'),
                'can_manage_users': request.user.has_perm('adminapp.user_management_view'),
            }
        }
    return {}




# Check if user is an admin
def is_admin(user):
    return user.is_authenticated and user.role == 'admin'

# Admin login view
def user_login(request):
    """Login view for both users and admin"""
    if request.user.is_authenticated:
        # Redirect based on user type
        if request.user.is_staff or request.user.is_superuser:
            return redirect('adminapp:admin_dashboard')
        else:
            return redirect('adminapp:user_dashboard')  # Assuming you have a user dashboard
    
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        if email and password:
            user = authenticate(request, username=email, password=password)
            
            if user is not None:
                if user.is_active:
                    login(request, user)
                    messages.success(request, f'Welcome back, {user.full_name}!')
                    
                    # Redirect based on user type
                    if user.is_staff or user.is_superuser:
                        return redirect('adminapp:admin_dashboard')
                    else:
                        return redirect('adminapp:user_dashboard')  # Regular user dashboard
                else:
                    messages.error(request, 'Your account is inactive. Please contact administrator.')
            else:
                messages.error(request, 'Invalid email or password.')
        else:
            messages.error(request, 'Please enter both email and password.')
    
    return render(request, 'adminapp/login.html')


# Admin logout view
def admin_logout(request):
    logout(request)
    return redirect('adminapp:admin_login')

@login_required
@check_permission('user_management_add')
def create_user_view(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            messages.success(request, 'User created successfully.')
            return redirect('adminapp:create_user')  # Redirect to form again or elsewhere
        else:
            messages.error(request, 'Error creating user.')
    else:
        form = CustomUserCreationForm()
    return render(request, 'adminapp/create_user.html', {'form': form})

@check_permission('user_management_view')
def users_list_view(request):
    users = CustomUser.objects.all().order_by('-date_joined')
    
    context = {
        'users': users,
    }
    
    return render(request, 'adminapp/list/users_list.html', context)

class CustomUserUpdateView(LoginRequiredMixin, UpdateView):
    model = CustomUser
    form_class = CustomUserUpdateForm
    template_name = 'adminapp/customuser_form.html'
    success_url = reverse_lazy('adminapp:users_list')
    context_object_name = 'user_obj'  # Avoid conflict with request.user
    
    def form_valid(self, form):
        messages.success(self.request, 'User updated successfully.')
        return super().form_valid(form)
    
    def form_invalid(self, form):
        messages.error(self.request, 'Error updating user.')
        return super().form_invalid(form)

class UserDeleteView(CustomPermissionMixin,DeleteView):
    permission_required = 'adminapp.user_management_delete'
    model = CustomUser
    template_name = 'adminapp/confirm_delete.html'
    success_url = reverse_lazy('adminapp:users_list')

    
# Dashboard View
def admin_dashboard(request):
    return render(request, 'adminapp/dashboard.html')

def user_dashboard(request):
    return render(request, 'adminapp/user_dashboard.html')


def master(request):
    return render(request, 'adminapp/master.html')
# -------------------------------
# Operational & Location Masters
# -------------------------------


class ProcessingCenterCreateView(CreateView):
    model = ProcessingCenter
    form_class = ProcessingCenterForm
    template_name = 'adminapp/forms/processingcenter_form.html'
    success_url = reverse_lazy('adminapp:processing_center_create')

class ProcessingCenterListView(ListView):
    model = ProcessingCenter
    template_name = 'adminapp/list/processingcenter_list.html'
    context_object_name = 'processing_centers'

class ProcessingCenterUpdateView(UpdateView):
    model = ProcessingCenter
    form_class = ProcessingCenterForm
    template_name = 'adminapp/forms/processingcenter_form.html'
    success_url = reverse_lazy('adminapp:processing_center_list')

class ProcessingCenterDeleteView(DeleteView):
    model = ProcessingCenter
    template_name = 'adminapp/confirm_delete.html'
    success_url = reverse_lazy('adminapp:processing_center_list')

class StoreCreateView(CreateView):
    model = Store
    form_class = StoreForm
    template_name = 'adminapp/forms/store_form.html'
    success_url = reverse_lazy('adminapp:store_create')

class StoreListView(ListView):
    model = Store
    template_name = 'adminapp/list/store_list.html'
    context_object_name = 'stores'

class StoreUpdateView(UpdateView):
    model = Store
    form_class = StoreForm
    template_name = 'adminapp/forms/store_form.html'
    success_url = reverse_lazy('adminapp:store_list')

class StoreDeleteView(DeleteView):
    model = Store
    template_name = 'adminapp/confirm_delete.html'
    success_url = reverse_lazy('adminapp:store_list')

def create_shed(request):
    if request.method == 'POST':
        form = ShedForm(request.POST)
        formset = ShedItemFormSet(request.POST)

        if form.is_valid() and formset.is_valid():
            shed = form.save()
            items = formset.save(commit=False)

            for item in items:
                item.shed = shed
                item.save()

            for deleted_item in formset.deleted_objects:
                deleted_item.delete()

            return redirect('adminapp:peeling_center_list')
    else:
        form = ShedForm()
        formset = ShedItemFormSet()

    return render(request, 'adminapp/forms/create_shed.html', {
        'form': form,
        'formset': formset,
    })

def get_item_types(request):
    item_id = request.GET.get('item_id')
    item_types = ItemType.objects.filter(item_id=item_id).values('id', 'name')
    return JsonResponse(list(item_types), safe=False)

class ShedListView(ListView):
    model = Shed
    template_name = 'adminapp/list/shed_list.html'
    context_object_name = 'peeling_centers'

def update_shed(request, pk):
    shed = get_object_or_404(Shed, pk=pk)

    if request.method == 'POST':
        form = ShedForm(request.POST, instance=shed)
        formset = ShedItemFormSet(request.POST, instance=shed)

        if form.is_valid() and formset.is_valid():
            shed = form.save()
            items = formset.save(commit=False)

            for item in items:
                item.shed = shed
                item.save()

            # Delete any items marked for deletion
            for deleted_item in formset.deleted_objects:
                deleted_item.delete()

            return redirect('adminapp:peeling_center_list')
    else:
        form = ShedForm(instance=shed)
        formset = ShedItemFormSet(instance=shed)

    return render(request, 'adminapp/forms/update_shed.html', {
        'form': form,
        'formset': formset,
        'shed': shed
    })

class ShedDeleteView(DeleteView):
    model = Shed
    template_name = 'adminapp/confirm_delete.html'
    success_url = reverse_lazy('adminapp:peeling_center_list')

class LocalPartyCreateView(CreateView):
    model = LocalParty
    form_class = LocalPartyForm
    template_name = 'adminapp/forms/LocalParty_form.html'
    success_url = reverse_lazy('adminapp:LocalParty_create')

class LocalPartyListView(ListView):
    model = LocalParty
    template_name = 'adminapp/list/LocalParty_list.html'
    context_object_name = 'purchasing_spots'

class LocalPartyUpdateView(UpdateView):
    model = LocalParty
    form_class = PurchasingSpotForm
    template_name = 'adminapp/forms/LocalParty_form.html'
    success_url = reverse_lazy('adminapp:LocalParty_create')

class LocalPartyDeleteView(DeleteView):
    model = LocalParty
    template_name = 'adminapp/confirm_delete.html'
    success_url = reverse_lazy('adminapp:LocalParty_create')

class PurchasingSpotCreateView(CreateView):
    model = PurchasingSpot
    form_class = PurchasingSpotForm
    template_name = 'adminapp/forms/purchasingspot_form.html'
    success_url = reverse_lazy('adminapp:purchasing_spot_create')

class PurchasingSpotListView(ListView):
    model = PurchasingSpot
    template_name = 'adminapp/list/purchasingspot_list.html'
    context_object_name = 'purchasing_spots'

class PurchasingSpotUpdateView(UpdateView):
    model = PurchasingSpot
    form_class = PurchasingSpotForm
    template_name = 'adminapp/forms/purchasingspot_form.html'
    success_url = reverse_lazy('adminapp:purchasing_spot_list')

class PurchasingSpotDeleteView(DeleteView):
    model = PurchasingSpot
    template_name = 'adminapp/confirm_delete.html'
    success_url = reverse_lazy('adminapp:purchasing_spot_list')

# -------------------
# Personnel Masters
# -------------------

class PurchasingSupervisorCreateView(CreateView):
    model = PurchasingSupervisor
    form_class = PurchasingSupervisorForm
    template_name = 'adminapp/forms/purchasingsupervisor_form.html'
    success_url = reverse_lazy('adminapp:purchasing_supervisor_create')

class PurchasingSupervisorListView(ListView):
    model = PurchasingSupervisor
    template_name = 'adminapp/list/purchasingsupervisor_list.html'
    context_object_name = 'purchasing_supervisors'

class PurchasingSupervisorUpdateView(UpdateView):
    model = PurchasingSupervisor
    form_class = PurchasingSupervisorForm
    template_name = 'adminapp/forms/purchasingsupervisor_form.html'
    success_url = reverse_lazy('adminapp:purchasing_supervisor_list')

class PurchasingSupervisorDeleteView(DeleteView):
    model = PurchasingSupervisor
    template_name = 'adminapp/confirm_delete.html'
    success_url = reverse_lazy('adminapp:purchasing_supervisor_list')

class PurchasingAgentCreateView(CreateView):
    model = PurchasingAgent
    form_class = PurchasingAgentForm
    template_name = 'adminapp/forms/purchasingagent_form.html'
    success_url = reverse_lazy('adminapp:purchasing_agent_create')

class PurchasingAgentListView(ListView):
    model = PurchasingAgent
    template_name = 'adminapp/list/purchasingagent_list.html'
    context_object_name = 'purchasing_agents'

class PurchasingAgentUpdateView(UpdateView):
    model = PurchasingAgent
    form_class = PurchasingAgentForm
    template_name = 'adminapp/forms/purchasingagent_form.html'
    success_url = reverse_lazy('adminapp:purchasing_agent_list')

class PurchasingAgentDeleteView(DeleteView):
    model = PurchasingAgent
    template_name = 'adminapp/confirm_delete.html'
    success_url = reverse_lazy('adminapp:purchasing_agent_list')

# ----------------------
# Item & Product Masters
# ----------------------

class ItemCategoryCreateView(CreateView):
    model = ItemCategory
    form_class = ItemCategoryForm
    template_name = 'adminapp/forms/itemcategory_form.html'
    success_url = reverse_lazy('adminapp:item_category_create')

class ItemCategoryListView(ListView):
    model = ItemCategory
    template_name = 'adminapp/list/itemcategory_list.html'
    context_object_name = 'item_categories'

class ItemCategoryUpdateView(UpdateView):
    model = ItemCategory
    form_class = ItemCategoryForm
    template_name = 'adminapp/forms/itemcategory_form.html'
    success_url = reverse_lazy('adminapp:item_category_list')

class ItemCategoryDeleteView(DeleteView):
    model = ItemCategory
    template_name = 'adminapp/confirm_delete.html'
    success_url = reverse_lazy('adminapp:item_category_list')

class ItemCreateView(CreateView):
    model = Item
    form_class = ItemForm
    template_name = 'adminapp/forms/item_form.html'
    success_url = reverse_lazy('adminapp:item_create')

class ItemListView(ListView):
    model = Item
    template_name = 'adminapp/list/item_list.html'
    context_object_name = 'items'

class ItemUpdateView(UpdateView):
    model = Item
    form_class = ItemForm
    template_name = 'adminapp/forms/item_form.html'
    success_url = reverse_lazy('adminapp:item_list')

class ItemDeleteView(DeleteView):
    model = Item
    template_name = 'adminapp/confirm_delete.html'
    success_url = reverse_lazy('adminapp:item_list')

class ItemQualityCreateView(CreateView):
    model = ItemQuality
    form_class = ItemQualityForm
    template_name = 'adminapp/forms/itemquality_form.html'
    success_url = reverse_lazy('adminapp:item_quality_create')

class ItemQualityListView(ListView):
    model = ItemQuality
    template_name = 'adminapp/list/itemquality_list.html'
    context_object_name = 'item_qualities'

class ItemQualityUpdateView(UpdateView):
    model = ItemQuality
    form_class = ItemQualityForm
    template_name = 'adminapp/forms/itemquality_form.html'
    success_url = reverse_lazy('adminapp:item_quality_list')

class ItemQualityDeleteView(DeleteView):
    model = ItemQuality
    template_name = 'adminapp/confirm_delete.html'
    success_url = reverse_lazy('adminapp:item_quality_list')

class SpeciesListView(ListView):
    model = Species
    template_name = 'adminapp/list/species_list.html'
    context_object_name = 'species_list'

class SpeciesCreateView(CreateView):
    model = Species
    form_class = SpeciesForm
    template_name = 'adminapp/forms/species_form.html'
    success_url = reverse_lazy('adminapp:species_list')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['action'] = 'Create'
        return context

class SpeciesUpdateView(UpdateView):
    model = Species
    form_class = SpeciesForm
    template_name = 'adminapp/forms/species_form.html'
    success_url = reverse_lazy('adminapp:species_list')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['action'] = 'Update'
        return context

class SpeciesDeleteView(DeleteView):
    model = Species
    template_name = 'adminapp/confirm_delete.html'
    success_url = reverse_lazy('adminapp:species_list')

class ItemGradeCreateView(CreateView):
    model = ItemGrade
    form_class = ItemGradeForm
    template_name = 'adminapp/forms/itemgrade_form.html'
    success_url = reverse_lazy('adminapp:item_grade_list')

def load_species(request):
    item_id = request.GET.get('item_id')
    species = Species.objects.filter(item_id=item_id).values('id', 'name', 'code')
    data = list(species)
    return JsonResponse(data, safe=False)

class ItemGradeListView(ListView):
    model = ItemGrade
    template_name = 'adminapp/list/itemgrade_list.html'
    context_object_name = 'item_grades'

class ItemGradeUpdateView(UpdateView):
    model = ItemGrade
    form_class = ItemGradeForm
    template_name = 'adminapp/forms/itemgrade_form.html'
    success_url = reverse_lazy('adminapp:item_grade_list')

class ItemGradeDeleteView(DeleteView):
    model = ItemGrade
    template_name = 'adminapp/confirm_delete.html'
    success_url = reverse_lazy('adminapp:item_grade_list')

class FreezingCategoryCreateView(CreateView):
    model = FreezingCategory
    form_class = FreezingCategoryForm
    template_name = 'adminapp/forms/freezingcategory_form.html'
    success_url = reverse_lazy('adminapp:freezing_category_create')

class FreezingCategoryListView(ListView):
    model = FreezingCategory
    template_name = 'adminapp/list/freezingcategory_list.html'
    context_object_name = 'freezing_categories'

class FreezingCategoryUpdateView(UpdateView):
    model = FreezingCategory
    form_class = FreezingCategoryForm
    template_name = 'adminapp/forms/freezingcategory_form.html'
    success_url = reverse_lazy('adminapp:freezing_category_list')

class FreezingCategoryDeleteView(DeleteView):
    model = FreezingCategory
    template_name = 'adminapp/confirm_delete.html'
    success_url = reverse_lazy('adminapp:freezing_category_list')

class PackingUnitCreateView(CreateView):
    model = PackingUnit
    form_class = PackingUnitForm
    template_name = 'adminapp/forms/packingunit_form.html'
    success_url = reverse_lazy('adminapp:packing_unit_create')

class PackingUnitListView(ListView):
    model = PackingUnit
    template_name = 'adminapp/list/packingunit_list.html'
    context_object_name = 'packing_units'

class PackingUnitUpdateView(UpdateView):
    model = PackingUnit
    form_class = PackingUnitForm
    template_name = 'adminapp/forms/packingunit_form.html'
    success_url = reverse_lazy('adminapp:packing_unit_list')

class PackingUnitDeleteView(DeleteView):
    model = PackingUnit
    template_name = 'adminapp/confirm_delete.html'
    success_url = reverse_lazy('adminapp:packing_unit_list')

class GlazePercentageCreateView(CreateView):
    model = GlazePercentage
    form_class = GlazePercentageForm
    template_name = 'adminapp/forms/glazepercentage_form.html'
    success_url = reverse_lazy('adminapp:glaze_percentage_create')

class GlazePercentageListView(ListView):
    model = GlazePercentage
    template_name = 'adminapp/list/glazepercentage_list.html'
    context_object_name = 'glaze_percentages'

class GlazePercentageUpdateView(UpdateView):
    model = GlazePercentage
    form_class = GlazePercentageForm
    template_name = 'adminapp/forms/glazepercentage_form.html'
    success_url = reverse_lazy('adminapp:glaze_percentage_list')

class GlazePercentageDeleteView(DeleteView):
    model = GlazePercentage
    template_name = 'adminapp/confirm_delete.html'
    success_url = reverse_lazy('adminapp:glaze_percentage_list')

class ItemBrandCreateView(CreateView):
    model = ItemBrand
    form_class = ItemBrandForm
    template_name = 'adminapp/forms/itembrand_form.html'
    success_url = reverse_lazy('adminapp:item_brand_create')

class ItemBrandListView(ListView):
    model = ItemBrand
    template_name = 'adminapp/list/itembrand_list.html'
    context_object_name = 'item_brands'

class ItemBrandUpdateView(UpdateView):
    model = ItemBrand
    form_class = ItemBrandForm
    template_name = 'adminapp/forms/itembrand_form.html'
    success_url = reverse_lazy('adminapp:item_brand_list')

class ItemBrandDeleteView(DeleteView):
    model = ItemBrand
    template_name = 'adminapp/confirm_delete.html'
    success_url = reverse_lazy('adminapp:item_brand_list')

class ItemTypeCreateView(CreateView):
    model = ItemType
    form_class = ItemTypeForm
    template_name = 'adminapp/forms/itemtype_form.html'
    success_url = reverse_lazy('adminapp:item_type_create')

class ItemTypeListView(ListView):
    model = ItemType
    template_name = 'adminapp/list/itemtype_list.html'
    context_object_name = 'item_types'

class ItemTypeUpdateView(UpdateView):
    model = ItemType
    form_class = ItemTypeForm
    template_name = 'adminapp/forms/itemtype_form.html'
    success_url = reverse_lazy('adminapp:item_type_list')

class ItemTypeDeleteView(DeleteView):
    model = ItemType
    template_name = 'adminapp/confirm_delete.html'
    success_url = reverse_lazy('adminapp:item_type_list')

# ----------------------------
# Financial & Expense Masters
# ----------------------------



class TenantCreateView(CreateView):
    model = Tenant
    form_class = TenantForm
    template_name = 'adminapp/forms/tenant_form.html'
    success_url = reverse_lazy('adminapp:tenant_list')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        if self.request.POST:
            context['formset'] = TenantFreezingTariffFormSet(self.request.POST)
        else:
            context['formset'] = TenantFreezingTariffFormSet()
        return context

    def form_valid(self, form):
        context = self.get_context_data()
        formset = context['formset']
        if form.is_valid() and formset.is_valid():
            tenant = form.save()
            formset.instance = tenant
            formset.save()
            return redirect(self.success_url)
        return self.render_to_response(self.get_context_data(form=form))


class TenantListView(ListView):
    model = Tenant
    template_name = 'adminapp/list/tenant_list.html'
    context_object_name = 'tenants'


class TenantUpdateView(UpdateView):
    model = Tenant
    form_class = TenantForm
    template_name = 'adminapp/forms/tenant_form.html'
    success_url = reverse_lazy('adminapp:tenant_list')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        if self.request.POST:
            context['formset'] = TenantFreezingTariffFormSet(self.request.POST, instance=self.object)
        else:
            context['formset'] = TenantFreezingTariffFormSet(instance=self.object)
        return context

    def form_valid(self, form):
        context = self.get_context_data()
        formset = context['formset']
        if form.is_valid() and formset.is_valid():
            tenant = form.save()
            formset.instance = tenant
            formset.save()
            return redirect(self.success_url)
        return self.render_to_response(self.get_context_data(form=form))


class TenantDeleteView(DeleteView):
    model = Tenant
    template_name = 'adminapp/confirm_delete.html'
    success_url = reverse_lazy('adminapp:tenant_list')





class PurchaseOverheadCreateView(CreateView):
    model = PurchaseOverhead
    form_class = PurchaseOverheadForm
    template_name = 'adminapp/forms/purchaseoverhead_form.html'
    success_url = reverse_lazy('adminapp:purchase_overhead_create')

class PurchaseOverheadListView(ListView):
    model = PurchaseOverhead
    template_name = 'adminapp/list/purchaseoverhead_list.html'
    context_object_name = 'purchase_overheads'

class PurchaseOverheadUpdateView(UpdateView):
    model = PurchaseOverhead
    form_class = PurchaseOverheadForm
    template_name = 'adminapp/forms/purchaseoverhead_form.html'
    success_url = reverse_lazy('adminapp:purchase_overhead_list')

class PurchaseOverheadDeleteView(DeleteView):
    model = PurchaseOverhead
    template_name = 'adminapp/confirm_delete.html'
    success_url = reverse_lazy('adminapp:purchase_overhead_list')

class PeelingOverheadCreateView(CreateView):
    model = PeelingOverhead
    form_class = PeelingOverheadForm
    template_name = 'adminapp/forms/peelingoverhead_form.html'
    success_url = reverse_lazy('adminapp:peeling_overhead_create')

class PeelingOverheadListView(ListView):
    model = PeelingOverhead
    template_name = 'adminapp/list/peelingoverhead_list.html'
    context_object_name = 'peeling_overheads'

class PeelingOverheadUpdateView(UpdateView):
    model = PeelingOverhead
    form_class = PeelingOverheadForm
    template_name = 'adminapp/forms/peelingoverhead_form.html'
    success_url = reverse_lazy('adminapp:peeling_overhead_list')

class PeelingOverheadDeleteView(DeleteView):
    model = PeelingOverhead
    template_name = 'adminapp/confirm_delete.html'
    success_url = reverse_lazy('adminapp:peeling_overhead_list')

class ProcessingOverheadCreateView(CreateView):
    model = ProcessingOverhead
    form_class = ProcessingOverheadForm
    template_name = 'adminapp/forms/processingoverhead_form.html'
    success_url = reverse_lazy('adminapp:processing_overhead_create')

class ProcessingOverheadListView(ListView):
    model = ProcessingOverhead
    template_name = 'adminapp/list/processingoverhead_list.html'
    context_object_name = 'processing_overheads'

class ProcessingOverheadUpdateView(UpdateView):
    model = ProcessingOverhead
    form_class = ProcessingOverheadForm
    template_name = 'adminapp/forms/processingoverhead_form.html'
    success_url = reverse_lazy('adminapp:processing_overhead_list')

class ProcessingOverheadDeleteView(DeleteView):
    model = ProcessingOverhead
    template_name = 'adminapp/confirm_delete.html'
    success_url = reverse_lazy('adminapp:processing_overhead_list')

class ShipmentOverheadCreateView(CreateView):
    model = ShipmentOverhead
    form_class = ShipmentOverheadForm
    template_name = 'adminapp/forms/shipmentoverhead_form.html'
    success_url = reverse_lazy('adminapp:shipment_overhead_create')

class ShipmentOverheadListView(ListView):
    model = ShipmentOverhead
    template_name = 'adminapp/list/shipmentoverhead_list.html'
    context_object_name = 'shipment_overheads'

class ShipmentOverheadUpdateView(UpdateView):
    model = ShipmentOverhead
    form_class = ShipmentOverheadForm
    template_name = 'adminapp/forms/shipmentoverhead_form.html'
    success_url = reverse_lazy('adminapp:shipment_overhead_list')

class ShipmentOverheadDeleteView(DeleteView):
    model = ShipmentOverhead
    template_name = 'adminapp/confirm_delete.html'
    success_url = reverse_lazy('adminapp:shipment_overhead_list')

def settings_create(request):
    if request.method == 'POST':
        form = SettingsForm(request.POST)
        if form.is_valid():
            dollar_rate = form.cleaned_data['dollar_rate_to_inr']
            vehicle_rent = form.cleaned_data['vehicle_rent_km']

            # Only create if NO active settings exist with same values
            exists = Settings.objects.filter(
                dollar_rate_to_inr=dollar_rate,
                vehicle_rent_km=vehicle_rent,
                is_active=True
            ).exists()

            if not exists:
                # deactivate all old ones
                Settings.objects.filter(is_active=True).update(is_active=False)
                # create new one
                form.save()
            return redirect('adminapp:settings_list')
    else:
        form = SettingsForm()

    return render(request, 'adminapp/forms/settings_form.html', {'form': form})

def settings_update(request, pk):
    old_setting = get_object_or_404(Settings, pk=pk)

    if request.method == 'POST':
        # Don’t bind to old instance → we want a *new* row
        form = SettingsForm(request.POST)
        if form.is_valid():
            # Mark old setting inactive
            old_setting.is_active = False
            old_setting.save()

            # Create new setting
            new_setting = form.save(commit=False)
            new_setting.is_active = True
            new_setting.save()

            return redirect('adminapp:settings_list')
    else:
        # Prefill form with old values for editing
        form = SettingsForm(instance=old_setting)

    return render(request, 'adminapp/forms/settings_form.html', {'form': form})

def settings_delete(request, pk):
    setting = get_object_or_404(Settings, pk=pk)
    if request.method == 'POST':
        setting.is_active = False   # mark inactive instead of deleting
        setting.save()
        return redirect('adminapp:settings_list')

    return render(request, 'adminapp/confirm_delete.html', {'setting': setting})

def settings_list(request):
    settings = Settings.objects.filter(is_active=True).order_by('-created_at')
    return render(request, 'adminapp/list/settings_list.html', {'settings': settings})


# function for SpotPurchase Entry
@check_permission('purchasing_add')
def create_spot_purchase(request):
    if request.method == 'POST':
        purchase_form = SpotPurchaseForm(request.POST)
        item_formset = SpotPurchaseItemFormSet(request.POST)
        expense_form = SpotPurchaseExpenseForm(request.POST)

        if purchase_form.is_valid() and item_formset.is_valid() and expense_form.is_valid():
            purchase = purchase_form.save()

            # Save expense first to calculate total_expense
            expense = expense_form.save(commit=False)
            expense.purchase = purchase
            expense.save()  # This will calculate total_expense in the model's save method

            # Save items with proper calculations
            items = item_formset.save(commit=False)
            for item in items:
                item.purchase = purchase
                item.save()  # Let the model's save method handle amount and rate calculation
            item_formset.save_m2m()

            # Use the model's calculate_totals method instead of manual calculation
            purchase.calculate_totals()

            return redirect('adminapp:spot_purchase_list')

    else:
        purchase_form = SpotPurchaseForm()
        item_formset = SpotPurchaseItemFormSet()
        expense_form = SpotPurchaseExpenseForm()

    return render(request, 'adminapp/purchases/spot_purchase_form.html', {
        'purchase_form': purchase_form,
        'item_formset': item_formset,
        'expense_form': expense_form,
    })

@check_permission('purchasing_edit')
def edit_spot_purchase(request, pk):
    purchase = get_object_or_404(SpotPurchase, pk=pk)
    SpotPurchaseItemFormSet = inlineformset_factory(
        SpotPurchase,
        SpotPurchaseItem,
        form=SpotPurchaseItemForm,
        extra=0,
        can_delete=True
    )

    # Get expense or set to None if it doesn't exist
    try:
        expense = purchase.expense
    except SpotPurchaseExpense.DoesNotExist:
        expense = None

    if request.method == 'POST':
        purchase_form = SpotPurchaseForm(request.POST, instance=purchase)
        item_formset = SpotPurchaseItemFormSet(request.POST, instance=purchase)
        expense_form = SpotPurchaseExpenseForm(request.POST, instance=expense)

        if purchase_form.is_valid() and item_formset.is_valid() and expense_form.is_valid():
            purchase = purchase_form.save()

            # Save expense first to calculate total_expense
            expense = expense_form.save(commit=False)
            expense.purchase = purchase
            expense.save()  # This will calculate total_expense in the model's save method

            # Save items with proper calculations
            items = item_formset.save(commit=False)
            for item in items:
                item.purchase = purchase
                item.save()  # Let the model's save method handle amount and rate calculation
            item_formset.save_m2m()

            # Handle deleted items
            for obj in item_formset.deleted_objects:
                obj.delete()

            # Use the model's calculate_totals method instead of manual calculation
            purchase.calculate_totals()

            return redirect('adminapp:spot_purchase_list')

        # 🐍 Debugging form errors
        print("Purchase Form Errors:", purchase_form.errors)
        print("Item Formset Errors:", item_formset.errors)
        print("Expense Form Errors:", expense_form.errors)

    else:
        purchase_form = SpotPurchaseForm(instance=purchase)
        item_formset = SpotPurchaseItemFormSet(instance=purchase)
        expense_form = SpotPurchaseExpenseForm(instance=expense)

    return render(request, 'adminapp/purchases/spot_purchase_edit.html', {
        'purchase_form': purchase_form,
        'item_formset': item_formset,
        'expense_form': expense_form,
    })

@check_permission('purchasing_view')
def spot_purchase_list(request):
    purchases = SpotPurchase.objects.all().order_by('-date')
    return render(request, 'adminapp/purchases/spot_purchase_list.html', {'purchases': purchases})

@check_permission('purchasing_delete')
def spot_purchase_delete(request, pk):
    purchase = get_object_or_404(SpotPurchase, pk=pk)
    if request.method == 'POST':
        purchase.delete()
        return redirect('adminapp:spot_purchase_list')
    return render(request, 'adminapp/purchases/spot_purchase_confirm_delete.html', {'purchase': purchase})

@check_permission('purchasing_view')
def spot_purchase_detail(request, pk):
    purchase = get_object_or_404(
        SpotPurchase.objects.select_related('expense', 'spot', 'supervisor', 'agent')
                            .prefetch_related('items'),
        pk=pk
    )
    return render(request, 'adminapp/purchases/spot_purchase_detail.html', {
        'purchase': purchase
    })


# function for LocalPurchase Entry

@check_permission('purchasing_add')
def local_purchase_create(request):
    if request.method == 'POST':
        form = LocalPurchaseForm(request.POST)
        formset = LocalPurchaseItemFormSet(request.POST, prefix='form')

        # DEBUG: Print form data to see what's being submitted
        print("POST data:", request.POST)
        print("Form is valid:", form.is_valid())
        print("Form errors:", form.errors)
        print("Formset is valid:", formset.is_valid())
        
        # Check if party_name is in POST data
        print("Party name in POST:", request.POST.get('party_name'))
        
        if form.is_valid() and formset.is_valid():
            with transaction.atomic():
                # DEBUG: Check cleaned_data before saving
                print("Form cleaned_data:", form.cleaned_data)
                
                # Create purchase instance but don't save yet
                purchase = form.save(commit=False)
                
                # DEBUG: Check if party_name is set
                print("Purchase party_name before save:", purchase.party_name)
                print("Purchase date:", purchase.date)
                print("Purchase voucher_number:", purchase.voucher_number)
                
                # Verify party_name is not None
                if not purchase.party_name:
                    print("ERROR: party_name is None!")
                    messages.error(request, "Party name is required!")
                    return render(request, 'adminapp/purchases/local_purchase_form.html', {
                        'form': form,
                        'formset': formset,
                    })
                
                # Initialize totals
                purchase.total_amount = 0
                purchase.total_quantity = 0
                purchase.total_items = 0
                
                # Save purchase first
                purchase.save()
                
                # DEBUG: Check after save
                print("Purchase ID after save:", purchase.id)
                print("Purchase party_name after save:", purchase.party_name)
                
                # Initialize totals for calculation
                total_amount = 0
                total_quantity = 0
                total_items = 0

                # Process each item in the formset
                for item_form in formset:
                    if item_form.cleaned_data and not item_form.cleaned_data.get('DELETE', False):
                        item = item_form.save(commit=False)
                        item.purchase = purchase
                        
                        # Calculate amount (quantity * rate)
                        quantity = item.quantity or 0
                        rate = item.rate or 0
                        item.amount = quantity * rate
                        item.save()
                        
                        # Add to totals
                        total_amount += item.amount
                        total_quantity += quantity
                        total_items += 1

                # Update purchase with calculated totals
                purchase.total_amount = total_amount
                purchase.total_quantity = total_quantity
                purchase.total_items = total_items
                purchase.save()

                # Success message
                messages.success(request, f'Local purchase created successfully. Total: {total_amount}')
                
                return redirect('adminapp:admin_dashboard')
        else:
            # DEBUG: Print detailed errors
            print("=== FORM ERRORS ===")
            for field, errors in form.errors.items():
                print(f"Field '{field}': {errors}")
            
            print("=== FORMSET ERRORS ===")
            for i, form_errors in enumerate(formset.errors):
                if form_errors:
                    print(f"Formset form {i} errors:", form_errors)
            
            # Add error messages to display to user
            if form.errors:
                for field, errors in form.errors.items():
                    for error in errors:
                        messages.error(request, f"{field}: {error}")

    else:
        form = LocalPurchaseForm()
        formset = LocalPurchaseItemFormSet(prefix='form')

    # DEBUG: Check if LocalParty objects exist
    from .models import LocalParty  # Adjust import path as needed
    party_count = LocalParty.objects.count()
    print(f"Number of LocalParty objects: {party_count}")
    
    if party_count == 0:
        messages.warning(request, "No parties found. Please create a party first.")

    return render(request, 'adminapp/purchases/local_purchase_form.html', {
        'form': form,
        'formset': formset,
    })

@check_permission('purchasing_view')
def local_purchase_list(request):
    purchases = LocalPurchase.objects.all().order_by('-date')
    return render(request, 'adminapp/purchases/local_purchase_list.html', {'purchases': purchases})

@check_permission('purchasing_edit')
def local_purchase_update(request, pk):
    purchase = get_object_or_404(LocalPurchase, pk=pk)
    
    if request.method == 'POST':
        form = LocalPurchaseForm(request.POST, instance=purchase)
        formset = LocalPurchaseItemFormSet(request.POST, instance=purchase, prefix='form')
        
        if form.is_valid() and formset.is_valid():
            with transaction.atomic():
                # Save the main purchase form
                purchase = form.save()
                
                # Save formset (handles creates, updates, and deletes)
                formset.save()
                
                # Recalculate totals from database to ensure accuracy
                items = LocalPurchaseItem.objects.filter(purchase=purchase)
                
                total_amount = 0
                total_quantity = 0
                total_items = items.count()
                
                for item in items:
                    # Ensure amount is calculated correctly
                    item.amount = (item.quantity or 0) * (item.rate or 0)
                    item.save()
                    
                    total_amount += item.amount
                    total_quantity += (item.quantity or 0)
                
                # Update purchase totals
                purchase.total_amount = total_amount
                purchase.total_quantity = total_quantity
                purchase.total_items = total_items
                purchase.save()
                
                messages.success(request, f'Local purchase updated successfully. Total: {total_amount}')
                return redirect('adminapp:local_purchase_list')
        else:
            # Handle errors
            if form.errors:
                for field, errors in form.errors.items():
                    for error in errors:
                        messages.error(request, f"{field}: {error}")
                        
            if formset.errors:
                for i, form_errors in enumerate(formset.errors):
                    if form_errors:
                        for field, errors in form_errors.items():
                            for error in errors:
                                messages.error(request, f"Item {i+1} - {field}: {error}")
    
    else:
        form = LocalPurchaseForm(instance=purchase)
        formset = LocalPurchaseItemFormSet(instance=purchase, prefix='form')

    return render(request, 'adminapp/purchases/local_purchase_edit.html', {
        'form': form,
        'formset': formset,
        'purchase': purchase,
    })

@check_permission('purchasing_delete')
def local_purchase_delete(request, pk):
    purchase = get_object_or_404(LocalPurchase, pk=pk)
    if request.method == 'POST':
        purchase.delete()
        return redirect('adminapp:local_purchase_list')
    return render(request, 'adminapp/purchases/local_purchase_confirm_delete.html', {'purchase': purchase})

@check_permission('purchasing_view')
def local_purchase_detail(request, pk):
    purchase = get_object_or_404(LocalPurchase, pk=pk)
    items = purchase.items.all()  # using related_name='items' from the model
    return render(request, 'adminapp/purchases/local_purchase_detail.html', {
        'purchase': purchase,
        'items': items,
        'title': f"Local Purchase Details - Voucher #{purchase.voucher_number}"
    })




# function for Both purchase Workouts
@check_permission('purchasing_view')
def spot_purchase_workout_summary(request):
    items = Item.objects.all()
    spots = PurchasingSpot.objects.all()
    agents = PurchasingAgent.objects.all()
    categories = ItemCategory.objects.all()

    queryset = SpotPurchaseItem.objects.select_related(
        "purchase", "item", "purchase__spot", "purchase__agent"
    )

    # ✅ Multi-select filters
    selected_items = request.GET.getlist("items")
    selected_spots = request.GET.getlist("spots")
    selected_agents = request.GET.getlist("agents")
    selected_categories = request.GET.getlist("categories")
    date_filter = request.GET.get("date_filter")

    # ✅ Date range filter
    start_date = request.GET.get("start_date")
    end_date = request.GET.get("end_date")

    if selected_items:
        queryset = queryset.filter(item__id__in=selected_items)
    if selected_spots:
        queryset = queryset.filter(purchase__spot__id__in=selected_spots)
    if selected_agents:
        queryset = queryset.filter(purchase__agent__id__in=selected_agents)
    if selected_categories:
        queryset = queryset.filter(item__category__id__in=selected_categories)

    # ✅ Quick date filter
    if date_filter == "week":
        queryset = queryset.filter(purchase__date__gte=now().date() - timedelta(days=7))
    elif date_filter == "month":
        queryset = queryset.filter(purchase__date__month=now().month)
    elif date_filter == "year":
        queryset = queryset.filter(purchase__date__year=now().year)

    # ✅ Custom date range
    if start_date and end_date:
        try:
            start = datetime.strptime(start_date, "%Y-%m-%d").date()
            end = datetime.strptime(end_date, "%Y-%m-%d").date()
            queryset = queryset.filter(purchase__date__range=[start, end])
        except:
            pass

    # ✅ Group & summary
    summary = (
        queryset.values(
            "item__name",
            "item__category__name",
            "purchase__spot__location_name",
            "purchase__agent__name",
            "purchase__date",
        )
        .annotate(
            total_quantity=Sum("quantity"),
            total_amount=Sum("amount"),
            avg_rate=Sum("amount") / Sum("quantity"),
        )
        .order_by("purchase__date")
    )

    return render(
        request,
        "adminapp/purchases/spot_purchase_workout_summary.html",
        {
            "summary": summary,
            "items": items,
            "spots": spots,
            "agents": agents,
            "categories": categories,
            "selected_items": selected_items,
            "selected_spots": selected_spots,
            "selected_agents": selected_agents,
            "selected_categories": selected_categories,
            "date_filter": date_filter,
            "start_date": start_date,
            "end_date": end_date,
        },
    )

@check_permission('purchasing_view')
def local_purchase_workout_summary(request):
    items = Item.objects.all()
    categories = ItemCategory.objects.all()
    species_list = Species.objects.all()
    parties = LocalPurchase.objects.values_list("party_name", flat=True).distinct()

    queryset = LocalPurchaseItem.objects.select_related(
        "purchase", "item", "item__category", "item__species"
    )

    # ✅ Multi-select filters
    selected_items = request.GET.getlist("items")
    selected_categories = request.GET.getlist("categories")
    selected_parties = request.GET.getlist("parties")
    selected_species = request.GET.getlist("species")

    # ✅ Date range filter
    start_date = request.GET.get("start_date")
    end_date = request.GET.get("end_date")

    # ✅ Quick filters (week, month, year)
    period = request.GET.get("period")

    if selected_items:
        queryset = queryset.filter(item__id__in=selected_items)

    if selected_categories:
        queryset = queryset.filter(item__category__id__in=selected_categories)

    if selected_parties:
        queryset = queryset.filter(purchase__party_name__in=selected_parties)

    if selected_species:
        queryset = queryset.filter(item__species__id__in=selected_species)

    # 📅 Date filters
    today = now().date()
    if start_date:
        queryset = queryset.filter(purchase__date__gte=start_date)
    if end_date:
        queryset = queryset.filter(purchase__date__lte=end_date)

    if period == "week":
        week_start = today - timedelta(days=today.weekday())  # Monday
        queryset = queryset.filter(purchase__date__gte=week_start)
    elif period == "month":
        queryset = queryset.filter(
            purchase__date__year=today.year, purchase__date__month=today.month
        )
    elif period == "year":
        queryset = queryset.filter(purchase__date__year=today.year)

    # ✅ Group & summary
    summary = (
        queryset.values(
            "purchase__date",
            "item__name",
            "item__category__name",
            "item__species__name",
            "purchase__party_name",
        )
        .annotate(
            total_qty=Sum("quantity"),
            total_amount=Sum("amount"),
            avg_rate=Sum("amount") / Sum("quantity"),
        )
        .order_by("purchase__date", "item__name")
    )

    return render(request, "adminapp/purchases/local_purchase_workout_summary.html", {
        "summary": summary,
        "items": items,
        "categories": categories,
        "species_list": species_list,
        "parties": parties,
        "selected_items": selected_items,
        "selected_categories": selected_categories,
        "selected_parties": selected_parties,
        "selected_species": selected_species,
        "start_date": start_date,
        "end_date": end_date,
        "period": period,
    })




# function for Peelingshed 
class PeelingShedSupplyListView(CustomPermissionMixin,ListView):
    permission_required = 'adminapp.processing_view'
    model = PeelingShedSupply
    template_name = 'adminapp/purchases/peeling_shed_supply_list.html'
    context_object_name = 'supplies'

class PeelingShedSupplyDeleteView(CustomPermissionMixin,DeleteView):
    permission_required = 'adminapp.processing_delete'
    model = PeelingShedSupply
    template_name = 'adminapp/purchases/confirm_delete.html'
    success_url = reverse_lazy('adminapp:peeling_shed_supply_list')

@check_permission('processing_add')
def create_peeling_shed_supply(request):
    if request.method == 'POST':
        form = PeelingShedSupplyForm(request.POST)
        formset = PeelingShedPeelingTypeFormSet(request.POST, prefix='form')

        if form.is_valid() and formset.is_valid():
            with transaction.atomic():
                supply = form.save()

                # Optional: calculate totals (if needed later)
                total_amount = 0

                for item_form in formset:
                    peeling_type = item_form.save(commit=False)
                    peeling_type.supply = supply
                    peeling_type.save()
                    total_amount += peeling_type.amount  # If total needed

                # Example: supply.total_amount = total_amount
                # supply.save()

                return redirect('adminapp:peeling_shed_supply_list')
        else:
            print("Form Errors:", form.errors)
            print("Formset Errors:", formset.errors)
    else:
        form = PeelingShedSupplyForm()
        formset = PeelingShedPeelingTypeFormSet(prefix='form')

    return render(request, 'adminapp/purchases/peeling_shed_supply_form.html', {
        'form': form,
        'formset': formset,
    })

@check_permission('processing_view')
def get_spot_purchases_by_date(request):
    date = request.GET.get('date')
    spot_purchases = SpotPurchase.objects.filter(date=date)

    data = [
        {
            'id': purchase.id,
            'name': f"{purchase.voucher_number} - {purchase.spot.location_name}"
        }
        for purchase in spot_purchases
    ]
    return JsonResponse(data, safe=False)

@check_permission('processing_view')
def get_spot_purchase_items(request):
    spot_purchase_id = request.GET.get('spot_purchase_id')
    items = SpotPurchaseItem.objects.filter(
        purchase_id=spot_purchase_id,
        item__is_peeling=True  # Only show items where is_peeling is True on the related item
    )

    data = [
        {
            'id': item.id,
            'name': item.item.name,
            'quantity': float(item.quantity),
        }
        for item in items
    ]
    return JsonResponse(data, safe=False)

@check_permission('processing_view')
def get_spot_purchase_item_details(request):
    item_id = request.GET.get('item_id')
    try:
        item = SpotPurchaseItem.objects.get(id=item_id)
        avg_weight = float(item.quantity) / float(item.boxes) if item.boxes else 0
        data = {
            'total_boxes': float(item.boxes or 0),
            'quantity': float(item.quantity),
            'average_weight': avg_weight
        }
    except SpotPurchaseItem.DoesNotExist:
        data = {
            'total_boxes': 0,
            'quantity': 0,
            'average_weight': 0
        }

    return JsonResponse(data)

@check_permission('processing_view')
def get_peeling_charge_by_shed(request):
    shed_id = request.GET.get('shed_id')
    data = []

    if shed_id:
        items = ShedItem.objects.filter(shed_id=shed_id)
        for i in items:
            data.append({
                'item_id': i.item.id,
                'item_name': i.item.name,
                'item_type_id': i.item_type.id if i.item_type else None,
                'item_type_name': i.item_type.name if i.item_type else '',
                'amount': float(i.amount),
                'unit': i.unit
            })
    return JsonResponse({'peeling_types': data})

@check_permission('processing_view')
def get_spot_purchase_item_details_with_balance(request):
    """
    Get spot purchase item details including available balance boxes
    considering previous peeling supplies
    """
    item_id = request.GET.get('item_id')
    try:
        item = SpotPurchaseItem.objects.get(id=item_id)
        
        # Calculate total boxes already used in previous peeling supplies
        used_boxes = PeelingShedSupply.objects.filter(
            spot_purchase_item=item
        ).aggregate(
            total_used=models.Sum('boxes_received_shed')
        )['total_used'] or 0
        
        # Calculate available balance
        total_boxes = float(item.boxes or 0)
        available_boxes = total_boxes - used_boxes
        
        # Calculate average weight
        avg_weight = float(item.quantity) / float(item.boxes) if item.boxes else 0
        
        data = {
            'total_boxes': total_boxes,
            'quantity': float(item.quantity),
            'average_weight': avg_weight,
            'used_boxes': used_boxes,
            'available_boxes': max(0, available_boxes),
            'is_fully_used': available_boxes <= 0
        }
        
    except SpotPurchaseItem.DoesNotExist:
        data = {
            'total_boxes': 0,
            'quantity': 0,
            'average_weight': 0,
            'used_boxes': 0,
            'available_boxes': 0,
            'is_fully_used': True
        }

    return JsonResponse(data)

class PeelingShedSupplyDetailView(CustomPermissionMixin,DetailView):
    permission_required = 'adminapp.processing_view'
    model = PeelingShedSupply
    template_name = 'adminapp/purchases/peeling_shed_supply_detail.html'
    context_object_name = 'supply'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['peeling_types'] = self.object.peeling_types.all()
        return context

@check_permission('processing_edit')
def update_peeling_shed_supply(request, pk):
    supply = get_object_or_404(PeelingShedSupply, pk=pk)
    
    if request.method == 'POST':
        form = PeelingShedSupplyForm(request.POST, instance=supply)
        formset = PeelingShedPeelingTypeFormSet(request.POST, instance=supply, prefix='form')

        if form.is_valid() and formset.is_valid():
            with transaction.atomic():
                # Get the spot purchase item and new boxes received
                spot_purchase_item = form.cleaned_data.get('spot_purchase_item')
                new_boxes_received = form.cleaned_data.get('boxes_received_shed', 0)
                
                if spot_purchase_item:
                    # Get total boxes from the spot purchase item
                    total_boxes = float(spot_purchase_item.boxes or 0)
                    
                    # Calculate already used boxes from database (excluding current supply)
                    used_boxes = PeelingShedSupply.objects.filter(
                        spot_purchase_item=spot_purchase_item
                    ).exclude(id=supply.id).aggregate(
                        total_used=models.Sum('boxes_received_shed')
                    )['total_used'] or 0
                    
                    # Calculate available boxes (what's left for this update)
                    available_boxes = total_boxes - used_boxes
                    
                    # Validate if new boxes received doesn't exceed available boxes
                    if new_boxes_received > available_boxes:
                        form.add_error('boxes_received_shed', 
                            f'Cannot receive {new_boxes_received} boxes. '
                            f'Already used by others: {used_boxes} boxes. '
                            f'Total available: {total_boxes} boxes. '
                            f'Maximum you can receive: {available_boxes} boxes.')
                        
                        return render(request, 'adminapp/purchases/update_peeling_shed_supply_form.html', {
                            'form': form,
                            'formset': formset,
                            'is_update': True,
                            'supply': supply,
                        })
                    
                    # Calculate balance: Available boxes - current boxes being received
                    balance_boxes = available_boxes - new_boxes_received
                    
                    # Ensure balance is not negative
                    balance_boxes = max(0, int(balance_boxes))
                    
                    # Set the calculated balance
                    form.instance.SpotPurchase_balance_boxes = balance_boxes
                
                supply = form.save()
                formset.save()
                
                messages.success(request, 
                    f'Peeling Shed Supply updated successfully. '
                    f'Boxes received: {new_boxes_received}, '
                    f'Remaining balance: {balance_boxes}')
                
            return redirect('adminapp:peeling_shed_supply_detail', pk=supply.pk)
        else:
            print("Form Errors:", form.errors)
            print("Formset Errors:", formset.errors)
    else:
        form = PeelingShedSupplyForm(instance=supply)
        formset = PeelingShedPeelingTypeFormSet(instance=supply, prefix='form')
        
        # Pre-populate the calculation fields with existing data
        if supply.spot_purchase_item:
            spot_item = supply.spot_purchase_item
            
            # Calculate available boxes for current update (excluding this supply)
            used_boxes = PeelingShedSupply.objects.filter(
                spot_purchase_item=spot_item
            ).exclude(id=supply.id).aggregate(
                total_used=models.Sum('boxes_received_shed')
            )['total_used'] or 0
            
            available_boxes = float(spot_item.boxes or 0) - used_boxes
            current_balance = max(0, available_boxes - (supply.boxes_received_shed or 0))
            
            # Set the initial form data for readonly fields
            form.initial.update({
                'SpotPurchase_total_boxes': int(spot_item.boxes or 0),
                'SpotPurchase_quantity': float(spot_item.quantity or 0),
                'SpotPurchase_average_box_weight': float(spot_item.quantity or 0) / float(spot_item.boxes or 1) if spot_item.boxes else 0,
                'SpotPurchase_balance_boxes': int(current_balance),
                'quantity_received_shed': float(supply.quantity_received_shed or 0)
            })

    return render(request, 'adminapp/purchases/update_peeling_shed_supply_form.html', {
        'form': form,
        'formset': formset,
        'is_update': True,
        'supply': supply,
    })

@check_permission('processing_edit')
def get_spot_purchase_item_details_for_update(request):
    """
    Get spot purchase item details for update form, excluding current supply from calculations
    """
    item_id = request.GET.get('item_id')
    supply_id = request.GET.get('supply_id')
    
    try:
        item = SpotPurchaseItem.objects.get(id=item_id)
        
        # Calculate total boxes already used in previous peeling supplies (excluding current supply)
        used_boxes_query = PeelingShedSupply.objects.filter(
            spot_purchase_item=item
        )
        
        # Exclude current supply from calculation if updating
        if supply_id:
            used_boxes_query = used_boxes_query.exclude(id=supply_id)
        
        used_boxes = used_boxes_query.aggregate(
            total_used=models.Sum('boxes_received_shed')
        )['total_used'] or 0
        
        # Calculate available balance
        total_boxes = float(item.boxes or 0)
        available_boxes = total_boxes - used_boxes
        
        # Calculate average weight
        avg_weight = float(item.quantity) / float(item.boxes) if item.boxes else 0
        
        data = {
            'total_boxes': total_boxes,
            'quantity': float(item.quantity),
            'average_weight': avg_weight,
            'used_boxes': used_boxes,
            'available_boxes': max(0, available_boxes),
            'is_fully_used': available_boxes <= 0
        }
        
    except SpotPurchaseItem.DoesNotExist:
        data = {
            'total_boxes': 0,
            'quantity': 0,
            'average_weight': 0,
            'used_boxes': 0,
            'available_boxes': 0,
            'is_fully_used': True
        }

    return JsonResponse(data)






# Create Freezing Entry Spot with Stock Management (FIXED)

@check_permission('freezing_add')
def create_freezing_entry_spot(request):
    if request.method == 'POST':
        form = FreezingEntrySpotForm(request.POST)
        formset = FreezingEntrySpotItemFormSet(request.POST, prefix='form')

        # Ensure shed queryset is set for each form in formset
        for f in formset.forms:
            f.fields['shed'].queryset = Shed.objects.all()

        if form.is_valid() and formset.is_valid():
            with transaction.atomic():
                # First calculate totals
                total_kg = Decimal(0)
                total_slab = Decimal(0)
                total_c_s = Decimal(0)
                total_usd = Decimal(0)
                total_inr = Decimal(0)
                yield_percentages = []
                stock_updates = []  # Store stock updates for later processing

                # Process formset and collect stock data
                for f in formset:
                    if f.cleaned_data and not f.cleaned_data.get('DELETE', False):
                        slab = f.cleaned_data.get('slab_quantity') or Decimal(0)
                        cs = f.cleaned_data.get('c_s_quantity') or Decimal(0)
                        kg = f.cleaned_data.get('kg') or Decimal(0)
                        usd = f.cleaned_data.get('usd_rate_item') or Decimal(0)
                        inr = f.cleaned_data.get('usd_rate_item_to_inr') or Decimal(0)
                        yield_percent = f.cleaned_data.get('yield_percentage')

                        # Extract data from formset for stock creation
                        store = f.cleaned_data.get('store')
                        item = f.cleaned_data.get('item')
                        item_quality = f.cleaned_data.get('item_quality')
                        unit = f.cleaned_data.get('unit')  # Keep as PackingUnit FK instance
                        glaze = f.cleaned_data.get('glaze')  # Keep as GlazePercentage FK instance
                        brand = f.cleaned_data.get('brand')
                        species = f.cleaned_data.get('species')  # Keep as Species FK instance
                        grade = f.cleaned_data.get('grade')  # Keep as ItemGrade FK instance
                        freezing_category = f.cleaned_data.get('freezing_category')
                        
                        # Extract additional fields for stock
                        usd_rate_per_kg = f.cleaned_data.get('usd_rate_per_kg') or Decimal(0)
                        usd_rate_item = f.cleaned_data.get('usd_rate_item') or Decimal(0)
                        usd_rate_item_to_inr = f.cleaned_data.get('usd_rate_item_to_inr') or Decimal(0)

                        # Store stock update data for processing after main entry is saved
                        if store and item and brand and freezing_category:
                            stock_updates.append({
                                'store': store,
                                'item': item,
                                'item_quality': item_quality,
                                'unit': unit,  # Keep as FK instance
                                'glaze': glaze,  # Keep as FK instance
                                'brand': brand,
                                'species': species,  # Keep as FK instance
                                'grade': grade,  # Keep as FK instance
                                'freezing_category': freezing_category,
                                'cs': cs,
                                'kg': kg,
                                'usd_rate_per_kg': usd_rate_per_kg,
                                'usd_rate_item': usd_rate_item,
                                'usd_rate_item_to_inr': usd_rate_item_to_inr,
                            })

                        # Calculate totals
                        total_slab += slab
                        total_c_s += cs
                        total_kg += kg
                        total_usd += usd
                        total_inr += inr
                        if yield_percent is not None:
                            yield_percentages.append(yield_percent)

                # Create and save the main freezing entry first
                freezing_entry = form.save(commit=False)
                freezing_entry.total_slab = total_slab
                freezing_entry.total_c_s = total_c_s
                freezing_entry.total_kg = total_kg
                freezing_entry.total_usd = total_usd
                freezing_entry.total_inr = total_inr
                freezing_entry.total_yield_percentage = (
                    sum(yield_percentages) / len(yield_percentages) if yield_percentages else Decimal(0)
                )
                freezing_entry.save()

                # Save formset with the saved instance
                formset.instance = freezing_entry
                formset.save()

                # Now process stock updates with the saved freezing entry
                for stock_data in stock_updates:
                    try:
                        # Prepare stock filter criteria using FK instances directly
                        stock_filters = {
                            'store': stock_data['store'],
                            'item': stock_data['item'],
                            'brand': stock_data['brand'],
                            'item_quality': stock_data['item_quality'],
                            'unit': stock_data['unit'],  # Use FK instance directly
                            'glaze': stock_data['glaze'],  # Use FK instance directly
                            'species': stock_data['species'],  # Use FK instance directly
                            'item_grade': stock_data['grade'],  # Use FK instance directly (note: item_grade not grade)
                            'freezing_category': stock_data['freezing_category'],
                        }
                        
                        # Remove None values to avoid issues
                        stock_filters = {k: v for k, v in stock_filters.items() if v is not None}

                        # Try to find existing stock with same characteristics
                        existing_stock = Stock.objects.filter(**stock_filters).first()
                        
                        if existing_stock:
                            # Update existing stock
                            existing_stock.cs_quantity += stock_data['cs']
                            existing_stock.kg_quantity += stock_data['kg']
                            existing_stock.usd_rate_per_kg = stock_data['usd_rate_per_kg']
                            existing_stock.usd_rate_item = stock_data['usd_rate_item']
                            existing_stock.usd_rate_item_to_inr = stock_data['usd_rate_item_to_inr']
                            existing_stock.save()
                            
                            print(f"Stock updated: {existing_stock}")
                            
                        else:
                            # Create new stock entry - REMOVED 'category' field
                            new_stock_data = {
                                **stock_filters,
                                'cs_quantity': stock_data['cs'],
                                'kg_quantity': stock_data['kg'],
                                'usd_rate_per_kg': stock_data['usd_rate_per_kg'],
                                'usd_rate_item': stock_data['usd_rate_item'],
                                'usd_rate_item_to_inr': stock_data['usd_rate_item_to_inr'],
                            }
                            
                            stock = Stock.objects.create(**new_stock_data)
                            print(f"Stock created: {stock}")

                    except Exception as e:
                        print(f"Error creating/updating stock: {e}")
                        messages.error(request, f"Error updating stock for {stock_data['item'].name}: {str(e)}")
                        # Continue processing other items instead of failing completely

            messages.success(request, 'Freezing entry created successfully!')
            return redirect('adminapp:freezing_entry_spot_list')
        else:
            print("Form Errors:", form.errors)
            print("Formset Errors:", formset.errors)
            messages.error(request, 'Please correct the errors below.')
    else:
        form = FreezingEntrySpotForm()
        form.fields['spot_agent'].queryset = PurchasingAgent.objects.none()
        form.fields['spot_supervisor'].queryset = PurchasingSupervisor.objects.none()
        formset = FreezingEntrySpotItemFormSet(prefix='form')

    return render(request, 'adminapp/freezing/freezing_entry_spot_create.html', {
        'form': form,
        'formset': formset,
    })

@check_permission('freezing_view')
def freezing_entry_spot_list(request):
    entries = FreezingEntrySpot.objects.all()
    return render(request, 'adminapp/freezing/freezing_entry_spot_list.html', {'entries': entries})

class FreezingEntrySpotDetailView(CustomPermissionMixin,View):
    permission_required = 'adminapp.freezing_view'
    template_name = "adminapp/freezing/freezing_entry_spot_detail.html"

    def get(self, request, pk):
        entry = get_object_or_404(FreezingEntrySpot, pk=pk)
        items = entry.items.select_related(
            "shed", "item", "unit", "glaze",
            "freezing_category", "brand", "species",
            "peeling_type", "grade"
        )

        context = {
            "entry": entry,
            "items": items,
        }
        return render(request, self.template_name, context)

@check_permission('freezing_edit')
def freezing_entry_spot_update(request, pk):
    freezing_entry = get_object_or_404(FreezingEntrySpot, pk=pk)

    if request.method == "POST":
        form = FreezingEntrySpotForm(request.POST, instance=freezing_entry)
        formset = FreezingEntrySpotItemFormSet(
            request.POST, instance=freezing_entry, prefix="form"
        )

        # Ensure shed queryset is set for each form in formset
        for f in formset.forms:
            f.fields["shed"].queryset = Shed.objects.all()

        if form.is_valid() and formset.is_valid():
            with transaction.atomic():
                entry = form.save(commit=False)

                # First, reverse all stock changes from this specific entry
                reverse_stock_changes_for_spot_entry(freezing_entry)

                # Initialize totals
                total_kg = Decimal(0)
                total_slab = Decimal(0)
                total_c_s = Decimal(0)
                total_usd = Decimal(0)
                total_inr = Decimal(0)
                yield_percentages = []
                stock_updates = []  # Store stock updates for later processing

                # Process formset and create new stock entries
                for f in formset:
                    if f.cleaned_data and not f.cleaned_data.get("DELETE", False):
                        slab = f.cleaned_data.get("slab_quantity") or Decimal(0)
                        cs = f.cleaned_data.get("c_s_quantity") or Decimal(0)
                        kg = f.cleaned_data.get("kg") or Decimal(0)
                        usd = f.cleaned_data.get("usd_rate_item") or Decimal(0)
                        inr = f.cleaned_data.get("usd_rate_item_to_inr") or Decimal(0)
                        yield_percent = f.cleaned_data.get("yield_percentage")

                        # Extract data from formset for stock updates
                        store = f.cleaned_data.get('store')
                        item = f.cleaned_data.get('item')
                        item_quality = f.cleaned_data.get('item_quality')
                        unit = f.cleaned_data.get('unit')  # Keep as PackingUnit FK instance
                        glaze = f.cleaned_data.get('glaze')  # Keep as GlazePercentage FK instance
                        brand = f.cleaned_data.get('brand')
                        species = f.cleaned_data.get('species')  # Keep as Species FK instance
                        grade = f.cleaned_data.get('grade')  # Keep as ItemGrade FK instance
                        freezing_category = f.cleaned_data.get('freezing_category')
                        
                        # Extract additional fields for stock
                        usd_rate_per_kg = f.cleaned_data.get('usd_rate_per_kg') or Decimal(0)
                        usd_rate_item = f.cleaned_data.get('usd_rate_item') or Decimal(0)
                        usd_rate_item_to_inr = f.cleaned_data.get('usd_rate_item_to_inr') or Decimal(0)

                        # Store stock update data for processing
                        if store and item and brand and freezing_category:
                            stock_updates.append({
                                'store': store,
                                'item': item,
                                'item_quality': item_quality,
                                'unit': unit,  # Keep as FK instance
                                'glaze': glaze,  # Keep as FK instance
                                'brand': brand,
                                'species': species,  # Keep as FK instance
                                'grade': grade,  # Keep as FK instance
                                'freezing_category': freezing_category,
                                'cs': cs,
                                'kg': kg,
                                'usd_rate_per_kg': usd_rate_per_kg,
                                'usd_rate_item': usd_rate_item,
                                'usd_rate_item_to_inr': usd_rate_item_to_inr,
                            })

                        # Calculate totals
                        total_slab += slab
                        total_c_s += cs
                        total_kg += kg
                        total_usd += usd
                        total_inr += inr
                        if yield_percent is not None:
                            yield_percentages.append(yield_percent)

                # Assign recalculated totals
                entry.total_slab = total_slab
                entry.total_c_s = total_c_s
                entry.total_kg = total_kg
                entry.total_usd = total_usd
                entry.total_inr = total_inr
                entry.total_yield_percentage = (
                    sum(yield_percentages) / len(yield_percentages) if yield_percentages else Decimal(0)
                )

                entry.save()
                formset.instance = entry
                formset.save()

                # Now process stock updates with the saved entry
                for stock_data in stock_updates:
                    try:
                        # Prepare stock filter criteria using FK instances directly
                        stock_filters = {
                            'store': stock_data['store'],
                            'item': stock_data['item'],
                            'brand': stock_data['brand'],
                            'item_quality': stock_data['item_quality'],
                            'unit': stock_data['unit'],  # Use FK instance directly
                            'glaze': stock_data['glaze'],  # Use FK instance directly
                            'species': stock_data['species'],  # Use FK instance directly
                            'item_grade': stock_data['grade'],  # Use FK instance directly (note: item_grade not grade)
                            'freezing_category': stock_data['freezing_category'],
                        }
                        
                        # Remove None values
                        stock_filters = {k: v for k, v in stock_filters.items() if v is not None}

                        # Try to find existing stock with same characteristics
                        existing_stock = Stock.objects.filter(**stock_filters).first()
                        
                        if existing_stock:
                            # Update existing stock
                            existing_stock.cs_quantity += stock_data['cs']
                            existing_stock.kg_quantity += stock_data['kg']
                            existing_stock.usd_rate_per_kg = stock_data['usd_rate_per_kg']
                            existing_stock.usd_rate_item = stock_data['usd_rate_item']
                            existing_stock.usd_rate_item_to_inr = stock_data['usd_rate_item_to_inr']
                            existing_stock.save()
                            
                            print(f"Stock updated: {existing_stock}")
                            
                        else:
                            # Create new stock entry - REMOVED 'category' field
                            new_stock_data = {
                                **stock_filters,
                                'cs_quantity': stock_data['cs'],
                                'kg_quantity': stock_data['kg'],
                                'usd_rate_per_kg': stock_data['usd_rate_per_kg'],
                                'usd_rate_item': stock_data['usd_rate_item'],
                                'usd_rate_item_to_inr': stock_data['usd_rate_item_to_inr'],
                            }
                            
                            stock = Stock.objects.create(**new_stock_data)
                            print(f"Stock created: {stock}")

                    except Exception as e:
                        print(f"Error creating/updating stock: {e}")
                        messages.error(request, f"Error updating stock for {stock_data['item'].name}: {str(e)}")
                        # Continue processing other items instead of failing completely

            messages.success(request, 'Freezing entry updated successfully!')
            return redirect("adminapp:freezing_entry_spot_list")
        else:
            print("Form Errors:", form.errors)
            print("Formset Errors:", formset.errors)
            messages.error(request, 'Please correct the errors below.')

    else:
        form = FreezingEntrySpotForm(instance=freezing_entry)
        # preload dependent dropdowns
        form.fields["spot_agent"].queryset = PurchasingAgent.objects.all()
        form.fields["spot_supervisor"].queryset = PurchasingSupervisor.objects.all()
        formset = FreezingEntrySpotItemFormSet(
            instance=freezing_entry, prefix="form"
        )

    return render(
        request,
        "adminapp/freezing/freezing_entry_spot_update.html",
        {"form": form, "formset": formset, "entry": freezing_entry},
    )

@check_permission('freezing_delete')
def delete_freezing_entry_spot(request, pk):
    entry = get_object_or_404(FreezingEntrySpot, pk=pk)
    
    if request.method == 'POST':
        try:
            with transaction.atomic():
                # Subtract quantities from stock entries (don't delete entire stock records)
                delete_stock_entries_for_spot_entry(entry)
                
                # Then delete the entry
                entry.delete()
                
                messages.success(request, 'Freezing entry deleted and stock quantities updated successfully!')
                
        except Exception as e:
            print(f"Error deleting freezing entry: {e}")
            messages.error(request, f'Error deleting entry: {str(e)}')
            
        return redirect('adminapp:freezing_entry_spot_list')
    
    return render(request, 'adminapp/confirm_delete.html', {'entry': entry})


def get_spots_by_date(request):
    date = request.GET.get('date')
    spots = SpotPurchase.objects.filter(date=date).values('id', 'spot__location_name' , 'voucher_number')
    return JsonResponse({'spots': list(spots)})

def get_spot_details(request):
    spot_id = request.GET.get('spot_id')

    try:
        spot = SpotPurchase.objects.select_related('agent', 'supervisor').get(id=spot_id)

        # ✅ Fetch all related items for this spot purchase
        items = SpotPurchaseItem.objects.filter(purchase=spot).select_related("item")

        items_data = [
            {
                "id": item.item.id,
                "name": item.item.name,
                "quantity": str(item.quantity),  # ensure JSON serializable
            }
            for item in items
        ]

        data = {
            "agent_id": spot.agent.id,
            "agent_name": str(spot.agent),  # e.g. "John - AG001"
            "supervisor_id": spot.supervisor.id,
            "supervisor_name": str(spot.supervisor),  # e.g. "Anita - 9876543210"
            "items": items_data,  # ✅ added items list
        }

        # Debug print for terminal
        print("Spot Purchase Details:", data)

        return JsonResponse(data)

    except SpotPurchase.DoesNotExist:
        return JsonResponse({"error": "SpotPurchase not found"}, status=404)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

def get_sheds_by_date(request):
    date_str = request.GET.get('date')  # Spot Purchase Date
    if not date_str:
        return JsonResponse({'error': 'Missing date'}, status=400)

    # Convert string to Python date
    try:
        date_obj = datetime.strptime(date_str, "%Y-%m-%d").date()
    except ValueError:
        return JsonResponse({'error': 'Invalid date format'}, status=400)

    # Fetch supplies for that spot purchase date
    supplies = PeelingShedSupply.objects.filter(
        spot_purchase__date=date_obj
    ).select_related('shed', 'spot_purchase_item__item')

    seen_pairs = set()
    result = []

    for supply in supplies:
        shed = supply.shed
        item = supply.spot_purchase_item.item
        key = (shed.id, item.id)

        if key not in seen_pairs:
            seen_pairs.add(key)

            # Yield calculation example
            try:
                total_qty = supply.spot_purchase_item.quantity  # adjust field name
                qty_received = supply.quantity_received_shed
                yield_percent = (qty_received / total_qty) * 100 if total_qty else 0
            except:
                yield_percent = 0

            result.append({
                'shed_id': shed.id,
                'shed_name': str(shed),
                'item_id': item.id,
                'item_name': str(item),
                'boxes_received_shed': supply.boxes_received_shed,
                'quantity_received_shed': str(supply.quantity_received_shed),
                'yield_percent': round(yield_percent, 2)
            })

    return JsonResponse({'sheds': result})

def get_unit_details(request):
    unit_id = request.GET.get('unit_id')
    try:
        unit = PackingUnit.objects.get(pk=unit_id)
        return JsonResponse({
            'precision': float(unit.precision),
            'factor': float(unit.factor)
        })
    except PackingUnit.DoesNotExist:
        return JsonResponse({'error': 'Unit not found'}, status=404)

def get_dollar_rate(request):
    settings_obj = Settings.objects.filter(is_active=True).order_by('-created_at').first()
    if settings_obj:
        return JsonResponse({
            'dollar_rate_to_inr': float(settings_obj.dollar_rate_to_inr)
        })
    return JsonResponse({'error': 'Settings not found'}, status=404)

def get_spot_purchase_items_by_date(request):
    date = request.GET.get("date")
    if not date:
        return JsonResponse({"error": "Missing date"}, status=400)

    items = SpotPurchaseItem.objects.filter(
        purchase__date=date
    ).select_related("item")

    data = []
    for item in items:
        # ✅ print to terminal
        print(f"Item: {item.item.name}, Quantity: {item.quantity}")

        data.append({
            "id": item.id,
            "name": str(item.item),
            "quantity": str(item.quantity),
        })

    return JsonResponse({"items": data})

def reverse_stock_changes_for_spot_entry(freezing_entry):
    """
    Helper function to reverse stock changes for a specific freezing entry
    """
    try:
        # Get all items from this freezing entry
        items = freezing_entry.items.all()
        
        for item in items:
            # Build stock filter criteria using FK instances directly
            stock_filters = {
                'store': item.store,
                'item': item.item,
                'brand': item.brand,
                'item_quality': item.item_quality,
                'unit': item.unit,  # Use FK instance directly
                'glaze': item.glaze,  # Use FK instance directly
                'species': item.species,  # Use FK instance directly
                'item_grade': item.grade,  # Use FK instance directly (note: item_grade not grade)
                'freezing_category': item.freezing_category,
            }
            
            # Remove None values
            stock_filters = {k: v for k, v in stock_filters.items() if v is not None}
            
            # Find and update stock
            try:
                # Find all matching stocks (there might be multiple)
                matching_stocks = Stock.objects.filter(**stock_filters)
                
                for stock in matching_stocks:
                    # Subtract the quantities (reverse the addition)
                    stock.cs_quantity -= (item.c_s_quantity or Decimal(0))
                    stock.kg_quantity -= (item.kg or Decimal(0))
                    
                    # If both quantities become zero or negative, delete the stock entry
                    if stock.cs_quantity <= 0 and stock.kg_quantity <= 0:
                        print(f"Deleting empty stock entry: {stock}")
                        stock.delete()
                    else:
                        # Ensure quantities don't go negative
                        stock.cs_quantity = max(stock.cs_quantity, Decimal(0))
                        stock.kg_quantity = max(stock.kg_quantity, Decimal(0))
                        stock.save()
                        print(f"Reversed stock quantities: {stock}")
                    
            except Exception as e:
                print(f"Error during stock reversal for item {item.item.name}: {e}")
                
    except Exception as e:
        print(f"Error reversing stock changes: {e}")

def delete_stock_entries_for_spot_entry(freezing_entry):
    """
    Helper function to subtract quantities from stock entries (not delete the entire stock record)
    """
    try:
        # Get all items from this freezing entry and subtract their quantities from matching stock entries
        items = freezing_entry.items.all()
        
        for item in items:
            # Build stock filter criteria using FK instances directly
            stock_filters = {
                'store': item.store,
                'item': item.item,
                'brand': item.brand,
                'item_quality': item.item_quality,
                'unit': item.unit,  # Use FK instance directly
                'glaze': item.glaze,  # Use FK instance directly
                'species': item.species,  # Use FK instance directly
                'item_grade': item.grade,  # Use FK instance directly (note: item_grade not grade)
                'freezing_category': item.freezing_category,
            }
            
            # Remove None values
            stock_filters = {k: v for k, v in stock_filters.items() if v is not None}
            
            # Find matching stock entries and subtract quantities
            try:
                matching_stocks = Stock.objects.filter(**stock_filters)
                
                for stock in matching_stocks:
                    # Subtract the quantities from this freezing entry item
                    stock.cs_quantity -= (item.c_s_quantity or Decimal(0))
                    stock.kg_quantity -= (item.kg or Decimal(0))
                    
                    # If quantities become zero or negative, delete the stock record
                    if stock.cs_quantity <= 0 and stock.kg_quantity <= 0:
                        print(f"Deleting empty stock record: {stock}")
                        stock.delete()
                    else:
                        # Ensure quantities don't go negative and save
                        stock.cs_quantity = max(stock.cs_quantity, Decimal(0))
                        stock.kg_quantity = max(stock.kg_quantity, Decimal(0))
                        print(f"Updated stock quantities for {item.item.name}: CS={stock.cs_quantity}, KG={stock.kg_quantity}")
                        stock.save()
                    
            except Exception as e:
                print(f"Error updating stock for item {item.item.name}: {e}")
                
    except Exception as e:
        print(f"Error updating stock entries: {e}")
        raise e



# Create Freezing Entry Local with Stock Management

@check_permission('freezing_add')
def create_freezing_entry_local(request):
    if request.method == 'POST':
        form = FreezingEntryLocalForm(request.POST)
        formset = FreezingEntryLocalItemFormSet(request.POST, prefix='form')

        if form.is_valid() and formset.is_valid():
            with transaction.atomic():
                # First calculate totals
                total_kg = Decimal(0)
                total_slab = Decimal(0)
                total_c_s = Decimal(0)
                total_usd = Decimal(0)
                total_inr = Decimal(0)
                stock_updates = []  # Store stock updates for later processing

                # Get Dollar Rate
                dollar_rate_to_inr = Decimal(0)
                try:
                    from .models import DollarRate
                    dollar_obj = DollarRate.objects.latest("id")
                    dollar_rate_to_inr = dollar_obj.rate
                except:
                    pass

                # Process formset and collect stock data
                for f in formset.forms:
                    if f.cleaned_data and not f.cleaned_data.get('DELETE', False):
                        slab = f.cleaned_data.get('slab_quantity') or Decimal(0)
                        cs = f.cleaned_data.get('c_s_quantity') or Decimal(0)
                        kg = f.cleaned_data.get('kg') or Decimal(0)
                        usd_rate_per_kg = f.cleaned_data.get('usd_rate_per_kg') or Decimal(0)

                        # Calculate USD and INR amounts
                        usd_item = kg * usd_rate_per_kg
                        inr_item = usd_item * dollar_rate_to_inr

                        # Extract data from formset for stock creation
                        store = f.cleaned_data.get('store')
                        item = f.cleaned_data.get('item')
                        item_quality = f.cleaned_data.get('item_quality')
                        unit = f.cleaned_data.get('unit')  # Keep as PackingUnit FK instance
                        glaze = f.cleaned_data.get('glaze')  # Keep as GlazePercentage FK instance
                        brand = f.cleaned_data.get('brand')
                        species = f.cleaned_data.get('species')  # Keep as Species FK instance
                        grade = f.cleaned_data.get('grade')  # Keep as ItemGrade FK instance
                        freezing_category = f.cleaned_data.get('freezing_category')  # Keep as FreezingCategory FK instance

                        # Store stock update data for processing after main entry is saved
                        if store and item and brand:
                            stock_updates.append({
                                'store': store,
                                'item': item,
                                'item_quality': item_quality,
                                'unit': unit,  # Keep as FK instance
                                'glaze': glaze,  # Keep as FK instance
                                'brand': brand,
                                'species': species,  # Keep as FK instance
                                'grade': grade,  # Keep as FK instance
                                'freezing_category': freezing_category,  # Keep as FK instance
                                'cs': cs,
                                'kg': kg,
                                'usd_item': usd_item,
                                'inr_item': inr_item,
                                'usd_rate_per_kg': usd_rate_per_kg,
                            })

                        # Calculate totals
                        total_slab += slab
                        total_c_s += cs
                        total_kg += kg
                        total_usd += usd_item
                        total_inr += inr_item

                # Create and save the main freezing entry first
                freezing_entry = form.save(commit=False)
                freezing_entry.created_by = request.user
                freezing_entry.total_slab = total_slab
                freezing_entry.total_c_s = total_c_s
                freezing_entry.total_kg = total_kg
                freezing_entry.total_usd = total_usd
                freezing_entry.total_inr = total_inr
                freezing_entry.save()

                # Save formset with calculations
                for f in formset.forms:
                    if f.cleaned_data and not f.cleaned_data.get("DELETE", False):
                        item = f.save(commit=False)
                        item.freezing_entry = freezing_entry

                        # Auto-calc fields
                        kg = f.cleaned_data.get("kg") or Decimal(0)
                        usd_rate_per_kg = f.cleaned_data.get("usd_rate_per_kg") or Decimal(0)

                        usd_item = kg * usd_rate_per_kg
                        inr_item = usd_item * dollar_rate_to_inr

                        item.usd_rate_item = usd_item
                        item.usd_rate_item_to_inr = inr_item
                        item.save()

                # Now process stock updates with the saved freezing entry
                for stock_data in stock_updates:
                    try:
                        # Prepare stock filter criteria using FK instances directly (like in spot function)
                        stock_filters = {
                            'store': stock_data['store'],
                            'item': stock_data['item'],
                            'brand': stock_data['brand'],
                            'item_quality': stock_data['item_quality'],
                            'unit': stock_data['unit'],  # Use FK instance directly
                            'glaze': stock_data['glaze'],  # Use FK instance directly
                            'species': stock_data['species'],  # Use FK instance directly
                            'item_grade': stock_data['grade'],  # Use FK instance directly (note: item_grade not grade)
                            'freezing_category': stock_data['freezing_category'],  # Use FK instance directly
                        }
                        
                        # Remove None values to avoid issues
                        stock_filters = {k: v for k, v in stock_filters.items() if v is not None}

                        # Try to find existing stock with same characteristics
                        existing_stock = Stock.objects.filter(**stock_filters).first()
                        
                        if existing_stock:
                            # Update existing stock
                            existing_stock.cs_quantity += stock_data['cs']
                            existing_stock.kg_quantity += stock_data['kg']
                            existing_stock.usd_rate_per_kg = stock_data['usd_rate_per_kg']
                            existing_stock.usd_rate_item = stock_data['usd_item']
                            existing_stock.usd_rate_item_to_inr = stock_data['inr_item']
                            existing_stock.save()
                            
                            print(f"Stock updated: {existing_stock}")
                            
                        else:
                            # Create new stock entry (removed non-existent fields)
                            new_stock_data = {
                                **stock_filters,
                                'cs_quantity': stock_data['cs'],
                                'kg_quantity': stock_data['kg'],
                                'usd_rate_per_kg': stock_data['usd_rate_per_kg'],
                                'usd_rate_item': stock_data['usd_item'],
                                'usd_rate_item_to_inr': stock_data['inr_item'],
                            }
                            
                            stock = Stock.objects.create(**new_stock_data)
                            print(f"Stock created: {stock}")

                    except Exception as e:
                        print(f"Error creating/updating stock: {e}")
                        messages.error(request, f"Error updating stock for {stock_data['item'].name}: {str(e)}")
                        # Continue processing other items instead of failing completely

                messages.success(request, "Freezing Entry created successfully ✅")
                return redirect("adminapp:freezing_entry_local_list")

        else:
            print("Form Errors:", form.errors)
            print("Formset Errors:", [f.errors for f in formset.forms])
    else:
        form = FreezingEntryLocalForm()
        formset = FreezingEntryLocalItemFormSet(prefix='form')

    return render(request, "adminapp/freezing/freezing_entry_local_create.html", {
        "form": form,
        "formset": formset,
    })

@check_permission('freezing_view')
def freezing_entry_local_list(request):
    entries = FreezingEntryLocal.objects.all()
    return render(request, 'adminapp/freezing/freezing_entry_local_list.html', {'entries': entries})

@check_permission('freezing_view')
def freezing_entry_local_detail(request, pk):
    entry = get_object_or_404(FreezingEntryLocal, pk=pk)
    items = entry.items.all().select_related(
        'processing_center',
        'store',
        'item',
        'unit',
        'glaze',
        'freezing_category',
        'brand',
        'species',
        'peeling_type',
        'grade'
    )

    context = {
        'entry': entry,
        'items': items
    }
    return render(request, 'adminapp/freezing/freezing_entry_local_detail.html', context)

@check_permission('freezing_delete')
def delete_freezing_entry_local(request, pk):
    entry = get_object_or_404(FreezingEntryLocal, pk=pk)
    
    if request.method == 'POST':
        try:
            with transaction.atomic():
                # Delete all stock entries associated with this freezing entry
                delete_stock_entries_for_local_entry(entry)
                
                # Then delete the entry
                entry.delete()
                
                messages.success(request, 'Local freezing entry and associated stock deleted successfully!')
                
        except Exception as e:
            print(f"Error deleting local freezing entry: {e}")
            messages.error(request, f'Error deleting entry: {str(e)}')
            
        return redirect('adminapp:freezing_entry_local_list')
    
    return render(request, 'adminapp/freezing/freezing_entry_local_confirm_delete.html', {'entry': entry})

@check_permission('freezing_edit')
def freezing_entry_local_update(request, pk):
    freezing_entry = get_object_or_404(FreezingEntryLocal, pk=pk)
    FreezingEntryLocalItemFormSet = inlineformset_factory(
        FreezingEntryLocal,
        FreezingEntryLocalItem,
        form=FreezingEntryLocalItemForm,
        extra=0,
        can_delete=True
    )
    
    if request.method == "POST":
        form = FreezingEntryLocalForm(request.POST, instance=freezing_entry)
        formset = FreezingEntryLocalItemFormSet(
            request.POST, instance=freezing_entry, prefix="form"
        )
        
        if form.is_valid() and formset.is_valid():
            with transaction.atomic():
                # First, reverse all stock changes from this specific entry
                reverse_stock_changes_for_local_entry(freezing_entry)

                # Initialize totals (matching create function)
                total_kg = Decimal('0')
                total_slab = Decimal('0')
                total_c_s = Decimal('0')
                total_usd = Decimal('0')
                total_inr = Decimal('0')
                stock_updates = []

                # Get Dollar Rate (matching create function)
                dollar_rate_to_inr = Decimal('0')
                try:
                    from .models import DollarRate
                    dollar_obj = DollarRate.objects.latest("id")
                    dollar_rate_to_inr = Decimal(str(dollar_obj.rate))
                    print(f"Dollar rate retrieved: {dollar_rate_to_inr}")
                except Exception as e:
                    print(f"Error getting dollar rate: {e}")
                    pass

                # Save formset to get access to deleted_objects
                instances = formset.save(commit=False)
                
                # Handle deletions
                for obj in formset.deleted_objects:
                    obj.delete()

                # Process formset and collect stock data (matching create function logic)
                for f in formset.forms:
                    if f.cleaned_data and not f.cleaned_data.get('DELETE', False):
                        # Get values directly from cleaned_data (like create function)
                        slab = f.cleaned_data.get('slab_quantity') or Decimal('0')
                        cs = f.cleaned_data.get('c_s_quantity') or Decimal('0')
                        kg = f.cleaned_data.get('kg') or Decimal('0')
                        usd_rate_per_kg = f.cleaned_data.get('usd_rate_per_kg') or Decimal('0')

                        # Calculate USD and INR amounts (matching create function)
                        usd_item = kg * usd_rate_per_kg
                        inr_item = usd_item * dollar_rate_to_inr

                        # Extract data from formset for stock creation (matching create function)
                        store = f.cleaned_data.get('store')
                        item = f.cleaned_data.get('item')
                        item_quality = f.cleaned_data.get('item_quality')
                        unit = f.cleaned_data.get('unit')
                        glaze = f.cleaned_data.get('glaze')
                        brand = f.cleaned_data.get('brand')
                        species = f.cleaned_data.get('species')
                        grade = f.cleaned_data.get('grade')
                        freezing_category = f.cleaned_data.get('freezing_category')

                        # Store stock update data for processing after main entry is saved
                        if store and item and brand:
                            stock_updates.append({
                                'store': store,
                                'item': item,
                                'item_quality': item_quality,
                                'unit': unit,
                                'glaze': glaze,
                                'brand': brand,
                                'species': species,
                                'grade': grade,
                                'freezing_category': freezing_category,
                                'cs': cs,
                                'kg': kg,
                                'usd_item': usd_item,
                                'inr_item': inr_item,
                                'usd_rate_per_kg': usd_rate_per_kg,
                                'form_instance': f,
                                'calculated_values': {
                                    'usd_rate_item': usd_item,
                                    'usd_rate_item_to_inr': inr_item,
                                }
                            })

                        # Calculate totals (matching create function)
                        total_slab += slab
                        total_c_s += cs
                        total_kg += kg
                        total_usd += usd_item
                        total_inr += inr_item

                        print(f"Processing form: slab={slab}, cs={cs}, kg={kg}, usd={usd_item}, inr={inr_item}")

                # Update the main freezing entry with totals (like create function)
                entry = form.save(commit=False)
                entry.total_slab = total_slab
                entry.total_c_s = total_c_s
                entry.total_kg = total_kg
                entry.total_usd = total_usd
                entry.total_inr = total_inr
                entry.save()

                # Save formset instances with calculated values (matching create function)
                for instance in instances:
                    # Find the corresponding calculated values
                    for stock_update in stock_updates:
                        if stock_update['form_instance'].instance == instance:
                            calc_vals = stock_update['calculated_values']
                            instance.usd_rate_item = calc_vals['usd_rate_item']
                            instance.usd_rate_item_to_inr = calc_vals['usd_rate_item_to_inr']
                            break
                    
                    instance.freezing_entry = freezing_entry
                    instance.save()

                # Now process stock updates (matching create function logic)
                for stock_data in stock_updates:
                    try:
                        # Prepare stock filter criteria using FK instances directly
                        stock_filters = {
                            'store': stock_data['store'],
                            'item': stock_data['item'],
                            'brand': stock_data['brand'],
                            'item_quality': stock_data['item_quality'],
                            'unit': stock_data['unit'],
                            'glaze': stock_data['glaze'],
                            'species': stock_data['species'],
                            'item_grade': stock_data['grade'],  # Note: item_grade not grade
                            'freezing_category': stock_data['freezing_category'],
                        }
                        
                        # Remove None values
                        stock_filters = {k: v for k, v in stock_filters.items() if v is not None}

                        # Try to find existing stock with same characteristics
                        existing_stock = Stock.objects.filter(**stock_filters).first()
                        
                        if existing_stock:
                            # Update existing stock (matching create function)
                            existing_stock.cs_quantity += stock_data['cs']
                            existing_stock.kg_quantity += stock_data['kg']
                            existing_stock.usd_rate_per_kg = stock_data['usd_rate_per_kg']
                            existing_stock.usd_rate_item = stock_data['usd_item']
                            existing_stock.usd_rate_item_to_inr = stock_data['inr_item']
                            existing_stock.save()
                            
                            print(f"Stock updated: {existing_stock}")
                            
                        else:
                            # Create new stock entry (matching create function)
                            new_stock_data = {
                                **stock_filters,
                                'cs_quantity': stock_data['cs'],
                                'kg_quantity': stock_data['kg'],
                                'usd_rate_per_kg': stock_data['usd_rate_per_kg'],
                                'usd_rate_item': stock_data['usd_item'],
                                'usd_rate_item_to_inr': stock_data['inr_item'],
                            }
                            
                            stock = Stock.objects.create(**new_stock_data)
                            print(f"Stock created: {stock}")

                    except Exception as e:
                        print(f"Error creating/updating stock: {e}")
                        messages.error(request, f"Error updating stock for {stock_data['item'].name}: {str(e)}")
                        # Continue processing other items instead of failing completely

                # Debug output for final totals
                print(f"Final totals - Slab: {total_slab}, C/S: {total_c_s}, KG: {total_kg}, USD: {total_usd}, INR: {total_inr}")

                messages.success(request, "Freezing Entry updated successfully ✅")
                return redirect("adminapp:freezing_entry_local_list")
        else:
            print("Form Errors:", form.errors)
            print("Formset Errors:", [f.errors for f in formset.forms if f.errors])
            print("Formset Non Form Errors:", formset.non_form_errors())
    else:
        form = FreezingEntryLocalForm(instance=freezing_entry)
        formset = FreezingEntryLocalItemFormSet(
            instance=freezing_entry, prefix="form"
        )
        
    return render(
        request,
        "adminapp/freezing/freezing_entry_local_update.html",
        {"form": form, "formset": formset, "entry": freezing_entry},
    )



def get_parties_by_date(request):
    date = request.GET.get('date')
    if not date:
        return JsonResponse({'error': 'Date parameter is required'}, status=400)
    
    purchases = LocalPurchase.objects.select_related('party_name').filter(date=date)
    
    parties = []
    for purchase in purchases:
        parties.append({
            'id': purchase.id,
            'party_name': purchase.party_name.party,
            'voucher_number': purchase.voucher_number
        })
    
    return JsonResponse({'parties': parties})

def get_party_details(request):
    party_id = request.GET.get('party_id')
    try:
        purchase = LocalPurchase.objects.get(id=party_id)

        # assuming LocalPurchaseItem has FK → ItemGrade as `grade`
        items = purchase.items.all().values(
            'id',
            'item__id',
            'item__name',
            'quantity',
            'rate',
            'amount',
            'grade__id',
            'grade__grade',             # grade text
            'grade__species__name',     # ✅ species name
            'item_quality__quality',   # ✅ correct field
            'item_quality__code',      
        )

        data = {
            'party_name': purchase.party_name,
            'voucher_number': purchase.voucher_number,
            'items': list(items),
        }
        return JsonResponse(data)

    except LocalPurchase.DoesNotExist:
        return JsonResponse({'error': 'LocalPurchase not found'}, status=404)

def get_unit_details_local(request):
    unit_id = request.GET.get('unit_id')
    try:
        unit = PackingUnit.objects.get(pk=unit_id)
        return JsonResponse({
            'precision': float(unit.precision),
            'factor': float(unit.factor)
        })
    except PackingUnit.DoesNotExist:
        return JsonResponse({'error': 'Unit not found'}, status=404)

def get_dollar_rate_local(request):
    settings_obj = Settings.objects.filter(is_active=True).order_by('-created_at').first()
    if settings_obj:
        return JsonResponse({
            'dollar_rate_to_inr': float(settings_obj.dollar_rate_to_inr)
        })
    return JsonResponse({'error': 'Settings not found'}, status=404)

def get_items_by_local_date(request):
    date = request.GET.get('date')
    if not date:
        return JsonResponse({'items': []})
    
    # Adjust this query based on your LocalPurchase model structure
    items = LocalPurchaseItem.objects.filter(
        local_purchase__purchase_date=date
    ).select_related('item').values(
        'item_id', 
        'item__name'
    ).annotate(
        item_name=F('item__name')
    ).distinct()
    
    return JsonResponse({'items': list(items)})


@require_http_methods(["GET"])
@csrf_exempt  # Remove this if CSRF protection is needed
def get_item_qualities(request):
    item_id = request.GET.get("item_id")
    
    # If item_id is missing, return empty JSON array
    if not item_id:
        return JsonResponse([], safe=False)
    
    # Validate item_id is not empty (allow alphanumeric IDs)
    item_id = item_id.strip()
    if not item_id:
        return JsonResponse({"error": "Invalid item_id"}, status=400)

    try:
        # Filter qualities for the given item
        qualities = ItemQuality.objects.filter(item_id=item_id).values("id", "quality")
        
        # Return as JSON
        return JsonResponse(list(qualities), safe=False)
    
    except Exception as e:
        # Handle any database errors
        return JsonResponse({"error": "Database error occurred"}, status=500)

def delete_stock_entries_for_local_entry(freezing_entry):
    """
    Helper function to subtract quantities from stock entries (not delete the entire stock record)
    """
    try:
        # Get all items from this freezing entry and subtract their quantities from matching stock entries
        items = freezing_entry.items.all()
        
        for item in items:
            # Build stock filter criteria using Stock model fields
            stock_filters = {
                'store': item.store,
                'item': item.item,
                'brand': item.brand,
                'item_quality': item.item_quality,
                'unit': item.unit,  # Keep as FK instance
                'glaze': item.glaze,  # Keep as FK instance
                'species': item.species,  # Keep as FK instance
                'item_grade': item.grade,  # Use item_grade field name
                'freezing_category': item.freezing_category,  # Keep as FK instance
            }
            
            # Remove None values
            stock_filters = {k: v for k, v in stock_filters.items() if v is not None}
            
            # Find matching stock entries and subtract quantities
            try:
                matching_stocks = Stock.objects.filter(**stock_filters)
                
                for stock in matching_stocks:
                    # Subtract the quantities from this freezing entry item
                    stock.cs_quantity -= (item.c_s_quantity or Decimal(0))
                    stock.kg_quantity -= (item.kg or Decimal(0))
                    
                    # If quantities become zero or negative, delete the stock record
                    if stock.cs_quantity <= 0 and stock.kg_quantity <= 0:
                        print(f"Deleting empty stock record: {stock}")
                        stock.delete()
                    else:
                        # Save the updated quantities
                        print(f"Updated stock quantities for {item.item.name}: CS={stock.cs_quantity}, KG={stock.kg_quantity}")
                        stock.save()
                    
            except Exception as e:
                print(f"Error updating stock for item {item.item.name}: {e}")
                
    except Exception as e:
        print(f"Error updating stock entries: {e}")
        raise e

def reverse_stock_changes_for_local_entry(freezing_entry):
    """
    Improved stock reversal function that handles multiple stock records properly
    """
    try:
        # Get all items from the freezing entry to reverse their quantities
        entry_items = FreezingEntryLocalItem.objects.filter(freezing_entry=freezing_entry)
        
        for entry_item in entry_items:
            try:
                # Build filter criteria to find the exact stock record using FK instances
                stock_filters = {
                    'store': entry_item.store,
                    'item': entry_item.item,
                    'brand': entry_item.brand,
                    'item_quality': entry_item.item_quality,
                    'unit': entry_item.unit,  # Keep as FK instance
                    'glaze': entry_item.glaze,  # Keep as FK instance
                    'species': entry_item.species,  # Keep as FK instance
                    'item_grade': entry_item.grade,  # Use item_grade field name
                    'freezing_category': entry_item.freezing_category,  # Keep as FK instance
                }
                
                # Remove None values
                stock_filters = {k: v for k, v in stock_filters.items() if v is not None}
                
                # Find all matching stock records
                matching_stocks = Stock.objects.filter(**stock_filters)
                
                print(f"Found {matching_stocks.count()} matching stock records for item {entry_item.item.name}")
                
                for stock in matching_stocks:
                    # Reverse the quantities
                    stock.cs_quantity -= (entry_item.c_s_quantity or Decimal(0))
                    stock.kg_quantity -= (entry_item.kg or Decimal(0))
                    
                    # If quantities become zero or negative, delete the stock record
                    if stock.cs_quantity <= 0 and stock.kg_quantity <= 0:
                        print(f"Deleting stock record: {stock}")
                        stock.delete()
                    else:
                        print(f"Updating stock quantities: CS={stock.cs_quantity}, KG={stock.kg_quantity}")
                        stock.save()
                        
            except Exception as e:
                print(f"Error reversing stock for item {entry_item.item.name}: {e}")
                continue
                
    except Exception as e:
        print(f"Error during stock reversal: {e}")
        # Don't raise the exception, just log it and continue


# function for Both Freezing Workouts
class FreezingWorkOutView(CustomPermissionMixin,View):
    permission_required = 'adminapp.freezing_view'
    template_name = "adminapp/freezing/freezing_workout.html"

    def get_summary(self, queryset, has_yield=True):
        """
        Build aggregated summary for a given queryset.
        `has_yield` flag is used because Spot has yield_percentage but Local does not.
        """
        qs = (
            queryset
            .select_related(
                'item', 'grade', 'species', 'peeling_type', 'brand',
                'glaze', 'unit', 'freezing_category'
            )
            .values(
                'item__name',
                'grade__grade',
                'species__name',
                'peeling_type__name',
                'brand__name',
                'glaze__percentage',
                'unit__unit_code',
                'freezing_category__name',
            )
        )

        annotations = {
            'total_slab': Coalesce(Sum('slab_quantity'), V(0), output_field=DecimalField()),
            'total_c_s': Coalesce(Sum('c_s_quantity'), V(0), output_field=DecimalField()),
            'total_kg': Coalesce(Sum('kg'), V(0), output_field=DecimalField()),
            'total_usd': Coalesce(Sum('usd_rate_item'), V(0), output_field=DecimalField()),
            'total_inr': Coalesce(Sum('usd_rate_item_to_inr'), V(0), output_field=DecimalField()),
        }

        if has_yield:
            annotations.update({
                'total_yield_sum': Coalesce(Sum('yield_percentage'), V(0), output_field=DecimalField()),
                'count_yield': Count('id'),
            })

        return qs.annotate(**annotations).order_by(
            'item__name', 'grade__grade', 'species__name',
            'peeling_type__name', 'brand__name'
        )

    def get(self, request):
        # Spot has yield, Local does not
        spot_summary = self.get_summary(FreezingEntrySpotItem.objects.all(), has_yield=True)
        local_summary = self.get_summary(FreezingEntryLocalItem.objects.all(), has_yield=False)

        # Merge spot + local summaries
        combined_data = {}
        for dataset, has_yield in [(spot_summary, True), (local_summary, False)]:
            for row in dataset:
                key = (
                    row['item__name'],
                    row['grade__grade'],
                    row['species__name'],
                    row['peeling_type__name'],
                    row['brand__name'],
                    str(row['glaze__percentage']),
                    row['unit__unit_code'],
                    row['freezing_category__name'],
                )

                if key not in combined_data:
                    combined_data[key] = {
                        'item_name': row['item__name'],
                        'grade_name': row['grade__grade'],
                        'species_name': row['species__name'],
                        'peeling_type_name': row['peeling_type__name'],
                        'brand_name': row['brand__name'],
                        'glaze_percentage': row['glaze__percentage'],
                        'unit_code': row['unit__unit_code'],
                        'freezing_category_name': row['freezing_category__name'],
                        'total_slab': Decimal(0),
                        'total_c_s': Decimal(0),
                        'total_kg': Decimal(0),
                        'total_usd': Decimal(0),
                        'total_inr': Decimal(0),
                        'total_yield_sum': Decimal(0),
                        'count_yield': 0,
                    }

                combined_data[key]['total_slab'] += row['total_slab']
                combined_data[key]['total_c_s'] += row['total_c_s']
                combined_data[key]['total_kg'] += row['total_kg']
                combined_data[key]['total_usd'] += row['total_usd']
                combined_data[key]['total_inr'] += row['total_inr']

                # Only Spot rows have yield
                if has_yield:
                    combined_data[key]['total_yield_sum'] += row['total_yield_sum']
                    combined_data[key]['count_yield'] += row['count_yield']

        # Compute avg yield %
        for val in combined_data.values():
            if val['count_yield'] > 0:
                val['avg_yield'] = val['total_yield_sum'] / val['count_yield']
            else:
                val['avg_yield'] = Decimal(0)

        context = {
            'spot_summary': spot_summary,
            'local_summary': local_summary,
            'combined_summary': list(combined_data.values()),
        }
        return render(request, self.template_name, context)




# PRE SHIPMENT WORK OUT 
class PreShipmentWorkOutCreateAndSummaryView(CustomPermissionMixin,View):
    permission_required = 'adminapp.shipping_view'
    template_name = "adminapp/create_preshipment_workout.html"

    def get_summary(self, queryset):
        """Aggregate summary data for freezing items."""
        return (
            queryset
            .select_related(
                'item', 'grade', 'species', 'peeling_type', 'brand',
                'glaze', 'unit', 'freezing_category'
            )
            .values(
                'item__name',
                'grade__grade',
                'species__name',
                'peeling_type__name',
                'brand__name',
                'glaze__percentage',
                'unit__unit_code',
                'freezing_category__name',
            )
            .annotate(
                total_slab=Coalesce(Sum('slab_quantity'), V(0), output_field=DecimalField()),
                total_c_s=Coalesce(Sum('c_s_quantity'), V(0), output_field=DecimalField()),
                total_kg=Coalesce(Sum('kg'), V(0), output_field=DecimalField()),
                # Removed yield_percentage related calculations as the field doesn't exist
                count_records=Count('id'),
                total_usd=Coalesce(Sum('usd_rate_item'), V(0), output_field=DecimalField()),
                total_inr=Coalesce(Sum('usd_rate_item_to_inr'), V(0), output_field=DecimalField()),
                avg_usd_per_kg=Coalesce(Avg('usd_rate_per_kg'), V(0), output_field=DecimalField()),
            )
            .order_by('item__name', 'grade__grade', 'species__name')
        )

    def get_combined_summary(self, filters):
        """Combine spot and local summaries."""
        spot_summary = self.get_summary(FreezingEntrySpotItem.objects.filter(**filters))
        local_summary = self.get_summary(FreezingEntryLocalItem.objects.filter(**filters))

        combined_data = {}
        for dataset in [spot_summary, local_summary]:
            for row in dataset:
                key = (
                    row['item__name'],
                    row['grade__grade'],
                    row['species__name'],
                    row['peeling_type__name'],
                    row['brand__name'],
                    str(row['glaze__percentage']),
                    row['unit__unit_code'],
                    row['freezing_category__name'],
                )
                if key not in combined_data:
                    combined_data[key] = {
                        'item_name': row['item__name'],
                        'grade_name': row['grade__grade'],
                        'species_name': row['species__name'],
                        'peeling_type_name': row['peeling_type__name'],
                        'brand_name': row['brand__name'],
                        'glaze_percentage': row['glaze__percentage'],
                        'unit_code': row['unit__unit_code'],
                        'freezing_category_name': row['freezing_category__name'],
                        'total_slab': Decimal(0),
                        'total_c_s': Decimal(0),
                        'total_kg': Decimal(0),
                        'count_records': 0,
                        'total_usd': Decimal(0),
                        'total_inr': Decimal(0),
                        'avg_usd_per_kg_sum': Decimal(0),
                        'avg_usd_per_kg_count': 0,
                    }
                combined_data[key]['avg_usd_per_kg_sum'] += row['avg_usd_per_kg']
                combined_data[key]['avg_usd_per_kg_count'] += 1
                combined_data[key]['total_slab'] += row['total_slab']
                combined_data[key]['total_c_s'] += row['total_c_s']
                combined_data[key]['total_kg'] += row['total_kg']
                combined_data[key]['total_usd'] += row['total_usd']
                combined_data[key]['total_inr'] += row['total_inr']
                combined_data[key]['count_records'] += row['count_records']

        for val in combined_data.values():
            # Removed avg_yield calculation as yield_percentage field doesn't exist
            
            if val['avg_usd_per_kg_count'] > 0:
                val['avg_usd_per_kg'] = val['avg_usd_per_kg_sum'] / val['avg_usd_per_kg_count']
            else:
                val['avg_usd_per_kg'] = Decimal(0)

        return list(combined_data.values())
    
    def get(self, request):
        filters = {}
        if request.GET.get("item"):
            filters["item_id"] = request.GET["item"]
        if request.GET.get("unit"):
            filters["unit_id"] = request.GET["unit"]
        if request.GET.get("glaze"):
            filters["glaze_id"] = request.GET["glaze"]
        if request.GET.get("category"):
            filters["freezing_category_id"] = request.GET["category"]
        if request.GET.get("brand"):
            filters["brand_id"] = request.GET["brand"]

        workout_form = PreShipmentWorkOutForm()
        formset = PreShipmentWorkOutItemFormSet(prefix="items", instance=PreShipmentWorkOut())

        context = {
            "workout_form": workout_form,
            "formset": formset,
            "combined_summary": self.get_combined_summary(filters),
            "items": Item.objects.all(),
            "units": PackingUnit.objects.all(),
            "glazes": GlazePercentage.objects.all(),
            "categories": FreezingCategory.objects.all(),
            "brands": ItemBrand.objects.all(),
            "request": request
        }
        return render(request, self.template_name, context)

    def post(self, request):
        filters = {}
        if request.GET.get("item"):
            filters["item_id"] = request.GET["item"]
        if request.GET.get("unit"):
            filters["unit_id"] = request.GET["unit"]
        if request.GET.get("glaze"):
            filters["glaze_id"] = request.GET["glaze"]
        if request.GET.get("category"):
            filters["freezing_category_id"] = request.GET["category"]
        if request.GET.get("brand"):
            filters["brand_id"] = request.GET["brand"]

        workout_form = PreShipmentWorkOutForm(request.POST)

        if workout_form.is_valid():
            workout = workout_form.save(commit=False)
            formset = PreShipmentWorkOutItemFormSet(request.POST, prefix="items", instance=workout)

            # ✅ Dynamically adjust species & peeling_type choices for validation
            selected_item = workout_form.cleaned_data.get("item")
            if selected_item:
                for f in formset.forms:
                    f.fields["species"].queryset = Species.objects.filter(item=selected_item)
                    f.fields["peeling_type"].queryset = ItemType.objects.filter(item=selected_item)

            if formset.is_valid():
                try:
                    with transaction.atomic():
                        workout.save()
                        # ✅ Backend profit/loss calculation
                        for f in formset:
                            obj = f.save(commit=False)
                            buy_inr = obj.usd_rate_item_to_inr or Decimal(0)
                            sell_inr = obj.usd_rate_item_to_inr_get or Decimal(0)
                            diff = sell_inr - buy_inr
                            if diff >= 0:
                                obj.profit = diff
                                obj.loss = Decimal(0)
                            else:
                                obj.profit = Decimal(0)
                                obj.loss = abs(diff)
                            obj.save()
                    messages.success(request, "Pre-Shipment WorkOut created successfully.")
                    return redirect(request.path)
                except Exception as e:
                    messages.error(request, f"Error saving data: {e}")
            else:
                print("Formset errors:", formset.errors)  # DEBUG
                messages.error(request, "Please correct the item form errors below.")
        else:
            print("Workout form errors:", workout_form.errors)  # DEBUG
            formset = PreShipmentWorkOutItemFormSet(request.POST, prefix="items", instance=PreShipmentWorkOut())
            messages.error(request, "Please correct the workout form errors below.")

        context = {
            "workout_form": workout_form,
            "formset": formset,
            "combined_summary": self.get_combined_summary(filters),
            "items": Item.objects.all(),
            "units": PackingUnit.objects.all(),
            "glazes": GlazePercentage.objects.all(),
            "categories": FreezingCategory.objects.all(),
            "brands": ItemBrand.objects.all(),
            "request": request
        }
        return render(request, self.template_name, context)

class PreShipmentWorkOutListView(CustomPermissionMixin,ListView):
    permission_required = 'adminapp.shipping_view'
    model = PreShipmentWorkOut
    template_name = "adminapp/preshipment_workout_list.html"
    context_object_name = "workouts"
    paginate_by = 20  # Optional: pagination

    def get_queryset(self):
        queryset = super().get_queryset().select_related()
        # Optional filtering
        if self.request.GET.get("item"):
            queryset = queryset.filter(item_id=self.request.GET["item"])
        return queryset.order_by("-id")  # Latest first

class PreShipmentWorkOutDeleteView(CustomPermissionMixin,DeleteView):
    permission_required = 'adminapp.shipping_delete'
    model = PreShipmentWorkOut
    template_name = "adminapp/confirm_delete.html"
    success_url = reverse_lazy("adminapp:preshipment_workout_list")

    def delete(self, request, *args, **kwargs):
        obj = self.get_object()
        messages.success(request, f"Pre-Shipment WorkOut '{obj}' deleted successfully.")
        return super().delete(request, *args, **kwargs)

class PreShipmentWorkOutDetailView(CustomPermissionMixin,DetailView):
    permission_required = 'adminapp.shipping_view'
    model = PreShipmentWorkOut
    template_name = "adminapp/detail_preshipment_workout.html"
    context_object_name = "workout"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # All related items
        items_qs = PreShipmentWorkOutItem.objects.filter(workout=self.object)

        # Summary calculation
        summary = items_qs.aggregate(
            total_cartons=Coalesce(Sum("cartons"), Decimal(0), output_field=DecimalField()),
            total_quantity=Coalesce(Sum("quantity"), Decimal(0), output_field=DecimalField()),
            total_usd_rate_item=Coalesce(Sum("usd_rate_item"), Decimal(0), output_field=DecimalField()),
            total_usd_rate_item_get=Coalesce(Sum("usd_rate_item_get"), Decimal(0), output_field=DecimalField()),
            total_usd_inr=Coalesce(Sum("usd_rate_item_to_inr"), Decimal(0), output_field=DecimalField()),
            total_usd_inr_get=Coalesce(Sum("usd_rate_item_to_inr_get"), Decimal(0), output_field=DecimalField()),
            avg_usd_per_kg=Coalesce(Avg("usd_rate_per_kg"), Decimal(0), output_field=DecimalField()),
            avg_usd_per_kg_get=Coalesce(Avg("usd_rate_per_kg_get"), Decimal(0), output_field=DecimalField()),
            total_profit=Coalesce(Sum("profit"), Decimal(0), output_field=DecimalField()),
            total_loss=Coalesce(Sum("loss"), Decimal(0), output_field=DecimalField()),
            item_count=Count("id")
        )

        context.update({
            "items": items_qs,
            "summary": summary
        })
        return context



def get_species_for_item(request):
    item_id = request.GET.get("item_id")
    species_list = []

    if item_id:
        species_qs = Species.objects.filter(item_id=item_id)
        species_list = list(species_qs.values("id", "name"))

    return JsonResponse({"species": species_list})

def get_peeling_for_item(request):
    item_id = request.GET.get("item_id")
    peeling_list = []

    if item_id:
        peeling_qs = ItemType.objects.filter(item_id=item_id)
        peeling_list = list(peeling_qs.values("id", "name"))

    return JsonResponse({"peeling_types": peeling_list})

def get_grade_for_species(request):
    species_id = request.GET.get("species_id")
    grade_list = []

    if species_id:
        grade_qs = ItemGrade.objects.filter(species_id=species_id)
        grade_list = list(grade_qs.values("id", "grade"))

    return JsonResponse({"grades": grade_list})

def get_dollar_rate_pre_workout(request):
    """Return the current dollar to INR rate for Pre-Shipment WorkOut."""
    settings_obj = Settings.objects.filter(is_active=True).order_by('-created_at').first()
    if settings_obj:
        return JsonResponse({
            'dollar_rate_to_inr': float(settings_obj.dollar_rate_to_inr)
        })
    return JsonResponse({'error': 'Settings not found'}, status=404)


# SPOT PURCHASE REPORT - FIXED VERSION
@check_permission('reports_view')
def spot_purchase_report(request):
    items = Item.objects.all()
    spots = PurchasingSpot.objects.all()
    agents = PurchasingAgent.objects.all()
    categories = ItemCategory.objects.all()

    queryset = SpotPurchaseItem.objects.select_related(
        "purchase", "item", "purchase__spot", "purchase__agent"
    )

    # ✅ Multi-select filters
    selected_items = request.GET.getlist("items")
    selected_spots = request.GET.getlist("spots")
    selected_agents = request.GET.getlist("agents")
    selected_categories = request.GET.getlist("categories")
    date_filter = request.GET.get("date_filter")

    # ✅ Date range filter
    start_date = request.GET.get("start_date")
    end_date = request.GET.get("end_date")

    if selected_items:
        queryset = queryset.filter(item__id__in=selected_items)
    if selected_spots:
        queryset = queryset.filter(purchase__spot__id__in=selected_spots)
    if selected_agents:
        queryset = queryset.filter(purchase__agent__id__in=selected_agents)
    if selected_categories:
        queryset = queryset.filter(item__category__id__in=selected_categories)

    # ✅ Quick date filter
    if date_filter == "week":
        queryset = queryset.filter(purchase__date__gte=now().date() - timedelta(days=7))
    elif date_filter == "month":
        queryset = queryset.filter(purchase__date__month=now().month)
    elif date_filter == "year":
        queryset = queryset.filter(purchase__date__year=now().year)

    # ✅ Custom date range
    if start_date and end_date:
        try:
            start = datetime.strptime(start_date, "%Y-%m-%d").date()
            end = datetime.strptime(end_date, "%Y-%m-%d").date()
            queryset = queryset.filter(purchase__date__range=[start, end])
        except:
            pass

    # ✅ Group & summary
    summary = (
        queryset.values(
            "item__name",
            "item__category__name",
            "purchase__spot__location_name",
            "purchase__agent__name",
            "purchase__date",
        )
        .annotate(
            total_quantity=Sum("quantity"),
            total_amount=Sum("amount"),
            avg_rate=Sum(F("amount"), output_field=FloatField()) / Sum(F("quantity"), output_field=FloatField()),
        )
        .order_by("purchase__date")
    )

    # ✅ Check if print/export requested
    action = request.GET.get("action")
    print_mode = request.GET.get("print")  # Check for print parameter

    # Handle print request
    if action == "print" or print_mode == "1":
        return render(
            request,
            "adminapp/report/spot_purchase_report_print.html",
            {"summary": summary, "start_date": start_date, "end_date": end_date},
        )

    if action == "csv":
        response = HttpResponse(content_type="text/csv")
        response["Content-Disposition"] = 'attachment; filename="spot_purchase_report.csv"'
        writer = csv.writer(response)
        writer.writerow(["Date", "Item", "Category", "Spot", "Agent", "Quantity", "Amount", "Avg Rate"])
        for row in summary:
            writer.writerow([
                row["purchase__date"],
                row["item__name"],
                row["item__category__name"],
                row["purchase__spot__location_name"],
                row["purchase__agent__name"],
                row["total_quantity"],
                row["total_amount"],
                round(row["avg_rate"], 2) if row["avg_rate"] else 0,
            ])
        return response

    if action == "excel":
        output = io.BytesIO()
        workbook = xlsxwriter.Workbook(output, {"in_memory": True})
        worksheet = workbook.add_worksheet("Report")

        headers = ["Date", "Item", "Category", "Spot", "Agent", "Quantity", "Amount", "Avg Rate"]
        for col, header in enumerate(headers):
            worksheet.write(0, col, header)

        for row_idx, row in enumerate(summary, start=1):
            worksheet.write(row_idx, 0, str(row["purchase__date"]))
            worksheet.write(row_idx, 1, row["item__name"])
            worksheet.write(row_idx, 2, row["item__category__name"])
            worksheet.write(row_idx, 3, row["purchase__spot__location_name"])
            worksheet.write(row_idx, 4, row["purchase__agent__name"])
            worksheet.write(row_idx, 5, row["total_quantity"])
            worksheet.write(row_idx, 6, row["total_amount"])
            worksheet.write(row_idx, 7, round(row["avg_rate"], 2) if row["avg_rate"] else 0)

        workbook.close()
        output.seek(0)

        response = HttpResponse(output.read(), content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        response["Content-Disposition"] = 'attachment; filename="spot_purchase_report.xlsx"'
        return response

    return render(
        request,
        "adminapp/report/spot_purchase_report.html",
        {
            "summary": summary,
            "items": items,
            "spots": spots,
            "agents": agents,
            "categories": categories,
            "selected_items": selected_items,
            "selected_spots": selected_spots,
            "selected_agents": selected_agents,
            "selected_categories": selected_categories,
            "date_filter": date_filter,
            "start_date": start_date,
            "end_date": end_date,
        },
    )

@check_permission('reports_export')
def spot_purchase_report_print(request):
    """Separate view specifically for print format"""
    items = Item.objects.all()
    spots = PurchasingSpot.objects.all()
    agents = PurchasingAgent.objects.all()
    categories = ItemCategory.objects.all()

    queryset = SpotPurchaseItem.objects.select_related(
        "purchase", "item", "purchase__spot", "purchase__agent"
    )

    # Apply the same filters as main view
    selected_items = request.GET.getlist("items")
    selected_spots = request.GET.getlist("spots")
    selected_agents = request.GET.getlist("agents")
    selected_categories = request.GET.getlist("categories")
    date_filter = request.GET.get("date_filter")
    start_date = request.GET.get("start_date")
    end_date = request.GET.get("end_date")

    if selected_items:
        queryset = queryset.filter(item__id__in=selected_items)
    if selected_spots:
        queryset = queryset.filter(purchase__spot__id__in=selected_spots)
    if selected_agents:
        queryset = queryset.filter(purchase__agent__id__in=selected_agents)
    if selected_categories:
        queryset = queryset.filter(item__category__id__in=selected_categories)

    if date_filter == "week":
        queryset = queryset.filter(purchase__date__gte=now().date() - timedelta(days=7))
    elif date_filter == "month":
        queryset = queryset.filter(purchase__date__month=now().month)
    elif date_filter == "year":
        queryset = queryset.filter(purchase__date__year=now().year)

    if start_date and end_date:
        try:
            start = datetime.strptime(start_date, "%Y-%m-%d").date()
            end = datetime.strptime(end_date, "%Y-%m-%d").date()
            queryset = queryset.filter(purchase__date__range=[start, end])
        except:
            pass

    summary = (
        queryset.values(
            "item__name",
            "item__category__name",
            "purchase__spot__location_name",
            "purchase__agent__name",
            "purchase__date",
        )
        .annotate(
            total_quantity=Sum("quantity"),
            total_amount=Sum("amount"),
            avg_rate=Sum(F("amount"), output_field=FloatField()) / Sum(F("quantity"), output_field=FloatField()),
        )
        .order_by("purchase__date")
    )

    return render(
        request,
        "adminapp/report/spot_purchase_report_print.html",
        {
            "summary": summary,
            "start_date": start_date,
            "end_date": end_date,
            "selected_items": selected_items,
            "selected_spots": selected_spots,
            "selected_agents": selected_agents,
            "selected_categories": selected_categories,
        },
    )



# LOCAL PURCHASE REPORT - FIXED VERSION
@check_permission('report_view')
def local_purchase_report(request):
    # ✅ Only get items, grades, categories, and species that exist in LocalPurchaseItem
    items = Item.objects.filter(
        id__in=LocalPurchaseItem.objects.values_list('item_id', flat=True).distinct()
    ).distinct()
    
    grades = ItemGrade.objects.filter(
        id__in=LocalPurchaseItem.objects.values_list('grade_id', flat=True).distinct()
    ).distinct()
    
    categories = ItemCategory.objects.filter(
        id__in=LocalPurchaseItem.objects.values_list('item__category_id', flat=True).distinct()
    ).distinct()
    
    species = Species.objects.filter(
        id__in=LocalPurchaseItem.objects.values_list('species_id', flat=True).distinct()
    ).distinct()

    queryset = LocalPurchaseItem.objects.select_related(
        "purchase", "item", "grade", "item__category", "species", "purchase__party_name"  # ✅ Added party_name relation
    )

    # ✅ Multi-select filters
    selected_items = request.GET.getlist("items")
    selected_grades = request.GET.getlist("grades")
    selected_categories = request.GET.getlist("categories")
    selected_parties = request.GET.getlist("parties")
    selected_species = request.GET.getlist("species")
    date_filter = request.GET.get("date_filter")

    # ✅ Date range filter
    start_date = request.GET.get("start_date")
    end_date = request.GET.get("end_date")

    # ✅ Party name filter (text search)
    party_search = request.GET.get("party_search", "").strip()

    if selected_items:
        queryset = queryset.filter(item__id__in=selected_items)
    if selected_grades:
        queryset = queryset.filter(grade__id__in=selected_grades)
    if selected_categories:
        queryset = queryset.filter(item__category__id__in=selected_categories)
    if selected_species:
        queryset = queryset.filter(species__id__in=selected_species)
    if selected_parties:  # ✅ Fixed party filter
        queryset = queryset.filter(purchase__party_name__id__in=selected_parties)
    if party_search:  # ✅ Fixed party search
        queryset = queryset.filter(purchase__party_name__party__icontains=party_search)

    # ✅ Quick date filter
    if date_filter == "week":
        queryset = queryset.filter(purchase__date__gte=now().date() - timedelta(days=7))
    elif date_filter == "month":
        queryset = queryset.filter(purchase__date__month=now().month)
    elif date_filter == "year":
        queryset = queryset.filter(purchase__date__year=now().year)

    # ✅ Custom date range
    if start_date and end_date:
        try:
            start = datetime.strptime(start_date, "%Y-%m-%d").date()
            end = datetime.strptime(end_date, "%Y-%m-%d").date()
            queryset = queryset.filter(purchase__date__range=[start, end])
        except:
            pass

    # ✅ Group & summary - FIXED party access
    summary = (
        queryset.values(
            "item__name",
            "item__category__name",
            "species__name",
            "grade__grade",
            "purchase__party_name__party",  # ✅ FIXED: Access the party field
            "purchase__party_name__district",  # ✅ Also get district
            "purchase__party_name__state",     # ✅ Also get state
            "purchase__voucher_number",
            "purchase__date",
        )
        .annotate(
            total_quantity=Sum("quantity"),
            total_amount=Sum("amount"),
            avg_rate=Sum(F("amount"), output_field=FloatField()) / Sum(F("quantity"), output_field=FloatField()),
        )
        .order_by("purchase__date")
    )

    # ✅ Get unique parties for filter dropdown - FIXED
    parties = LocalParty.objects.filter(
        id__in=LocalPurchase.objects.values_list('party_name_id', flat=True).distinct()
    ).distinct().order_by('party')

    # ✅ Check if print/export requested
    action = request.GET.get("action")
    print_mode = request.GET.get("print")

    # Handle print request
    if action == "print" or print_mode == "1":
        return render(
            request,
            "adminapp/report/local_purchase_report_print.html",
            {
                "summary": summary, 
                "start_date": start_date, 
                "end_date": end_date
            },
        )

    if action == "csv":
        response = HttpResponse(content_type="text/csv")
        response["Content-Disposition"] = 'attachment; filename="local_purchase_report.csv"'
        writer = csv.writer(response)
        writer.writerow(["Date", "Voucher No", "Party", "District", "State", "Item", "Grade", "Category", "Species", "Quantity", "Amount", "Avg Rate"])
        for row in summary:
            writer.writerow([
                row["purchase__date"],
                row["purchase__voucher_number"],
                row["purchase__party_name__party"],  # ✅ FIXED
                row["purchase__party_name__district"] or "N/A",  # ✅ NEW
                row["purchase__party_name__state"] or "N/A",     # ✅ NEW
                row["item__name"],
                row["grade__grade"] or "N/A",
                row["item__category__name"],
                row["species__name"] or "N/A",
                row["total_quantity"],
                row["total_amount"],
                round(row["avg_rate"], 2) if row["avg_rate"] else 0,
            ])
        return response

    if action == "excel":
        output = io.BytesIO()
        workbook = xlsxwriter.Workbook(output, {"in_memory": True})
        worksheet = workbook.add_worksheet("Report")

        headers = ["Date", "Voucher No", "Party", "District", "State", "Item", "Grade", "Category", "Species", "Quantity", "Amount", "Avg Rate"]
        for col, header in enumerate(headers):
            worksheet.write(0, col, header)

        for row_idx, row in enumerate(summary, start=1):
            worksheet.write(row_idx, 0, str(row["purchase__date"]))
            worksheet.write(row_idx, 1, row["purchase__voucher_number"])
            worksheet.write(row_idx, 2, row["purchase__party_name__party"])  # ✅ FIXED
            worksheet.write(row_idx, 3, row["purchase__party_name__district"] or "N/A")  # ✅ NEW
            worksheet.write(row_idx, 4, row["purchase__party_name__state"] or "N/A")     # ✅ NEW
            worksheet.write(row_idx, 5, row["item__name"])
            worksheet.write(row_idx, 6, row["grade__grade"] or "N/A")
            worksheet.write(row_idx, 7, row["item__category__name"])
            worksheet.write(row_idx, 8, row["species__name"] or "N/A")
            worksheet.write(row_idx, 9, row["total_quantity"])
            worksheet.write(row_idx, 10, row["total_amount"])
            worksheet.write(row_idx, 11, round(row["avg_rate"], 2) if row["avg_rate"] else 0)

        workbook.close()
        output.seek(0)

        response = HttpResponse(output.read(), content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        response["Content-Disposition"] = 'attachment; filename="local_purchase_report.xlsx"'
        return response

    return render(
        request,
        "adminapp/report/local_purchase_report.html",
        {
            "summary": summary,
            "items": items,
            "grades": grades,
            "categories": categories,
            "species": species,
            "parties": parties,
            "selected_items": selected_items,
            "selected_grades": selected_grades,
            "selected_categories": selected_categories,
            "selected_species": selected_species,
            "selected_parties": selected_parties,  # ✅ Added this
            "date_filter": date_filter,
            "start_date": start_date,
            "end_date": end_date,
            "party_search": party_search,
        },
    )

@check_permission('report_export')
def local_purchase_report_print(request):
    """Separate view specifically for print format"""
    # ✅ Only get data that exists in LocalPurchaseItem
    items = Item.objects.filter(
        id__in=LocalPurchaseItem.objects.values_list('item_id', flat=True).distinct()
    ).distinct()
    
    grades = ItemGrade.objects.filter(
        id__in=LocalPurchaseItem.objects.values_list('grade_id', flat=True).distinct()
    ).distinct()
    
    categories = ItemCategory.objects.filter(
        id__in=LocalPurchaseItem.objects.values_list('item__category_id', flat=True).distinct()
    ).distinct()
    
    species = Species.objects.filter(
        id__in=LocalPurchaseItem.objects.values_list('species_id', flat=True).distinct()
    ).distinct()

    queryset = LocalPurchaseItem.objects.select_related(
        "purchase", "item", "grade", "item__category", "species", "purchase__party_name"  # ✅ Added party_name relation
    )

    # Apply the same filters as main view
    selected_items = request.GET.getlist("items")
    selected_grades = request.GET.getlist("grades")
    selected_categories = request.GET.getlist("categories")
    selected_parties = request.GET.getlist("parties")  # ✅ Added this
    selected_species = request.GET.getlist("species")
    date_filter = request.GET.get("date_filter")
    start_date = request.GET.get("start_date")
    end_date = request.GET.get("end_date")
    party_search = request.GET.get("party_search", "").strip()

    if selected_items:
        queryset = queryset.filter(item__id__in=selected_items)
    if selected_grades:
        queryset = queryset.filter(grade__id__in=selected_grades)
    if selected_categories:
        queryset = queryset.filter(item__category__id__in=selected_categories)
    if selected_species:
        queryset = queryset.filter(species__id__in=selected_species)
    if selected_parties:  # ✅ Fixed party filter
        queryset = queryset.filter(purchase__party_name__id__in=selected_parties)
    if party_search:  # ✅ Fixed party search
        queryset = queryset.filter(purchase__party_name__party__icontains=party_search)

    if date_filter == "week":
        queryset = queryset.filter(purchase__date__gte=now().date() - timedelta(days=7))
    elif date_filter == "month":
        queryset = queryset.filter(purchase__date__month=now().month)
    elif date_filter == "year":
        queryset = queryset.filter(purchase__date__year=now().year)

    if start_date and end_date:
        try:
            start = datetime.strptime(start_date, "%Y-%m-%d").date()
            end = datetime.strptime(end_date, "%Y-%m-%d").date()
            queryset = queryset.filter(purchase__date__range=[start, end])
        except:
            pass

    # ✅ FIXED party access in summary
    summary = (
        queryset.values(
            "item__name",
            "item__category__name",
            "species__name",
            "grade__grade",
            "purchase__party_name__party",  # ✅ FIXED
            "purchase__party_name__district",
            "purchase__party_name__state",
            "purchase__voucher_number",
            "purchase__date",
        )
        .annotate(
            total_quantity=Sum("quantity"),
            total_amount=Sum("amount"),
            avg_rate=Sum(F("amount"), output_field=FloatField()) / Sum(F("quantity"), output_field=FloatField()),
        )
        .order_by("purchase__date")
    )

    return render(
        request,
        "adminapp/report/local_purchase_report_print.html",
        {
            "summary": summary,
            "start_date": start_date,
            "end_date": end_date,
            "selected_items": selected_items,
            "selected_grades": selected_grades,
            "selected_categories": selected_categories,
            "selected_species": selected_species,
            "selected_parties": selected_parties,  # ✅ Added this
            "party_search": party_search,
        },
    )


# PEELING SHED SUPPLY REPORT
@check_permission('report_view')
def peeling_shed_supply_report(request):
    # ✅ Only show items that are in spot_purchase_item (supplied items only)
    items = Item.objects.filter(
        id__in=PeelingShedSupply.objects.values_list('spot_purchase_item__item__id', flat=True)
    ).distinct().order_by('name')
    
    # ✅ Only get item types from supplied items that also have peeling data
    item_types = ItemType.objects.filter(
        # From items that are supplied
        item__spotpurchaseitem__peelingshedsupply__isnull=False,
        # And also have peeling type records
        peelingshedpeelingtype__supply__isnull=False
    ).distinct().order_by('name')
    
    # ✅ Only get sheds that have received supplies
    sheds = Shed.objects.filter(
        peelingshedsupply__isnull=False
    ).distinct().order_by('name')
    
    # ✅ Only get spot purchases that have been supplied to sheds
    spot_purchases = SpotPurchase.objects.filter(
        peelingshedsupply__isnull=False
    ).distinct().order_by('voucher_number')

    queryset = PeelingShedSupply.objects.select_related(
        "shed", "spot_purchase", "spot_purchase_item", "spot_purchase_item__item"
    ).prefetch_related("peeling_types", "peeling_types__item", "peeling_types__item_type")

    # ✅ Multi-select filters
    selected_items = request.GET.getlist("items")
    selected_item_types = request.GET.getlist("item_types")
    selected_sheds = request.GET.getlist("sheds")
    selected_spot_purchases = request.GET.getlist("spot_purchases")
    date_filter = request.GET.get("date_filter")

    # ✅ Date range filter
    start_date = request.GET.get("start_date")
    end_date = request.GET.get("end_date")

    # ✅ Voucher number search
    voucher_search = request.GET.get("voucher_search", "").strip()

    # ✅ Vehicle number search
    vehicle_search = request.GET.get("vehicle_search", "").strip()

    # Apply filters
    if selected_items:
        queryset = queryset.filter(spot_purchase_item__item__id__in=selected_items)
    if selected_item_types:
        queryset = queryset.filter(peeling_types__item_type__id__in=selected_item_types)
    if selected_sheds:
        queryset = queryset.filter(shed__id__in=selected_sheds)
    if selected_spot_purchases:
        queryset = queryset.filter(spot_purchase__id__in=selected_spot_purchases)
    if voucher_search:
        queryset = queryset.filter(voucher_number__icontains=voucher_search)
    if vehicle_search:
        queryset = queryset.filter(vehicle_number__icontains=vehicle_search)

    # ✅ Quick date filter
    if date_filter == "week":
        queryset = queryset.filter(date__gte=now().date() - timedelta(days=7))
    elif date_filter == "month":
        queryset = queryset.filter(date__month=now().month)
    elif date_filter == "year":
        queryset = queryset.filter(date__year=now().year)

    # ✅ Custom date range
    if start_date and end_date:
        try:
            start = datetime.strptime(start_date, "%Y-%m-%d").date()
            end = datetime.strptime(end_date, "%Y-%m-%d").date()
            queryset = queryset.filter(date__range=[start, end])
        except:
            pass

    # ✅ Group & summary
    summary = (
        queryset.values(
            "voucher_number",
            "date",
            "shed__name",
            "vehicle_number",
            "spot_purchase_date",
            "spot_purchase__voucher_number",
            "spot_purchase_item__item__name",
            "spot_purchase_item__item__category__name",
            "spot_purchase_item__item__species__name",
        )
        .annotate(
            total_boxes_purchase=Sum("SpotPurchase_total_boxes"),
            total_quantity_purchase=Sum("SpotPurchase_quantity"),
            avg_box_weight=Avg("SpotPurchase_average_box_weight"),
            boxes_received=Sum("boxes_received_shed"),
            quantity_received=Sum("quantity_received_shed"),
            total_peeling_amount=Sum("peeling_types__amount"),
        )
        .order_by("date")
    )

    # ✅ Get unique voucher numbers and vehicles for search suggestions (only from existing records)
    vouchers = PeelingShedSupply.objects.values_list('voucher_number', flat=True).distinct().order_by('voucher_number')
    vehicles = PeelingShedSupply.objects.values_list('vehicle_number', flat=True).distinct().order_by('vehicle_number')

    # ✅ Check if print/export requested
    action = request.GET.get("action")
    print_mode = request.GET.get("print")  # Check for print parameter

    # Handle print request
    if action == "print" or print_mode == "1":
        return render(
            request,
            "adminapp/report/peeling_shed_supply_report_print.html",
            {
                "summary": summary, 
                "start_date": start_date, 
                "end_date": end_date
            },
        )

    if action == "csv":
        response = HttpResponse(content_type="text/csv")
        response["Content-Disposition"] = 'attachment; filename="peeling_shed_supply_report.csv"'
        writer = csv.writer(response)
        writer.writerow([
            "Date", "Voucher No", "Shed", "Vehicle", "Spot Purchase Date", 
            "Spot Voucher", "Item", "Category", "Species", "Purchase Boxes", 
            "Purchase Quantity", "Avg Box Weight", "Boxes Received", 
            "Quantity Received", "Total Peeling Amount"
        ])
        for row in summary:
            writer.writerow([
                row["date"],
                row["voucher_number"],
                row["shed__name"],
                row["vehicle_number"],
                row["spot_purchase_date"],
                row["spot_purchase__voucher_number"],
                row["spot_purchase_item__item__name"],
                row["spot_purchase_item__item__category__name"] or "N/A",
                row["spot_purchase_item__item__species__name"] or "N/A",
                row["total_boxes_purchase"],
                row["total_quantity_purchase"],
                round(row["avg_box_weight"], 2) if row["avg_box_weight"] else 0,
                row["boxes_received"],
                row["quantity_received"],
                row["total_peeling_amount"],
            ])
        return response

    if action == "excel":
        output = io.BytesIO()
        workbook = xlsxwriter.Workbook(output, {"in_memory": True})
        worksheet = workbook.add_worksheet("Report")

        headers = [
            "Date", "Voucher No", "Shed", "Vehicle", "Spot Purchase Date", 
            "Spot Voucher", "Item", "Category", "Species", "Purchase Boxes", 
            "Purchase Quantity", "Avg Box Weight", "Boxes Received", 
            "Quantity Received", "Total Peeling Amount"
        ]
        for col, header in enumerate(headers):
            worksheet.write(0, col, header)

        for row_idx, row in enumerate(summary, start=1):
            worksheet.write(row_idx, 0, str(row["date"]))
            worksheet.write(row_idx, 1, row["voucher_number"])
            worksheet.write(row_idx, 2, row["shed__name"])
            worksheet.write(row_idx, 3, row["vehicle_number"])
            worksheet.write(row_idx, 4, str(row["spot_purchase_date"]) if row["spot_purchase_date"] else "N/A")
            worksheet.write(row_idx, 5, row["spot_purchase__voucher_number"])
            worksheet.write(row_idx, 6, row["spot_purchase_item__item__name"])
            worksheet.write(row_idx, 7, row["spot_purchase_item__item__category__name"] or "N/A")
            worksheet.write(row_idx, 8, row["spot_purchase_item__item__species__name"] or "N/A")
            worksheet.write(row_idx, 9, row["total_boxes_purchase"])
            worksheet.write(row_idx, 10, row["total_quantity_purchase"])
            worksheet.write(row_idx, 11, round(row["avg_box_weight"], 2) if row["avg_box_weight"] else 0)
            worksheet.write(row_idx, 12, row["boxes_received"])
            worksheet.write(row_idx, 13, row["quantity_received"])
            worksheet.write(row_idx, 14, row["total_peeling_amount"])

        workbook.close()
        output.seek(0)

        response = HttpResponse(output.read(), content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        response["Content-Disposition"] = 'attachment; filename="peeling_shed_supply_report.xlsx"'
        return response

    return render(
        request,
        "adminapp/report/peeling_shed_supply_report.html",
        {
            "summary": summary,
            "items": items,
            "item_types": item_types,
            "sheds": sheds,
            "spot_purchases": spot_purchases,
            "vouchers": vouchers,
            "vehicles": vehicles,
            "selected_items": selected_items,
            "selected_item_types": selected_item_types,
            "selected_sheds": selected_sheds,
            "selected_spot_purchases": selected_spot_purchases,
            "date_filter": date_filter,
            "start_date": start_date,
            "end_date": end_date,
            "voucher_search": voucher_search,
            "vehicle_search": vehicle_search,
        },
    )

@check_permission('report_export')
def peeling_shed_supply_report_print(request):
    """Separate view specifically for print format"""
    # ✅ Only show supplied items for print view too
    items = Item.objects.filter(
        id__in=PeelingShedSupply.objects.values_list('spot_purchase_item__item__id', flat=True)
    ).distinct().order_by('name')
    
    item_types = ItemType.objects.filter(
        # From items that are supplied
        item__spotpurchaseitem__peelingshedsupply__isnull=False,
        # And also have peeling type records
        peelingshedpeelingtype__supply__isnull=False
    ).distinct().order_by('name')
    
    sheds = Shed.objects.filter(
        peelingshedsupply__isnull=False
    ).distinct().order_by('name')
    
    spot_purchases = SpotPurchase.objects.filter(
        peelingshedsupply__isnull=False
    ).distinct().order_by('voucher_number')

    queryset = PeelingShedSupply.objects.select_related(
        "shed", 
        "spot_purchase", 
        "spot_purchase_item", 
        "spot_purchase_item__item",
        "spot_purchase_item__item__species",
        "spot_purchase_item__item__itemgrade",  # Add ForeignKey relationship
        "spot_purchase_item__item__itemtype"    # Add ForeignKey relationship
    ).prefetch_related("peeling_types", "peeling_types__item", "peeling_types__item_type")

    # Apply the same filters as main view
    selected_items = request.GET.getlist("items")
    selected_item_types = request.GET.getlist("item_types")
    selected_sheds = request.GET.getlist("sheds")
    selected_spot_purchases = request.GET.getlist("spot_purchases")
    date_filter = request.GET.get("date_filter")
    start_date = request.GET.get("start_date")
    end_date = request.GET.get("end_date")
    voucher_search = request.GET.get("voucher_search", "").strip()
    vehicle_search = request.GET.get("vehicle_search", "").strip()

    # Apply filters
    if selected_items:
        queryset = queryset.filter(spot_purchase_item__item__id__in=selected_items)
    if selected_item_types:
        queryset = queryset.filter(peeling_types__item_type__id__in=selected_item_types)
    if selected_sheds:
        queryset = queryset.filter(shed__id__in=selected_sheds)
    if selected_spot_purchases:
        queryset = queryset.filter(spot_purchase__id__in=selected_spot_purchases)
    if voucher_search:
        queryset = queryset.filter(voucher_number__icontains=voucher_search)
    if vehicle_search:
        queryset = queryset.filter(vehicle_number__icontains=vehicle_search)

    # Date filters
    if date_filter == "week":
        queryset = queryset.filter(date__gte=now().date() - timedelta(days=7))
    elif date_filter == "month":
        queryset = queryset.filter(date__month=now().month)
    elif date_filter == "year":
        queryset = queryset.filter(date__year=now().year)

    if start_date and end_date:
        try:
            start = datetime.strptime(start_date, "%Y-%m-%d").date()
            end = datetime.strptime(end_date, "%Y-%m-%d").date()
            queryset = queryset.filter(date__range=[start, end])
        except ValueError:
            pass

    # Generate summary - Access ForeignKey relationships properly
    summary = (
        queryset.values(
            "voucher_number",
            "date",
            "shed__name",
            "vehicle_number",
            "spot_purchase_date",
            "spot_purchase__voucher_number",
            "spot_purchase_item__item__name",
            "spot_purchase_item__item__category__name",
            "spot_purchase_item__item__species__name",           # Species (ForeignKey -> name)
            "spot_purchase_item__item__itemgrade__grade",        # Grade (ForeignKey -> grade field)
            "spot_purchase_item__item__itemtype__name",          # ItemType (ForeignKey -> name field)
        )
        .annotate(
            total_boxes_purchase=Sum("SpotPurchase_total_boxes"),
            total_quantity_purchase=Sum("SpotPurchase_quantity"),
            avg_box_weight=Avg("SpotPurchase_average_box_weight"),
            boxes_received=Sum("boxes_received_shed"),
            quantity_received=Sum("quantity_received_shed"),
            total_peeling_amount=Sum("peeling_types__amount"),
        )
        .order_by("date", "voucher_number")
    )

    return render(
        request,
        "adminapp/report/peeling_shed_supply_report_print.html",
        {
            "summary": summary,
            "start_date": start_date,
            "end_date": end_date,
            "selected_items": selected_items,
            "selected_item_types": selected_item_types,
            "selected_sheds": selected_sheds,
            "selected_spot_purchases": selected_spot_purchases,
            "voucher_search": voucher_search,
            "vehicle_search": vehicle_search,
        },
    )




# FREEZING REPORT
@check_permission('report_view')
def freezing_report(request):
    # First, let's check what fields actually exist on the models
    from django.db import connection
    
    # Check FreezingEntrySpotItem fields
    try:
        spot_item_fields = [field.name for field in FreezingEntrySpotItem._meta.fields]
        print("FreezingEntrySpotItem fields:", spot_item_fields)
        
        local_item_fields = [field.name for field in FreezingEntryLocalItem._meta.fields]
        print("FreezingEntryLocalItem fields:", local_item_fields)
        
        # Check foreign key relationships
        spot_fk_fields = [field.name for field in FreezingEntrySpotItem._meta.fields if field.get_internal_type() == 'ForeignKey']
        print("FreezingEntrySpotItem FK fields:", spot_fk_fields)
        
        local_fk_fields = [field.name for field in FreezingEntryLocalItem._meta.fields if field.get_internal_type() == 'ForeignKey']
        print("FreezingEntryLocalItem FK fields:", local_fk_fields)
        
    except Exception as e:
        print("Error checking fields:", str(e))

    items = Item.objects.all()
    grades = ItemGrade.objects.all()
    categories = ItemCategory.objects.all()
    species = Species.objects.all()
    brands = ItemBrand.objects.all()
    freezing_categories = FreezingCategory.objects.all()
    processing_centers = ProcessingCenter.objects.all()
    stores = Store.objects.all()
    
    # Check if models exist and get units/glazes
    try:
        units = PackingUnit.objects.all()
    except NameError:
        units = []
    
    try:
        glazes = GlazePercentage.objects.all()
    except NameError:
        glazes = []

    # Get filter parameters
    selected_items = request.GET.getlist("items")
    selected_grades = request.GET.getlist("grades")
    selected_categories = request.GET.getlist("categories")
    selected_species = request.GET.getlist("species")
    selected_brands = request.GET.getlist("brands")
    selected_freezing_categories = request.GET.getlist("freezing_categories")
    selected_processing_centers = request.GET.getlist("processing_centers")
    selected_stores = request.GET.getlist("stores")
    selected_units = request.GET.getlist("units")
    selected_glazes = request.GET.getlist("glazes")
    
    date_filter = request.GET.get("date_filter")
    start_date = request.GET.get("start_date")
    end_date = request.GET.get("end_date")
    freezing_status = request.GET.get("freezing_status")
    voucher_search = request.GET.get("voucher_search", "").strip()
    entry_type = request.GET.get("entry_type", "all")  # all, spot, local
    section_by = request.GET.get("section_by", "category")

    # SAFE: Start with minimal select_related and build up
    spot_queryset = FreezingEntrySpotItem.objects.select_related("freezing_entry", "item", "item__category")
    local_queryset = FreezingEntryLocalItem.objects.select_related("freezing_entry", "item", "item__category")

    # Check what other relationships exist and add them safely
    try:
        # Test if grade field exists
        test_spot = FreezingEntrySpotItem.objects.first()
        if test_spot and hasattr(test_spot, 'grade'):
            spot_queryset = spot_queryset.select_related("grade")
            local_queryset = local_queryset.select_related("grade")
            print("Added grade to select_related")
    except:
        print("No grade field found")

    try:
        # Test if species field exists
        if test_spot and hasattr(test_spot, 'species'):
            spot_queryset = spot_queryset.select_related("species")
            local_queryset = local_queryset.select_related("species")
            print("Added species to select_related")
    except:
        print("No direct species field found")

    try:
        # Test if brand field exists
        if test_spot and hasattr(test_spot, 'brand'):
            spot_queryset = spot_queryset.select_related("brand")
            local_queryset = local_queryset.select_related("brand")
            print("Added brand to select_related")
    except:
        print("No brand field found")

    try:
        # Test if freezing_category field exists
        if test_spot and hasattr(test_spot, 'freezing_category'):
            spot_queryset = spot_queryset.select_related("freezing_category")
            local_queryset = local_queryset.select_related("freezing_category")
            print("Added freezing_category to select_related")
    except:
        print("No freezing_category field found")

    try:
        # Test if processing_center field exists
        if test_spot and hasattr(test_spot, 'processing_center'):
            spot_queryset = spot_queryset.select_related("processing_center")
            local_queryset = local_queryset.select_related("processing_center")
            print("Added processing_center to select_related")
    except:
        print("No processing_center field found")

    try:
        # Test if store field exists
        if test_spot and hasattr(test_spot, 'store'):
            spot_queryset = spot_queryset.select_related("store")
            local_queryset = local_queryset.select_related("store")
            print("Added store to select_related")
    except:
        print("No store field found")

    # Apply filters with safe field checks
    def apply_filters(queryset, is_spot=True):
        # Item filters
        if selected_items:
            queryset = queryset.filter(item__id__in=selected_items)
        
        # Check if grade field exists before filtering
        test_item = queryset.first()
        if test_item and hasattr(test_item, 'grade') and selected_grades:
            queryset = queryset.filter(grade__id__in=selected_grades)
        
        if selected_categories:
            queryset = queryset.filter(item__category__id__in=selected_categories)
        
        # Check if species field exists before filtering
        if test_item and hasattr(test_item, 'species') and selected_species:
            queryset = queryset.filter(species__id__in=selected_species)
        
        # Check other fields similarly
        if test_item and hasattr(test_item, 'brand') and selected_brands:
            queryset = queryset.filter(brand__id__in=selected_brands)
        if test_item and hasattr(test_item, 'freezing_category') and selected_freezing_categories:
            queryset = queryset.filter(freezing_category__id__in=selected_freezing_categories)
        if test_item and hasattr(test_item, 'processing_center') and selected_processing_centers:
            queryset = queryset.filter(processing_center__id__in=selected_processing_centers)
        if test_item and hasattr(test_item, 'store') and selected_stores:
            queryset = queryset.filter(store__id__in=selected_stores)
        if test_item and hasattr(test_item, 'unit') and selected_units:
            queryset = queryset.filter(unit__id__in=selected_units)
        if test_item and hasattr(test_item, 'glaze') and selected_glazes:
            queryset = queryset.filter(glaze__id__in=selected_glazes)
            
        # Status and voucher filters
        if freezing_status:
            queryset = queryset.filter(freezing_entry__freezing_status=freezing_status)
        if voucher_search:
            queryset = queryset.filter(freezing_entry__voucher_number__icontains=voucher_search)

        # Date filters
        today = now().date()
        if date_filter == "today":
            queryset = queryset.filter(freezing_entry__freezing_date=today)
        elif date_filter == "week":
            week_start = today - timedelta(days=today.weekday())
            queryset = queryset.filter(freezing_entry__freezing_date__gte=week_start)
        elif date_filter == "month":
            queryset = queryset.filter(
                freezing_entry__freezing_date__year=today.year,
                freezing_entry__freezing_date__month=today.month
            )
        elif date_filter == "quarter":
            quarter_start_month = ((today.month - 1) // 3) * 3 + 1
            quarter_start = today.replace(month=quarter_start_month, day=1)
            queryset = queryset.filter(freezing_entry__freezing_date__gte=quarter_start)
        elif date_filter == "year":
            queryset = queryset.filter(freezing_entry__freezing_date__year=today.year)
        elif date_filter == "custom" and start_date and end_date:
            try:
                start = datetime.strptime(start_date, "%Y-%m-%d").date()
                end = datetime.strptime(end_date, "%Y-%m-%d").date()
                queryset = queryset.filter(freezing_entry__freezing_date__range=[start, end])
            except ValueError:
                pass

        if start_date and end_date and not date_filter:
            try:
                start = datetime.strptime(start_date, "%Y-%m-%d").date()
                end = datetime.strptime(end_date, "%Y-%m-%d").date()
                queryset = queryset.filter(freezing_entry__freezing_date__range=[start, end])
            except ValueError:
                pass

        return queryset

    # Apply filters
    spot_queryset = apply_filters(spot_queryset, True)
    local_queryset = apply_filters(local_queryset, False)

    # Process data safely
    all_data = []

    if entry_type in ['all', 'spot']:
        for item in spot_queryset:
            data_row = {
                'id': item.id,
                'item__name': item.item.name if item.item else None,
                'item__category__name': item.item.category.name if item.item and item.item.category else None,
                'freezing_entry__voucher_number': item.freezing_entry.voucher_number if item.freezing_entry else None,
                'freezing_entry__freezing_date': item.freezing_entry.freezing_date if item.freezing_entry else None,
                'freezing_entry__freezing_status': item.freezing_entry.freezing_status if item.freezing_entry else None,
                'entry_type': 'spot',
                'item_count': 1
            }
            
            # Add optional fields safely
            if hasattr(item, 'species') and item.species:
                data_row['item__species__name'] = item.species.name
            else:
                data_row['item__species__name'] = None
                
            if hasattr(item, 'grade') and item.grade:
                data_row['grade__grade'] = item.grade.grade
            else:
                data_row['grade__grade'] = None
                
            if hasattr(item, 'brand') and item.brand:
                data_row['brand__name'] = item.brand.name
            else:
                data_row['brand__name'] = None
                
            if hasattr(item, 'freezing_category') and item.freezing_category:
                data_row['freezing_category__name'] = item.freezing_category.name
            else:
                data_row['freezing_category__name'] = None
                
            if hasattr(item, 'processing_center') and item.processing_center:
                data_row['processing_center__name'] = item.processing_center.name
            else:
                data_row['processing_center__name'] = None
                
            if hasattr(item, 'store') and item.store:
                data_row['store__name'] = item.store.name
            else:
                data_row['store__name'] = None

            # Add numeric fields
            data_row.update({
                'total_kg': float(getattr(item, 'kg', 0) or 0),
                'total_slab_quantity': float(getattr(item, 'slab_quantity', 0) or 0),
                'total_c_s_quantity': float(getattr(item, 'c_s_quantity', 0) or 0),
                'total_usd_amount': float(getattr(item, 'usd_rate_item', 0) or 0),
                'total_inr_amount': float(getattr(item, 'usd_rate_item_to_inr', 0) or 0),
                'avg_usd_rate_per_kg': float(getattr(item, 'usd_rate_per_kg', 0) or 0),
                'avg_yield_percentage': float(getattr(item, 'yield_percentage', 0) or 0),
            })
            
            # Add unit and glaze fields if they exist
            if hasattr(item, 'unit') and item.unit:
                data_row['unit__description'] = item.unit.description
                data_row['unit__unit_code'] = item.unit.unit_code
            else:
                data_row['unit__description'] = None
                data_row['unit__unit_code'] = None
                
            if hasattr(item, 'glaze') and item.glaze:
                data_row['glaze__percentage'] = item.glaze.percentage
            else:
                data_row['glaze__percentage'] = None
                
            all_data.append(data_row)

    if entry_type in ['all', 'local']:
        for item in local_queryset:
            data_row = {
                'id': item.id,
                'item__name': item.item.name if item.item else None,
                'item__category__name': item.item.category.name if item.item and item.item.category else None,
                'freezing_entry__voucher_number': item.freezing_entry.voucher_number if item.freezing_entry else None,
                'freezing_entry__freezing_date': item.freezing_entry.freezing_date if item.freezing_entry else None,
                'freezing_entry__freezing_status': item.freezing_entry.freezing_status if item.freezing_entry else None,
                'entry_type': 'local',
                'item_count': 1
            }
            
            # Add optional fields safely (same as spot)
            if hasattr(item, 'species') and item.species:
                data_row['item__species__name'] = item.species.name
            else:
                data_row['item__species__name'] = None
                
            if hasattr(item, 'grade') and item.grade:
                data_row['grade__grade'] = item.grade.grade
            else:
                data_row['grade__grade'] = None
                
            if hasattr(item, 'brand') and item.brand:
                data_row['brand__name'] = item.brand.name
            else:
                data_row['brand__name'] = None
                
            if hasattr(item, 'freezing_category') and item.freezing_category:
                data_row['freezing_category__name'] = item.freezing_category.name
            else:
                data_row['freezing_category__name'] = None
                
            if hasattr(item, 'processing_center') and item.processing_center:
                data_row['processing_center__name'] = item.processing_center.name
            else:
                data_row['processing_center__name'] = None
                
            if hasattr(item, 'store') and item.store:
                data_row['store__name'] = item.store.name
            else:
                data_row['store__name'] = None

            # Add numeric fields
            data_row.update({
                'total_kg': float(getattr(item, 'kg', 0) or 0),
                'total_slab_quantity': float(getattr(item, 'slab_quantity', 0) or 0),
                'total_c_s_quantity': float(getattr(item, 'c_s_quantity', 0) or 0),
                'total_usd_amount': float(getattr(item, 'usd_rate_item', 0) or 0),
                'total_inr_amount': float(getattr(item, 'usd_rate_item_to_inr', 0) or 0),
                'avg_usd_rate_per_kg': float(getattr(item, 'usd_rate_per_kg', 0) or 0),
                'avg_yield_percentage': None,  # Local entries don't have yield percentage
            })
            
            # Add unit and glaze fields if they exist
            if hasattr(item, 'unit') and item.unit:
                data_row['unit__description'] = item.unit.description
                data_row['unit__unit_code'] = item.unit.unit_code
            else:
                data_row['unit__description'] = None
                data_row['unit__unit_code'] = None
                
            if hasattr(item, 'glaze') and item.glaze:
                data_row['glaze__percentage'] = item.glaze.percentage
            else:
                data_row['glaze__percentage'] = None
                
            all_data.append(data_row)

    # Sectioning logic (rest of the original code remains the same)
    sectioned_data = {}
    
    for item in all_data:
        if section_by == "category":
            section_key = item.get("item__category__name") or "Uncategorized"
        elif section_by == "brand":
            section_key = item.get("brand__name") or "No Brand"
        elif section_by == "processing_center":
            section_key = item.get("processing_center__name") or "No Processing Center"
        elif section_by == "store":
            section_key = item.get("store__name") or "No Store"
        elif section_by == "month":
            date_obj = item.get("freezing_entry__freezing_date")
            if date_obj:
                section_key = f"{date_obj.strftime('%B %Y')}"
            else:
                section_key = "No Date"
        elif section_by == "species":
            section_key = item.get("item__species__name") or "No Species"
        elif section_by == "grade":
            section_key = item.get("grade__grade") or "No Grade"
        elif section_by == "item":
            section_key = item.get("item__name") or "No Item"
        elif section_by == "unit":
            section_key = item.get("unit__description") or "No Unit"
        elif section_by == "glaze":
            glaze_pct = item.get("glaze__percentage")
            section_key = f"{glaze_pct}%" if glaze_pct is not None else "No Glaze"
        elif section_by == "entry_type":
            section_key = item.get("entry_type", "Unknown").title()
        elif section_by == "status":
            section_key = item.get("freezing_entry__freezing_status", "Unknown").title()
        else:
            section_key = "All Items"
            
        if section_key not in sectioned_data:
            sectioned_data[section_key] = {
                'items': [],
                'totals': {
                    'total_kg': 0,
                    'total_slab_quantity': 0,
                    'total_c_s_quantity': 0,
                    'total_usd_amount': 0,
                    'total_inr_amount': 0,
                    'count': 0,
                    'item_count': 0
                }
            }
        
        sectioned_data[section_key]['items'].append(item)
        
        # Calculate section totals
        totals = sectioned_data[section_key]['totals']
        totals['total_kg'] += float(item.get('total_kg') or 0)
        totals['total_slab_quantity'] += float(item.get('total_slab_quantity') or 0)
        totals['total_c_s_quantity'] += float(item.get('total_c_s_quantity') or 0)
        totals['total_usd_amount'] += float(item.get('total_usd_amount') or 0)
        totals['total_inr_amount'] += float(item.get('total_inr_amount') or 0)
        totals['count'] += 1
        totals['item_count'] += int(item.get('item_count') or 0)

    sectioned_data = dict(sorted(sectioned_data.items()))

    # Calculate grand totals
    grand_totals = {
        'total_kg': 0,
        'total_slab_quantity': 0,
        'total_c_s_quantity': 0,
        'total_usd_amount': 0,
        'total_inr_amount': 0,
        'count': 0,
        'item_count': 0,
        'avg_kg_per_entry': 0,
        'avg_usd_per_kg': 0
    }
    
    for section in sectioned_data.values():
        for key in ['total_kg', 'total_slab_quantity', 'total_c_s_quantity', 
                   'total_usd_amount', 'total_inr_amount', 'count', 'item_count']:
            grand_totals[key] += section['totals'][key]

    if grand_totals['count'] > 0:
        grand_totals['avg_kg_per_entry'] = grand_totals['total_kg'] / grand_totals['count']
    if grand_totals['total_kg'] > 0:
        grand_totals['avg_usd_per_kg'] = grand_totals['total_usd_amount'] / grand_totals['total_kg']

    # Get unique vouchers
    try:
        spot_vouchers = list(FreezingEntrySpot.objects.values_list('voucher_number', flat=True).distinct())
        local_vouchers = list(FreezingEntryLocal.objects.values_list('voucher_number', flat=True).distinct())
        all_vouchers = sorted(set(spot_vouchers + local_vouchers))
    except Exception as e:
        all_vouchers = []

    return render(
        request,
        "adminapp/report/freezing_report.html",
        {
            "sectioned_data": sectioned_data,
            "grand_totals": grand_totals,
            "items": items,
            "grades": grades,
            "categories": categories,
            "species": species,
            "brands": brands,
            "freezing_categories": freezing_categories,
            "processing_centers": processing_centers,
            "stores": stores,
            "units": units,
            "glazes": glazes,
            "vouchers": all_vouchers,
            "selected_items": selected_items,
            "selected_grades": selected_grades,
            "selected_categories": selected_categories,
            "selected_species": selected_species,
            "selected_brands": selected_brands,
            "selected_freezing_categories": selected_freezing_categories,
            "selected_processing_centers": selected_processing_centers,
            "selected_stores": selected_stores,
            "selected_units": selected_units,
            "selected_glazes": selected_glazes,
            "date_filter": date_filter,
            "start_date": start_date,
            "end_date": end_date,
            "freezing_status": freezing_status,
            "voucher_search": voucher_search,
            "entry_type": entry_type,
            "section_by": section_by,
        },
    )

@check_permission('report_export')
def freezing_report_print(request):
    """Separate view specifically for print format"""
    items = Item.objects.all()
    grades = ItemGrade.objects.all()
    categories = ItemCategory.objects.all()
    species = Species.objects.all()
    brands = ItemBrand.objects.all()
    freezing_categories = FreezingCategory.objects.all()

    # Get filter parameters (same as main view)
    selected_items = request.GET.getlist("items")
    selected_grades = request.GET.getlist("grades")
    selected_categories = request.GET.getlist("categories")
    selected_species = request.GET.getlist("species")
    selected_brands = request.GET.getlist("brands")
    selected_freezing_categories = request.GET.getlist("freezing_categories")
    date_filter = request.GET.get("date_filter")
    start_date = request.GET.get("start_date")
    end_date = request.GET.get("end_date")
    freezing_status = request.GET.get("freezing_status")
    voucher_search = request.GET.get("voucher_search", "").strip()
    entry_type = request.GET.get("entry_type", "all")

    # Base querysets
    spot_queryset = FreezingEntrySpotItem.objects.select_related(
        "freezing_entry", "item", "grade", "item__category", "item__species",
        "brand", "freezing_category"
    )
    
    local_queryset = FreezingEntryLocalItem.objects.select_related(
        "freezing_entry", "item", "grade", "item__category", "item__species",
        "brand", "freezing_category"
    )

    # Apply same filters as main view
    def apply_filters(queryset):
        if selected_items:
            queryset = queryset.filter(item__id__in=selected_items)
        if selected_grades:
            queryset = queryset.filter(grade__id__in=selected_grades)
        if selected_categories:
            queryset = queryset.filter(item__category__id__in=selected_categories)
        if selected_species:
            queryset = queryset.filter(item__species__id__in=selected_species)
        if selected_brands:
            queryset = queryset.filter(brand__id__in=selected_brands)
        if selected_freezing_categories:
            queryset = queryset.filter(freezing_category__id__in=selected_freezing_categories)
        if freezing_status:
            queryset = queryset.filter(freezing_entry__freezing_status=freezing_status)
        if voucher_search:
            queryset = queryset.filter(freezing_entry__voucher_number__icontains=voucher_search)

        if date_filter == "week":
            queryset = queryset.filter(freezing_entry__freezing_date__gte=now().date() - timedelta(days=7))
        elif date_filter == "month":
            queryset = queryset.filter(freezing_entry__freezing_date__month=now().month)
        elif date_filter == "year":
            queryset = queryset.filter(freezing_entry__freezing_date__year=now().year)

        if start_date and end_date:
            try:
                start = datetime.strptime(start_date, "%Y-%m-%d").date()
                end = datetime.strptime(end_date, "%Y-%m-%d").date()
                queryset = queryset.filter(freezing_entry__freezing_date__range=[start, end])
            except:
                pass

        return queryset

    # Apply filters
    spot_queryset = apply_filters(spot_queryset)
    local_queryset = apply_filters(local_queryset)

    summary_data = []

    # Process entries based on type filter
    if entry_type in ['all', 'spot']:
        spot_summary = (
            spot_queryset.values(
                "item__name",
                "item__category__name",
                "item__species__name",
                "grade__grade",
                "brand__name",
                "freezing_category__name",
                "freezing_entry__voucher_number",
                "freezing_entry__freezing_date",
                "freezing_entry__freezing_status",
            )
            .annotate(
                total_kg=Sum("kg"),
                total_slab_quantity=Sum("slab_quantity"),
                total_c_s_quantity=Sum("c_s_quantity"),
                total_usd_amount=Sum("usd_rate_item"),
                total_inr_amount=Sum("usd_rate_item_to_inr"),
                avg_usd_rate_per_kg=Avg("usd_rate_per_kg"),
                avg_yield_percentage=Avg("yield_percentage"),
                entry_type=Value('Spot', output_field=CharField()),
            )
            .order_by("freezing_entry__freezing_date")
        )
        summary_data.extend(list(spot_summary))

    if entry_type in ['all', 'local']:
        local_summary = (
            local_queryset.values(
                "item__name",
                "item__category__name",
                "item__species__name",
                "grade__grade",
                "brand__name",
                "freezing_category__name",
                "freezing_entry__voucher_number",
                "freezing_entry__freezing_date",
                "freezing_entry__freezing_status",
            )
            .annotate(
                total_kg=Sum("kg"),
                total_slab_quantity=Sum("slab_quantity"),
                total_c_s_quantity=Sum("c_s_quantity"),
                total_usd_amount=Sum("usd_rate_item"),
                total_inr_amount=Sum("usd_rate_item_to_inr"),
                avg_usd_rate_per_kg=Avg("usd_rate_per_kg"),
                avg_yield_percentage=Value(None, output_field=DecimalField()),
                entry_type=Value('Local', output_field=CharField()),
            )
            .order_by("freezing_entry__freezing_date")
        )
        summary_data.extend(list(local_summary))

    # Sort combined data by date
    summary_data = sorted(summary_data, key=lambda x: x['freezing_entry__freezing_date'])

    return render(
        request,
        "adminapp/report/freezing_report_print.html",
        {
            "summary": summary_data,
            "start_date": start_date,
            "end_date": end_date,
            "entry_type": entry_type,
            "selected_items": selected_items,
            "selected_grades": selected_grades,
            "selected_categories": selected_categories,
            "selected_species": selected_species,
            "selected_brands": selected_brands,
            "selected_freezing_categories": selected_freezing_categories,
            "freezing_status": freezing_status,
            "voucher_search": voucher_search,
        },
    )



# Tenant Freezing Entry Views
@check_permission('freezing_view')
def tenant_freezing_list(request):
    entries = FreezingEntryTenant.objects.all().order_by('-freezing_date')
    return render(request, 'adminapp/tenant/list.html', {'entries': entries})

@check_permission('freezing_view')
def tenant_freezing_detail(request, pk):
    entry = get_object_or_404(FreezingEntryTenant, pk=pk)
    return render(request, 'adminapp/tenant/detail.html', {'entry': entry})

@transaction.atomic
@check_permission('freezing_add')
def tenant_freezing_create(request):
    if request.method == "POST":
        form = FreezingEntryTenantForm(request.POST)
        formset = FreezingEntryTenantItemFormSet(request.POST)
        
        print("=== DEBUG FORMSET DATA ===")
        print(f"POST data keys: {list(request.POST.keys())}")
        print(f"Formset is_valid: {formset.is_valid()}")
        print(f"Form is_valid: {form.is_valid()}")
        print(f"Formset total forms: {formset.total_form_count()}")
        print(f"Formset errors: {formset.errors}")
        print(f"Formset non_form_errors: {formset.non_form_errors()}")
        
        if form.is_valid() and formset.is_valid():
            # Save the main entry first
            entry = form.save()
            print(f"Main entry saved with ID: {entry.id}")
            
            # Set the instance and save the formset
            formset.instance = entry
            saved_items = formset.save()
            print(f"Saved {len(saved_items)} items from formset")
            
            # Debug: Check what was actually saved
            for i, item in enumerate(saved_items):
                print(f"Item {i+1}: {item.item} - Slab: {item.slab_quantity} - CS: {item.c_s_quantity} - KG: {item.kg}")

            # 🔹 Update totals
            totals = entry.items.aggregate(
                total_slab_sum=Sum('slab_quantity'),
                total_c_s_sum=Sum('c_s_quantity'),
                total_kg_sum=Sum('kg'),
            )
            entry.total_slab = totals['total_slab_sum'] or 0
            entry.total_c_s = totals['total_c_s_sum'] or 0
            entry.total_kg = totals['total_kg_sum'] or 0
            entry.total_amount = 0  # (If you have rate × qty, calculate here)
            entry.save()
            
            print(f"Updated totals - Slab: {entry.total_slab}, CS: {entry.total_c_s}, KG: {entry.total_kg}")

            return redirect(reverse('adminapp:list_freezing_entry_tenant'))
        else:
            # Debug form and formset errors
            print("=== VALIDATION ERRORS ===")
            if not form.is_valid():
                print(f"Form errors: {form.errors}")
            if not formset.is_valid():
                print(f"Formset errors: {formset.errors}")
                print(f"Formset non-form errors: {formset.non_form_errors()}")
                
                # Debug individual form errors
                for i, form_instance in enumerate(formset):
                    if form_instance.errors:
                        print(f"Form {i} errors: {form_instance.errors}")
                        print(f"Form {i} cleaned_data: {form_instance.cleaned_data if form_instance.is_valid() else 'Invalid'}")
                
    else:
        form = FreezingEntryTenantForm()
        formset = FreezingEntryTenantItemFormSet()
        
    return render(request, 'adminapp/tenant/create.html', {'form': form, 'formset': formset})

@transaction.atomic
@check_permission('freezing_edit')
def tenant_freezing_update(request, pk):
    entry = get_object_or_404(FreezingEntryTenant, pk=pk)
    if request.method == "POST":
        form = FreezingEntryTenantForm(request.POST, instance=entry)
        formset = FreezingEntryTenantItemFormSet(request.POST, instance=entry)
        if form.is_valid() and formset.is_valid():
            form.save()
            formset.save()

            totals = entry.items.aggregate(
                total_slab_sum=Sum('slab_quantity'),
                total_c_s_sum=Sum('c_s_quantity'),
                total_kg_sum=Sum('kg'),
            )
            entry.total_slab = totals['total_slab_sum'] or 0
            entry.total_c_s = totals['total_c_s_sum'] or 0
            entry.total_kg = totals['total_kg_sum'] or 0
            entry.total_amount = 0
            entry.save()

            return redirect(reverse('adminapp:list_freezing_entry_tenant'))
    else:
        form = FreezingEntryTenantForm(instance=entry)
        formset = FreezingEntryTenantItemFormSet(instance=entry)
    return render(request, 'adminapp/tenant/update.html', {'form': form, 'formset': formset})

@check_permission('freezing_delete')
def tenant_freezing_delete(request, pk):
    entry = get_object_or_404(FreezingEntryTenant, pk=pk)
    if request.method == "POST":
        entry.delete()
        return redirect('adminapp:list_freezing_entry_tenant')
    return render(request, 'adminapp/confirm_delete.html', {'entry': entry})

@check_permission('freezing_view')
def tenant_freezing_detail_pdf(request, pk):
    """
    Generate PDF for FreezingEntryTenant detail view
    """
    # Get the FreezingEntryTenant object
    entry = get_object_or_404(FreezingEntryTenant, pk=pk)
    
    # Get the PDF template
    template = get_template('adminapp/tenant/detail_pdf.html')
    
    # Context data for the template
    context = {
        'entry': entry,
        'items': entry.items.all(),
        'company_name': 'Your Company Name',  # Add your company name
        'company_address': 'Your Company Address',  # Add your company address
        'phone': 'Your Phone Number',  # Add your phone number
        'email': 'your-email@company.com',  # Add your email
    }
    
    # Render the template with context
    html = template.render(context)
    
    # Create a BytesIO buffer to receive PDF data
    buffer = io.BytesIO()
    
    # Generate PDF
    pdf = pisa.pisaDocument(io.BytesIO(html.encode("UTF-8")), buffer)
    
    if not pdf.err:
        # PDF generation successful
        buffer.seek(0)
        response = HttpResponse(buffer.read(), content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="freezing_entry_{entry.voucher_number}.pdf"'
        buffer.close()
        return response
    else:
        # PDF generation failed
        return HttpResponse("Error generating PDF", status=500)




# return_tenant views
@transaction.atomic
@check_permission('freezing_add')
def return_tenant_create(request):
    if request.method == "POST":
        form = ReturnTenantForm(request.POST)
        formset = ReturnTenantItemFormSet(request.POST)
        
        print("=== DEBUG FORMSET DATA ===")
        print(f"POST data keys: {list(request.POST.keys())}")
        print(f"Formset is_valid: {formset.is_valid()}")
        print(f"Form is_valid: {form.is_valid()}")
        print(f"Formset total forms: {formset.total_form_count()}")
        print(f"Formset errors: {formset.errors}")
        print(f"Formset non_form_errors: {formset.non_form_errors()}")
        
        if form.is_valid() and formset.is_valid():
            # Save the main entry first
            entry = form.save()
            print(f"Main entry saved with ID: {entry.id}")
            
            # Set the instance and save the formset
            formset.instance = entry
            saved_items = formset.save()
            print(f"Saved {len(saved_items)} items from formset")
            
            # Debug: Check what was actually saved
            for i, item in enumerate(saved_items):
                print(f"Item {i+1}: {item.item} - Slab: {item.slab_quantity} - CS: {item.c_s_quantity} - KG: {item.kg}")

            total_amount = Decimal("0.00")

            # Process each saved item for additional logic
            for item in saved_items:
                # Auto-link to stock lot if not already linked
                if not item.original_item:
                    original = FreezingEntryTenantItem.objects.filter(
                        item=item.item,
                        store=item.store,
                        freezing_entry__tenant_company_name=entry.tenant_company_name,
                        species=item.species,
                        grade=item.grade
                    ).order_by('-freezing_entry__freezing_date', '-id').first()
                    if original:
                        item.original_item = original
                        item.save()

                # Calculate amount based on tariff
                try:
                    tariff_obj = TenantFreezingTariff.objects.get(
                        tenant=entry.tenant_company_name,
                        category=item.freezing_category
                    )
                    tariff = Decimal(str(tariff_obj.tariff or 0))
                except TenantFreezingTariff.DoesNotExist:
                    tariff = Decimal("0.00")

                if item.kg:
                    total_amount += Decimal(str(item.kg)) * tariff

            # Update totals
            totals = entry.items.aggregate(
                total_slab_sum=Sum('slab_quantity'),
                total_c_s_sum=Sum('c_s_quantity'),
                total_kg_sum=Sum('kg'),
            )
            entry.total_slab = totals['total_slab_sum'] or 0
            entry.total_c_s = totals['total_c_s_sum'] or 0
            entry.total_kg = totals['total_kg_sum'] or 0
            entry.total_amount = total_amount
            entry.save()
            
            print(f"Updated totals - Slab: {entry.total_slab}, CS: {entry.total_c_s}, KG: {entry.total_kg}")

            messages.success(request, f'Return entry {entry.voucher_number} created successfully with {len(saved_items)} items!')
            return redirect(reverse('adminapp:list_return_tenant'))
        else:
            # Debug form and formset errors
            print("=== VALIDATION ERRORS ===")
            if not form.is_valid():
                print(f"Form errors: {form.errors}")
                messages.error(request, f'Form errors: {form.errors}')
            if not formset.is_valid():
                print(f"Formset errors: {formset.errors}")
                print(f"Formset non-form errors: {formset.non_form_errors()}")
                messages.error(request, f'Formset errors: {formset.errors}')
                
                # Debug individual form errors
                for i, form_instance in enumerate(formset):
                    if form_instance.errors:
                        print(f"Form {i} errors: {form_instance.errors}")
                        print(f"Form {i} cleaned_data: {form_instance.cleaned_data if form_instance.is_valid() else 'Invalid'}")
                
    else:
        form = ReturnTenantForm()
        formset = ReturnTenantItemFormSet()
        
    return render(request, 'adminapp/ReturnTenant/create.html', {
        'form': form,
        'formset': formset,
    })

@check_permission('freezing_view')
def get_tenant_tariff(request):
    """
    Get tariff rate for a specific tenant and freezing category combination
    """
    tenant_id = request.GET.get('tenant_id')
    freezing_category_id = request.GET.get('freezing_category_id')
    
    if not tenant_id or not freezing_category_id:
        return JsonResponse({
            'success': False, 
            'error': 'Both tenant_id and freezing_category_id are required',
            'tariff': 0
        })
    
    try:
        tariff_obj = TenantFreezingTariff.objects.get(
            tenant_id=tenant_id,
            category_id=freezing_category_id
        )
        
        return JsonResponse({
            'success': True,
            'tariff': float(tariff_obj.tariff or 0),
            'tenant_name': str(tariff_obj.tenant),
            'category_name': str(tariff_obj.category)
        })
        
    except TenantFreezingTariff.DoesNotExist:
        return JsonResponse({
            'success': False,
            'error': 'No tariff found for this tenant and freezing category combination',
            'tariff': 0
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e),
            'tariff': 0
        })


@check_permission('freezing_view')
def calculate_return_total_amount(request):
    """
    Calculate total amount based on current form data
    """
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'POST method required'})
    
    try:
        tenant_id = request.POST.get('tenant_id')
        items_data = []
        
        # Parse formset data
        form_count = int(request.POST.get('form-TOTAL_FORMS', 0))
        
        for i in range(form_count):
            # Skip deleted forms
            if request.POST.get(f'form-{i}-DELETE'):
                continue
                
            freezing_category_id = request.POST.get(f'form-{i}-freezing_category')
            kg_weight = request.POST.get(f'form-{i}-kg')
            
            if freezing_category_id and kg_weight:
                try:
                    kg_weight = Decimal(str(kg_weight))
                    if kg_weight > 0:
                        items_data.append({
                            'freezing_category_id': freezing_category_id,
                            'kg': kg_weight
                        })
                except (ValueError, TypeError):
                    continue
        
        if not tenant_id or not items_data:
            return JsonResponse({
                'success': True,
                'total_amount': 0.00,
                'item_amounts': []
            })
        
        total_amount = Decimal('0.00')
        item_amounts = []
        
        # Calculate amount for each item
        for item_data in items_data:
            try:
                tariff_obj = TenantFreezingTariff.objects.get(
                    tenant_id=tenant_id,
                    category_id=item_data['freezing_category_id']
                )
                tariff = Decimal(str(tariff_obj.tariff or 0))
                item_amount = item_data['kg'] * tariff
                total_amount += item_amount
                
                item_amounts.append({
                    'freezing_category_id': item_data['freezing_category_id'],
                    'kg': float(item_data['kg']),
                    'tariff': float(tariff),
                    'amount': float(item_amount)
                })
                
            except TenantFreezingTariff.DoesNotExist:
                # No tariff found - contribute 0 to total
                item_amounts.append({
                    'freezing_category_id': item_data['freezing_category_id'],
                    'kg': float(item_data['kg']),
                    'tariff': 0,
                    'amount': 0,
                    'error': 'No tariff found'
                })
        
        return JsonResponse({
            'success': True,
            'total_amount': float(total_amount),
            'item_amounts': item_amounts,
            'item_count': len(items_data)
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e),
            'total_amount': 0
        })

@check_permission('freezing_view')
def get_tenant_original_items(request):
    """
    AJAX view to get original items filtered by tenant company
    """
    tenant_id = request.GET.get('tenant_id')
    item_id = request.GET.get('item_id')  # For getting specific item details
    
    if not tenant_id and not item_id:
        return JsonResponse({'success': False, 'error': 'No tenant ID or item ID provided'})
    
    try:
        # If item_id is provided, return specific item details
        if item_id:
            try:
                item = FreezingEntryTenantItem.objects.select_related(
                    'item', 'species', 'grade', 'unit', 'freezing_category', 
                    'store', 'item_quality', 'glaze', 'brand', 'processing_center'
                ).get(id=item_id)
                
                return JsonResponse({
                    'success': True,
                    'item_name': str(item.item) if item.item else '',
                    'full_description': f"{item.item} - {item.species} - {item.grade}" if all([item.item, item.species, item.grade]) else str(item.item),
                    'item': item.item.id if item.item else None,
                    'store': item.store.id if item.store else None,
                    'item_quality': item.item_quality.id if item.item_quality else None,
                    'unit': item.unit.id if item.unit else None,
                    'species': item.species.id if item.species else None,
                    'grade': item.grade.id if item.grade else None,
                    'glaze': item.glaze.id if item.glaze else None,
                    'freezing_category': item.freezing_category.id if item.freezing_category else None,
                    'brand': item.brand.id if item.brand else None,
                    'processing_center': item.processing_center.id if item.processing_center else None,
                    'slab_quantity': float(item.slab_quantity) if item.slab_quantity else 0,
                    'kg': float(item.kg) if item.kg else 0,
                })
            except FreezingEntryTenantItem.DoesNotExist:
                return JsonResponse({'success': False, 'error': 'Item not found'})
        
        # Get tenant and filter original items
        try:
            # Get the tenant by ID
            from django.shortcuts import get_object_or_404
            tenant = get_object_or_404(Tenant, id=tenant_id)
        except:
            return JsonResponse({'success': False, 'error': 'Tenant not found'})
        
        # Filter original items by the selected tenant company
        original_items = FreezingEntryTenantItem.objects.filter(
            freezing_entry__tenant_company_name=tenant  # This filters by the tenant object
        ).select_related(
            'item', 'species', 'grade', 'unit', 'freezing_category',
            'freezing_entry'  # Added to access freezing_entry data
        ).order_by('-freezing_entry__freezing_date', '-id').distinct()
        
        items_data = []
        for item in original_items:
            # Create a descriptive display name for each item
            display_parts = []
            
            if item.item:
                display_parts.append(str(item.item))
            if item.species:
                display_parts.append(str(item.species))
            if item.grade:
                display_parts.append(str(item.grade))
            if item.unit:
                display_parts.append(f"({item.unit})")
            
            # Add quantities for reference
            quantities = []
            if item.slab_quantity:
                quantities.append(f"Slab: {item.slab_quantity}")
            if item.kg:
                quantities.append(f"KG: {item.kg}")
            
            if quantities:
                display_parts.append(f"[{', '.join(quantities)}]")
            
            # Add voucher number for better identification
            if item.freezing_entry and item.freezing_entry.voucher_number:
                display_parts.append(f"(Voucher: {item.freezing_entry.voucher_number})")
            
            display_name = " - ".join(display_parts) if display_parts else f"Item #{item.id}"
            
            items_data.append({
                'id': item.id,
                'display_name': display_name,
                'item_id': item.item.id if item.item else None,
                'item_name': str(item.item) if item.item else '',
                'species_name': str(item.species) if item.species else '',
                'grade_name': str(item.grade) if item.grade else '',
                'slab_quantity': float(item.slab_quantity) if item.slab_quantity else 0,
                'kg': float(item.kg) if item.kg else 0,
                'voucher_number': item.freezing_entry.voucher_number if item.freezing_entry else '',
            })
        
        return JsonResponse({
            'success': True,
            'items': items_data,
            'tenant_name': tenant.company_name,
            'count': len(items_data)
        })
        
    except Exception as e:
        print(f"Error in get_tenant_original_items: {str(e)}")
        return JsonResponse({'success': False, 'error': str(e)})

@transaction.atomic
@check_permission('freezing_edit')
def return_tenant_update(request, pk):
    entry = get_object_or_404(ReturnTenant, pk=pk)
    if request.method == "POST":
        form = ReturnTenantForm(request.POST, instance=entry)
        formset = ReturnTenantItemFormSet(request.POST, instance=entry)
        if form.is_valid() and formset.is_valid():
            form.save()
            formset.save()

            totals = entry.items.aggregate(
                total_slab_sum=Sum('slab_quantity'),
                total_c_s_sum=Sum('c_s_quantity'),
                total_kg_sum=Sum('kg'),
            )
            entry.total_slab = totals['total_slab_sum'] or 0
            entry.total_c_s = totals['total_c_s_sum'] or 0
            entry.total_kg = totals['total_kg_sum'] or 0
            entry.total_amount = 0
            entry.save()

            return redirect(reverse('adminapp:list_return_tenant'))
    else:
        form = ReturnTenantForm(instance=entry)
        formset = ReturnTenantItemFormSet(instance=entry)
    return render(request, 'adminapp/ReturnTenant/update.html', {'form': form, 'formset': formset})

@check_permission('freezing_delete')
def return_tenant_delete(request, pk):
    entry = get_object_or_404(ReturnTenant, pk=pk)
    if request.method == "POST":
        entry.delete()
        return redirect('adminapp:list_return_tenant')
    return render(request, 'adminapp/confirm_delete.html', {'entry': entry})

@check_permission('freezing_view')
def return_tenant_list(request):
    entries = ReturnTenant.objects.all().order_by('-return_date')
    return render(request, 'adminapp/ReturnTenant/list.html', {'entries': entries})

@check_permission('freezing_view')
def generate_return_tenant_pdf(request, pk):
    """
    Generate PDF for ReturnTenant detail view
    """
    # Get the ReturnTenant object
    entry = get_object_or_404(ReturnTenant, pk=pk)
    
    # Get the PDF template
    template = get_template('adminapp/ReturnTenant/pdf_detail.html')
    
    # Context data for the template
    context = {
        'entry': entry,
        'items': entry.items.all(),
        'company_name': 'Your Company Name',  # Add your company name
        'company_address': 'Your Company Address',  # Add your company address
        'phone': 'Your Phone Number',  # Add your phone number
        'email': 'your-email@company.com',  # Add your email
    }
    
    # Render the template with context
    html = template.render(context)
    
    # Create a BytesIO buffer to receive PDF data
    buffer = io.BytesIO()
    
    # Generate PDF
    pdf = pisa.pisaDocument(io.BytesIO(html.encode("UTF-8")), buffer)
    
    if not pdf.err:
        # PDF generation successful
        buffer.seek(0)
        response = HttpResponse(buffer.read(), content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="return_tenant_{entry.voucher_number}.pdf"'
        buffer.close()
        return response
    else:
        # PDF generation failed
        return HttpResponse("Error generating PDF", status=500)

@check_permission('freezing_view')
def return_tenant_detail(request, pk):
    """
    Updated detail view with PDF generation option
    """
    entry = get_object_or_404(ReturnTenant, pk=pk)
    
    # Check if PDF generation is requested
    if request.GET.get('format') == 'pdf':
        return generate_return_tenant_pdf(request, pk)
    
    return render(request, 'adminapp/ReturnTenant/detail.html', {'entry': entry})




# Tenant Stock Balance Views

@check_permission('reports_view')
def tenant_stock_balance(request):
    """
    Calculate current stock balance for all tenants
    """
    from django.db.models import Sum
    from collections import defaultdict
    
    # Get all freezing entries (INBOUND stock)
    freezing_data = FreezingEntryTenantItem.objects.select_related(
        'freezing_entry__tenant_company_name', 'item', 'species', 'grade', 'store'
    ).values(
        'freezing_entry__tenant_company_name__company_name',
        'freezing_entry__tenant_company_name__id',
        'item__name',
        'species__name',
        'grade__grade',
        'store__name'
    ).annotate(
        total_slab_in=Sum('slab_quantity'),
        total_cs_in=Sum('c_s_quantity'),
        total_kg_in=Sum('kg')
    )
    
    # Get all return entries (OUTBOUND stock)
    return_data = ReturnTenantItem.objects.select_related(
        'return_entry__tenant_company_name', 'item', 'species', 'grade', 'store'
    ).values(
        'return_entry__tenant_company_name__company_name',
        'return_entry__tenant_company_name__id',
        'item__name',
        'species__name',
        'grade__grade',
        'store__name'
    ).annotate(
        total_slab_out=Sum('slab_quantity'),
        total_cs_out=Sum('c_s_quantity'),
        total_kg_out=Sum('kg')
    )
    
    # Calculate balance for each tenant-item combination
    balance_data = defaultdict(lambda: {
        'slab_in': 0, 'cs_in': 0, 'kg_in': 0,
        'slab_out': 0, 'cs_out': 0, 'kg_out': 0,
        'slab_balance': 0, 'cs_balance': 0, 'kg_balance': 0
    })
    
    # Process inbound data
    for entry in freezing_data:
        key = (
            entry['freezing_entry__tenant_company_name__id'],
            entry['freezing_entry__tenant_company_name__company_name'],
            entry['item__name'],
            entry['species__name'],
            entry['grade__grade'],
            entry['store__name']
        )
        balance_data[key]['slab_in'] = entry['total_slab_in'] or 0
        balance_data[key]['cs_in'] = entry['total_cs_in'] or 0
        balance_data[key]['kg_in'] = entry['total_kg_in'] or 0
    
    # Process outbound data
    for entry in return_data:
        key = (
            entry['return_entry__tenant_company_name__id'],
            entry['return_entry__tenant_company_name__company_name'],
            entry['item__name'],
            entry['species__name'],
            entry['grade__grade'],
            entry['store__name']
        )
        balance_data[key]['slab_out'] = entry['total_slab_out'] or 0
        balance_data[key]['cs_out'] = entry['total_cs_out'] or 0
        balance_data[key]['kg_out'] = entry['total_kg_out'] or 0
    
    # Calculate final balances
    stock_balance = []
    for key, data in balance_data.items():
        tenant_id, tenant_name, item_name, species, grade, store = key
        
        slab_balance = data['slab_in'] - data['slab_out']
        cs_balance = data['cs_in'] - data['cs_out']
        kg_balance = data['kg_in'] - data['kg_out']
        
        # Only show items with remaining stock
        if slab_balance > 0 or cs_balance > 0 or kg_balance > 0:
            stock_balance.append({
                'tenant_id': tenant_id,
                'tenant_name': tenant_name,
                'item_name': item_name,
                'species': species,
                'grade': grade,
                'store': store,
                'slab_in': data['slab_in'],
                'cs_in': data['cs_in'], 
                'kg_in': data['kg_in'],
                'slab_out': data['slab_out'],
                'cs_out': data['cs_out'],
                'kg_out': data['kg_out'],
                'slab_balance': slab_balance,
                'cs_balance': cs_balance,
                'kg_balance': kg_balance,
            })
    
    # Sort by tenant name, then item name
    stock_balance.sort(key=lambda x: (x['tenant_name'], x['item_name']))
    
    context = {
        'stock_balance': stock_balance,
        'total_items': len(stock_balance)
    }
    return render(request, 'adminapp/TenantStock/balance.html', context)

@check_permission('reports_view')
def tenant_stock_detail(request, tenant_id):
    """
    Detailed stock view for a specific tenant
    """
    try:
        # Get the actual Tenant object, not ReturnTenant
        tenant = Tenant.objects.get(id=tenant_id)
    except Tenant.DoesNotExist:
        messages.error(request, 'Tenant not found.')
        return redirect('adminapp:tenant_stock_balance')
    
    # Get detailed freezing entries for this tenant
    freezing_entries = FreezingEntryTenantItem.objects.filter(
        freezing_entry__tenant_company_name=tenant
    ).select_related(
        'freezing_entry', 'item', 'species', 'grade', 'store', 'unit'
    ).order_by('-freezing_entry__freezing_date')
    
    # Get detailed return entries for this tenant
    return_entries = ReturnTenantItem.objects.filter(
        return_entry__tenant_company_name=tenant
    ).select_related(
        'return_entry', 'item', 'species', 'grade', 'store', 'unit'
    ).order_by('-return_entry__return_date')
    
    # Calculate totals
    freezing_totals = freezing_entries.aggregate(
        total_slab=Sum('slab_quantity'),
        total_cs=Sum('c_s_quantity'),
        total_kg=Sum('kg')
    )
    
    return_totals = return_entries.aggregate(
        total_slab=Sum('slab_quantity'),
        total_cs=Sum('c_s_quantity'), 
        total_kg=Sum('kg')
    )
    
    balance_totals = {
        'slab_balance': (freezing_totals['total_slab'] or 0) - (return_totals['total_slab'] or 0),
        'cs_balance': (freezing_totals['total_cs'] or 0) - (return_totals['total_cs'] or 0),
        'kg_balance': (freezing_totals['total_kg'] or 0) - (return_totals['total_kg'] or 0),
    }
    
    context = {
        'tenant': tenant,
        'freezing_entries': freezing_entries,
        'return_entries': return_entries,
        'freezing_totals': freezing_totals,
        'return_totals': return_totals,
        'balance_totals': balance_totals,
    }
    return render(request, 'adminapp/TenantStock/detail.html', context)

@check_permission('reports_view')
def get_tenant_companies(request):
    """
    Fixed: Get tenant companies properly
    """
    try:
        # Get unique tenant companies from FreezingEntryTenant
        # Assuming FreezingEntryTenant has a foreign key to TenantCompany
        tenants = (
            FreezingEntryTenant.objects
            .values('tenant_company_name__id', 'tenant_company_name__company_name')
            .distinct()
            .order_by('tenant_company_name__company_name')
        )
        
        data = [{"id": t['tenant_company_name__id'], "name": t['tenant_company_name__company_name']} 
                for t in tenants if t['tenant_company_name__id'] is not None]
        
        return JsonResponse({"tenants": data})
    
    except Exception as e:
        print(f"Error in get_tenant_companies: {str(e)}")
        # Fallback: Get all tenant companies
        try:
            all_tenants = FreezingEntryTenant.objects.all().order_by('company_name')
            data = [{"id": t.id, "name": t.company_name} for t in all_tenants]
            return JsonResponse({"tenants": data})
        except Exception as e2:
            print(f"Fallback error in get_tenant_companies: {str(e2)}")
            return JsonResponse({"tenants": []})

@check_permission('reports_view')
def tenant_stock_summary(request):
    """
    Summary view showing total stock per tenant
    """
    tenants = Tenant.objects.all()  # Get all tenants, not ReturnTenant objects
    tenant_summary = []
    
    for tenant in tenants:
        # Calculate totals for this tenant
        freezing_totals = FreezingEntryTenantItem.objects.filter(
            freezing_entry__tenant_company_name=tenant
        ).aggregate(
            total_slab=Sum('slab_quantity'),
            total_cs=Sum('c_s_quantity'),
            total_kg=Sum('kg')
        )
        
        return_totals = ReturnTenantItem.objects.filter(
            return_entry__tenant_company_name=tenant  # Fixed: return_entry instead of return_tenant
        ).aggregate(
            total_slab=Sum('slab_quantity'),
            total_cs=Sum('c_s_quantity'),
            total_kg=Sum('kg')
        )
        
        slab_balance = (freezing_totals['total_slab'] or 0) - (return_totals['total_slab'] or 0)
        cs_balance = (freezing_totals['total_cs'] or 0) - (return_totals['total_cs'] or 0)
        kg_balance = (freezing_totals['total_kg'] or 0) - (return_totals['total_kg'] or 0)
        
        # Count unique items
        item_count = FreezingEntryTenantItem.objects.filter(
            freezing_entry__tenant_company_name=tenant
        ).values('item', 'species', 'grade').distinct().count()
        
        tenant_summary.append({
            'tenant': tenant,
            'freezing_totals': freezing_totals,
            'return_totals': return_totals,
            'slab_balance': slab_balance,
            'cs_balance': cs_balance,
            'kg_balance': kg_balance,
            'item_count': item_count,
            'has_stock': slab_balance > 0 or cs_balance > 0 or kg_balance > 0
        })
    
    context = {
        'tenant_summary': tenant_summary,
    }
    return render(request, 'adminapp/TenantStock/summary.html', context)


def create_tenant_bill(tenant, from_date, to_date):
    """
    Create a TenantBill and items from freezing entries between from_date and to_date.
    Calculation is tariff × kg (not per-day).
    Returns the created or existing bill, or None if nothing to bill.
    """
    # avoid duplicates for exact period
    existing = TenantBill.objects.filter(
        tenant=tenant, from_date=from_date, to_date=to_date
    ).first()
    if existing:
        logger.info(f"Bill already exists for {tenant} {from_date} to {to_date}")
        return existing

    entries = FreezingEntryTenant.objects.filter(
        tenant_company_name=tenant,
        freezing_date__gte=from_date,
        freezing_date__lte=to_date,
        freezing_status="complete",
    ).prefetch_related("items")

    if not entries.exists():
        logger.info(f"No freezing entries for {tenant} between {from_date} and {to_date}")
        return None

    bill = TenantBill.objects.create(
        tenant=tenant,
        from_date=from_date,
        to_date=to_date,
    )

    totals = {"amount": Decimal("0.00"), "slabs": 0, "cs": 0, "kg": Decimal("0.00")}
    items_created = 0

    for entry in entries:
        for item in entry.items.all():
            try:
                tariff_obj = TenantFreezingTariff.objects.get(
                    tenant=tenant, category=item.freezing_category
                )
                tariff = Decimal(str(tariff_obj.tariff))
            except TenantFreezingTariff.DoesNotExist:
                logger.warning(f"No tariff for {tenant} - {item.freezing_category}; using 0.00")
                tariff = Decimal("0.00")

            # quantity
            kg_quantity = Decimal(str(getattr(item, "kg", 0)))

            # ✅ only tariff × kg
            line_total = tariff * kg_quantity

            TenantBillItem.objects.create(
                bill=bill,
                freezing_entry=entry,
                freezing_entry_item=item,
                slab_quantity=getattr(item, "slab_quantity", 0),
                c_s_quantity=getattr(item, "c_s_quantity", 0),
                kg_quantity=kg_quantity,
                days_stored=0,             # optional placeholder
                tariff_per_day=tariff,     # actually "tariff", no per-day calc
                line_total=line_total,
            )

            totals["amount"] += line_total
            totals["slabs"] += getattr(item, "slab_quantity", 0) or 0
            totals["cs"] += getattr(item, "c_s_quantity", 0) or 0
            totals["kg"] += kg_quantity
            items_created += 1

    # update totals on bill
    bill.total_amount = totals["amount"]
    bill.total_slabs = totals["slabs"]
    bill.total_c_s = totals["cs"]
    bill.total_kg = totals["kg"]
    bill.save()

    logger.info(f"Created bill {bill.pk} ({items_created} items) for tenant {tenant}")
    return bill

def auto_generate_bills():
    """
    Generate bills for all TenantBillingConfiguration entries that are due.
    Returns (generated_bills_list, errors_list)
    """
    today = timezone.now().date()
    configs_due = TenantBillingConfiguration.objects.filter(is_active=True, next_bill_date__lte=today)
    generated = []
    errors = []

    for config in configs_due:
        try:
            from_date = (config.last_bill_generated_date + timedelta(days=1)) if config.last_bill_generated_date else config.billing_start_date
            to_date = today

            if from_date > to_date:
                logger.warning(f"Skipping {config.tenant}: from_date {from_date} > to_date {to_date}")
                continue

            bill = create_tenant_bill(config.tenant, from_date, to_date)
            if bill:
                generated.append(bill)
                # update config
                config.last_bill_generated_date = to_date
                config.next_bill_date = to_date + timedelta(days=config.billing_frequency_days)
                config.save()
        except Exception as e:
            logger.exception(f"Auto billing error for {config.tenant}: {e}")
            errors.append(f"{config.tenant}: {str(e)}")

    return generated, errors

def run_auto_billing(request):
    """
    Trigger auto billing manually.
    If POST contains config_id -> generate only for that config.
    Otherwise generate for all due configs.
    """
    if request.method == 'POST':
        config_id = request.POST.get('config_id')
        if config_id:
            config = get_object_or_404(TenantBillingConfiguration, id=config_id)
            today = timezone.now().date()
            from_date = (config.last_bill_generated_date + timedelta(days=1)) if config.last_bill_generated_date else config.billing_start_date
            bill = create_tenant_bill(config.tenant, from_date, today)
            if bill:
                config.last_bill_generated_date = today
                config.next_bill_date = today + timedelta(days=config.billing_frequency_days)
                config.save()
                messages.success(request, f"Generated bill {getattr(bill, 'bill_number', bill.id)} for {config.tenant}")
            else:
                messages.warning(request, f"No freezing entries found for {config.tenant}")
        else:
            bills, errors = auto_generate_bills()
            if bills:
                messages.success(request, f"Generated {len(bills)} bills.")
            else:
                messages.info(request, "No bills generated. No due configurations found.")
            for e in errors:
                messages.error(request, e)
    return redirect('adminapp:billing_config_list')



@check_permission('billing_view')
def bill_list(request):
    bills = TenantBill.objects.select_related('tenant').order_by('-created_at')
    return render(request, 'adminapp/billing/bill_list.html', {'bills': bills})

@check_permission('billing_add')
def generate_manual_bill(request):
    """Form to generate bill for chosen tenant and date range"""
    if request.method == 'POST':
        form = BillGenerationForm(request.POST)
        if form.is_valid():
            tenant = form.cleaned_data['tenant']
            from_date = form.cleaned_data['from_date']
            to_date = form.cleaned_data['to_date']

            bill = create_tenant_bill(tenant, from_date, to_date)
            if bill:
                messages.success(request, f"Bill {getattr(bill, 'bill_number', bill.id)} created successfully.")
                return redirect('adminapp:view_bill', bill_id=bill.id)
            else:
                messages.warning(request, "No freezing entries found for selected period.")
    else:
        tenant_id = request.GET.get("tenant_id")
        initial = {}
        if tenant_id:
            from adminapp.models import TenantBill  # adjust if different app name
            try:
                last_bill = TenantBill.objects.filter(tenant_id=tenant_id).order_by('-to_date').first()
                if last_bill:
                    # Set next start date = last bill end date + 1 day
                    initial['from_date'] = last_bill.to_date + timedelta(days=1)
            except TenantBill.DoesNotExist:
                pass

        form = BillGenerationForm(initial=initial)

    return render(request, 'adminapp/billing/generate_manual_bill.html', {'form': form})

@check_permission('billing_view')
def view_bill(request, bill_id):
    bill = get_object_or_404(TenantBill, id=bill_id)
    items = bill.items.select_related('freezing_entry', 'freezing_entry_item').all()
    return render(request, 'adminapp/billing/view_bill.html', {'bill': bill, 'items': items})

@check_permission('billing_edit')
def update_bill_status(request, bill_id):
    if request.method == 'POST':
        bill = get_object_or_404(TenantBill, id=bill_id)
        new_status = request.POST.get('status')
        if new_status in dict(TenantBill.BILL_STATUS_CHOICES):
            bill.status = new_status
            bill.save()
            messages.success(request, f"Bill {bill.bill_number} status updated to {new_status}")
    return redirect('adminapp:view_bill', bill_id=bill_id)

@check_permission('billing_delete')
def delete_bill(request, bill_id):
    bill = get_object_or_404(TenantBill, id=bill_id)
    if request.method == 'POST':
        if bill.status == 'paid':
            messages.error(request, 'Cannot delete a paid bill.')
            return redirect('adminapp:view_bill', bill_id=bill.id)
        bill_number = bill.bill_number
        bill.delete()
        messages.success(request, f'Bill {bill_number} deleted successfully.')
        return redirect('adminapp:bill_list')
    # GET -> confirmation page
    return render(request, 'adminapp/billing/confirm_delete.html', {'bill': bill, 'bill_items_count': bill.items.count()})

@check_permission('billing_delete')
def delete_bill_ajax(request, bill_id):
    if request.method == 'POST':
        bill = get_object_or_404(TenantBill, id=bill_id)
        if bill.status == 'paid':
            return JsonResponse({'success': False, 'message': 'Cannot delete paid bill'}, status=400)
        bill.delete()
        return JsonResponse({'success': True, 'message': 'Bill deleted'})
    return JsonResponse({'success': False, 'message': 'Invalid request'}, status=405)

@check_permission('billing_view')
def billing_config_list(request):
    configs = TenantBillingConfiguration.objects.select_related('tenant').all()
    today = timezone.now().date()
    return render(request, 'adminapp/billing/config_list.html', {'configs': configs, 'today': today})

@check_permission('billing_add')
def setup_billing_configuration(request):
    if request.method == 'POST':
        form = TenantBillingConfigurationForm(request.POST)
        if form.is_valid():
            config = form.save()
            messages.success(request, f'Billing configuration created for {config.tenant}')
            return redirect('adminapp:billing_config_list')
    else:
        form = TenantBillingConfigurationForm()
    return render(request, 'adminapp/billing/setup_config.html', {'form': form})

@check_permission('billing_view')
def debug_billing_status(request):
    today = timezone.now().date()
    all_configs = TenantBillingConfiguration.objects.select_related('tenant').all()
    configs_due = TenantBillingConfiguration.objects.filter(is_active=True, next_bill_date__lte=today)

    debug_data = {
        'system_status': {
            'current_date': str(today),
            'total_configs': all_configs.count(),
            'active_configs': all_configs.filter(is_active=True).count(),
            'configs_due': configs_due.count(),
        },
        'configurations': []
    }

    for config in all_configs:
        from_date = (config.last_bill_generated_date + timedelta(days=1)) if config.last_bill_generated_date else config.billing_start_date
        freezing_count = FreezingEntryTenant.objects.filter(
            tenant_company_name=config.tenant,
            freezing_date__range=(from_date, today),
            freezing_status='complete'
        ).count()
        debug_data['configurations'].append({
            'tenant': config.tenant.company_name,
            'is_active': config.is_active,
            'billing_start_date': str(config.billing_start_date),
            'billing_frequency_days': config.billing_frequency_days,
            'last_bill_generated_date': str(config.last_bill_generated_date) if config.last_bill_generated_date else None,
            'next_bill_date': str(config.next_bill_date),
            'is_due': config.is_active and config.next_bill_date <= today,
            'calculated_from_date': str(from_date),
            'freezing_entries_available': freezing_count,
        })

    if request.GET.get('format') == 'json':
        return JsonResponse(debug_data, indent=2)

    # simple HTML fallback
    html = ["<h2>Billing Debug Info</h2>"]
    html.append(f"<p>Today: {today}</p>")
    html.append(f"<p>Total Configs: {debug_data['system_status']['total_configs']}</p>")
    html.append(f"<p>Active Configs: {debug_data['system_status']['active_configs']}</p>")
    html.append(f"<p>Due Configs: {debug_data['system_status']['configs_due']}</p>")
    html.append("<hr><ul>")
    for c in debug_data['configurations']:
        html.append(f"<li>{c['tenant']} → Active: {c['is_active']}, Due: {c['is_due']}, Next: {c['next_bill_date']}, Entries: {c['freezing_entries_available']}</li>")
    html.append("</ul>")
    return HttpResponse(''.join(html))

@check_permission('billing_delete')
def delete_billing_configuration(request, pk):
    config = get_object_or_404(TenantBillingConfiguration, pk=pk)
    if request.method == 'POST':
        tenant_name = config.tenant.company_name
        config.delete()
        messages.success(request, f'Billing configuration for {tenant_name} deleted successfully.')
        return redirect('adminapp:billing_config_list')
    return render(request, 'adminapp/billing/delete_confirm.html', {'config': config})

@check_permission('billing_view')
def get_last_bill_date(request):
    tenant_id = request.GET.get("tenant_id")
    if not tenant_id:
        return JsonResponse({"success": False, "error": "No tenant_id given"})

    last_bill = TenantBill.objects.filter(tenant_id=tenant_id).order_by('-to_date').first()
    if last_bill:
        next_from_date = last_bill.to_date + timedelta(days=1)
        return JsonResponse({
            "success": True,
            "last_to_date": last_bill.to_date,
            "next_from_date": next_from_date
        })
    return JsonResponse({"success": False, "error": "No bills found"})


def render_to_pdf(template_src, context_dict={}):
    """
    Utility function to render a template to PDF using xhtml2pdf.
    """
    template = get_template(template_src)
    html = template.render(context_dict)
    response = HttpResponse(content_type="application/pdf")
    response["Content-Disposition"] = 'attachment; filename="bill.pdf"'
    pisa.CreatePDF(html, dest=response)
    return response

@check_permission('billing_view')
def bill_pdf(request, bill_id):
    """
    Generate PDF for a TenantBill with grouped categories and qualities.
    """
    bill = get_object_or_404(TenantBill, id=bill_id)

    # Use the correct related_name from your TenantBillItem model (likely "items")
    items = bill.items.select_related("freezing_entry_item").all()

    categories_dict = defaultdict(lambda: {
        "name": None,
        "number": 0,
        "qualities": defaultdict(lambda: {
            "kg_quantity": Decimal("0"),
            "line_total": Decimal("0"),
            "tariff_per_day": Decimal("0"),
            "count": 0,
        }),
        "total_kg": Decimal("0"),
        "total_amount": Decimal("0"),
    })

    for item in items:
        category_obj = item.freezing_entry_item.freezing_category
        category_name = str(category_obj) if category_obj else "Uncategorized"
        item_quality = item.freezing_entry_item.item_quality or "N/A"

        if not categories_dict[category_name]["name"]:
            categories_dict[category_name]["name"] = category_obj or category_name

        # Group by quality
        quality_data = categories_dict[category_name]["qualities"][item_quality]
        quality_data["kg_quantity"] += Decimal(str(item.kg_quantity))
        quality_data["line_total"] += Decimal(str(item.line_total))
        quality_data["count"] += 1

        # Weighted avg tariff
        if quality_data["tariff_per_day"] == Decimal("0"):
            quality_data["tariff_per_day"] = Decimal(str(item.tariff_per_day))
        else:
            total_tariff = (
                quality_data["tariff_per_day"] * (quality_data["count"] - 1)
                + Decimal(str(item.tariff_per_day))
            )
            quality_data["tariff_per_day"] = total_tariff / quality_data["count"]

        # Category totals
        categories_dict[category_name]["total_kg"] += Decimal(str(item.kg_quantity))
        categories_dict[category_name]["total_amount"] += Decimal(str(item.line_total))

    # Convert to structured list for template
    categories = []
    category_number = 1
    for category_name, category_data in categories_dict.items():
        merged_items = []
        for quality, quality_data in category_data["qualities"].items():
            merged_items.append({
                "freezing_entry_item": {
                    "item_quality": quality
                },
                "kg_quantity": quality_data["kg_quantity"],
                "tariff_per_day": quality_data["tariff_per_day"],
                "line_total": quality_data["line_total"],
            })

        categories.append({
            "number": category_number,
            "name": category_name,  # stringified category name
            "items": merged_items,
            "total_kg": category_data["total_kg"],
            "total_amount": category_data["total_amount"],
        })
        category_number += 1

    # Sort categories by their name (string)
    categories.sort(key=lambda x: str(x["name"]))

    context = {
        "bill": bill,
        "categories": categories,
        "items": items,  # keep original items for fallback rendering
    }

    return render_to_pdf("adminapp/billing/bill_pdf.html", context)


@check_permission('billing_view')
def bill_list_by_status(request, status):
    """Generic view to list bills by status."""
    bills = TenantBill.objects.filter(status=status).select_related("tenant").order_by("-created_at")
    return render(request, f"adminapp/billing/bill_list_{status}.html", {
        "bills": bills,
        "status": status,
    })

@check_permission('billing_view')
def bill_list_draft(request):
    return bill_list_by_status(request, "draft")

# def bill_list_finalized(request):
#     return bill_list_by_status(request, "finalized")

# def bill_list_sent(request):
#     return bill_list_by_status(request, "sent")

# def bill_list_paid(request):
#     return bill_list_by_status(request, "paid")

# def bill_list_cancelled(request):
#     return bill_list_by_status(request, "cancelled")





# Create a simple formset (not inline)
StoreTransferItemFormSet = formset_factory(
    StoreTransferItemForm, 
    extra=0, 
    can_delete=True
)


def process_stock_transfer(transfer, transfer_item):
    """Process stock transfer between stores"""
    try:
        cs_qty = transfer_item.cs_quantity or 0
        kg_qty = transfer_item.kg_quantity or 0
        
        if cs_qty <= 0 and kg_qty <= 0:
            return
            
        # Find source stock
        source_stock = Stock.objects.filter(
            store=transfer.from_store,
            item=transfer_item.item,
            brand=transfer_item.brand,
            item_quality=transfer_item.item_quality,
            freezing_category=transfer_item.freezing_category,
            unit=transfer_item.unit,
            glaze=transfer_item.glaze,
            species=transfer_item.species,
            item_grade=transfer_item.item_grade,
        ).first()
        
        if not source_stock:
            print(f"WARNING: No source stock found for {transfer_item.item}")
            return
            
        # Check sufficient stock
        if (source_stock.cs_quantity or 0) < cs_qty:
            raise ValueError(f"Insufficient CS quantity for {transfer_item.item}. Required: {cs_qty}, Available: {source_stock.cs_quantity}")
        if (source_stock.kg_quantity or 0) < kg_qty:
            raise ValueError(f"Insufficient KG quantity for {transfer_item.item}. Required: {kg_qty}, Available: {source_stock.kg_quantity}")
        
        # Deduct from source
        source_stock.cs_quantity = (source_stock.cs_quantity or 0) - cs_qty
        source_stock.kg_quantity = (source_stock.kg_quantity or 0) - kg_qty
        source_stock.save()
        print(f"Updated source stock: {source_stock}")
        
        # Add to destination
        dest_stock, created = Stock.objects.get_or_create(
            store=transfer.to_store,
            item=transfer_item.item,
            brand=transfer_item.brand,
            item_quality=transfer_item.item_quality,
            freezing_category=transfer_item.freezing_category,
            unit=transfer_item.unit,
            glaze=transfer_item.glaze,
            species=transfer_item.species,
            item_grade=transfer_item.item_grade,
            defaults={'cs_quantity': 0, 'kg_quantity': 0}
        )
        
        dest_stock.cs_quantity = (dest_stock.cs_quantity or 0) + cs_qty
        dest_stock.kg_quantity = (dest_stock.kg_quantity or 0) + kg_qty
        dest_stock.save()
        print(f"Updated dest stock: {dest_stock} (created: {created})")
        
    except Exception as e:
        print(f"Stock transfer error: {str(e)}")
        raise

@login_required
def get_stock_by_store(request):
    store_id = request.GET.get("store_id")
    if not store_id:
        return JsonResponse({"stocks": []})

    stocks = Stock.objects.filter(store_id=store_id).select_related(
        "item", "brand", "category", "item_quality", "freezing_category",
        "unit", "glaze", "species", "item_grade"
    )

    stocks_list = []
    for s in stocks:
        stocks_list.append({
            "stock_id": s.id,
            "item_id": s.item.id,
            "item_name": s.item.name,
            "brand_id": s.brand.id,
            "brand_name": s.brand.name,
            "category_id": s.category.id,
            "category_name": s.category.name,
            "quality_id": s.item_quality.id if s.item_quality else None,
            "quality_name": s.item_quality.name if s.item_quality else None,
            "freezing_category_id": s.freezing_category.id if s.freezing_category else None,
            "freezing_category_name": s.freezing_category.name if s.freezing_category else None,
            "unit_id": s.unit.id if s.unit else None,
            "unit_name": s.unit.description if s.unit else None,
            "glaze_id": s.glaze.id if s.glaze else None,
            "glaze_name": s.glaze.name if s.glaze else None,
            "species_id": s.species.id if s.species else None,
            "species_name": s.species.name if s.species else None,
            "grade_id": s.item_grade.id if s.item_grade else None,
            "grade_name": s.item_grade.name if s.item_grade else None,
            "cs_quantity": float(s.cs_quantity),
            "kg_quantity": float(s.kg_quantity),
        })

    return JsonResponse({"stocks": stocks_list})

# API endpoint to get available stock for validation
def get_available_stock(request):
    """API endpoint to check available stock for transfer validation"""
    store_id = request.GET.get('store_id')
    item_id = request.GET.get('item_id')
    item_grade_id = request.GET.get('item_grade_id')
    
    if not all([store_id, item_id, item_grade_id]):
        return JsonResponse({'error': 'Missing parameters'}, status=400)
    
    try:
        stock = Stock.objects.get(
            store_id=store_id,
            item_id=item_id,
            item_grade_id=item_grade_id
        )
        
        return JsonResponse({
            'success': True,
            'cs_qty': float(stock.cs_qty),
            'kg_qty': float(stock.kg_qty),
            'rate': float(stock.rate)
        })
        
    except Stock.DoesNotExist:
        return JsonResponse({
            'success': False,
            'error': 'Stock not found',
            'cs_qty': 0,
            'kg_qty': 0
        })
    
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)



class StoreTransferListView(LoginRequiredMixin,CustomPermissionMixin,ListView):
    permission_required = 'adminapp.shipping_view'
    """List all store transfers"""
    model = StoreTransfer
    template_name = 'adminapp/transfer_list.html'
    context_object_name = 'transfers'
    paginate_by = 20
    ordering = ['-date', '-id']
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = 'Store Transfers'
        return context

@login_required
@check_permission('shipping_view')
def create_store_transfer(request):
    if request.method == 'POST':
        form = StoreTransferForm(request.POST)
        formset = StoreTransferItemFormSet(request.POST)
        
        # DEBUG: Print all formset-related POST data
        print("=== FULL POST DATA DEBUG ===")
        for key, value in request.POST.items():
            print(f"{key}: {value}")
        print("=== END POST DATA DEBUG ===")
        
        print("=== FORMSET DEBUG ===")
        print("TOTAL_FORMS:", request.POST.get('form-TOTAL_FORMS'))
        print("INITIAL_FORMS:", request.POST.get('form-INITIAL_FORMS'))
        print("Form is valid:", form.is_valid())
        print("Formset is valid:", formset.is_valid())
        
        if not form.is_valid():
            print("Form errors:", form.errors)
            
        if not formset.is_valid():
            print("Formset errors:", formset.errors)
            print("Non-form errors:", formset.non_form_errors())
            
            # Debug each form in formset
            for i, item_form in enumerate(formset):
                if item_form.errors:
                    print(f"Item form {i} errors:", item_form.errors)

        if form.is_valid() and formset.is_valid():
            try:
                with transaction.atomic():
                    # Save the transfer
                    transfer = form.save()
                    print(f"Transfer saved: {transfer}")
                    
                    items_saved = 0
                    
                    # Process each form in the formset
                    for i, item_form in enumerate(formset):
                        if item_form.cleaned_data and not item_form.cleaned_data.get('DELETE', False):
                            # Check if item is selected and has quantity
                            item = item_form.cleaned_data.get('item')
                            cs_quantity = item_form.cleaned_data.get('cs_quantity', 0) or 0
                            kg_quantity = item_form.cleaned_data.get('kg_quantity', 0) or 0
                            
                            print(f"Processing item form {i}: Item={item}, CS={cs_quantity}, KG={kg_quantity}")
                            
                            if item and (cs_quantity > 0 or kg_quantity > 0):
                                # Create transfer item manually since this isn't an inline formset
                                transfer_item = StoreTransferItem(
                                    transfer=transfer,
                                    item=item,
                                    brand=item_form.cleaned_data.get('brand'),
                                    item_quality=item_form.cleaned_data.get('item_quality'),
                                    freezing_category=item_form.cleaned_data.get('freezing_category'),
                                    unit=item_form.cleaned_data.get('unit'),
                                    glaze=item_form.cleaned_data.get('glaze'),
                                    species=item_form.cleaned_data.get('species'),
                                    item_grade=item_form.cleaned_data.get('item_grade'),
                                    cs_quantity=cs_quantity,
                                    kg_quantity=kg_quantity,
                                )
                                transfer_item.save()
                                items_saved += 1
                                
                                print(f"Saved transfer item {items_saved}: {transfer_item}")
                                
                                # Process stock transfer
                                process_stock_transfer(transfer, transfer_item)
                            else:
                                print(f"Skipping item form {i}: no item or no quantity")
                    
                    if items_saved > 0:
                        messages.success(request, f"Transfer created successfully with {items_saved} items!")
                        return redirect('adminapp:store_transfer_list')
                    else:
                        transfer.delete()
                        messages.error(request, "No valid items were added to the transfer.")
                        
            except Exception as e:
                print(f"Error creating transfer: {str(e)}")
                messages.error(request, f"Error creating transfer: {str(e)}")
        else:
            messages.error(request, "Please correct the errors below.")
    else:
        # GET request
        form = StoreTransferForm()
        formset = StoreTransferItemFormSet()

    return render(request, "adminapp/create_transfer.html", {
        "form": form, 
        "formset": formset
    })


@login_required
@check_permission('shipping_view')
def transfer_detail(request, pk):
    """View transfer details"""
    transfer = get_object_or_404(StoreTransfer, pk=pk)
    items = StoreTransferItem.objects.filter(transfer=transfer).select_related(
        'item', 'brand', 'item_quality', 'species', 'item_grade', 'freezing_category'
    )
    
    context = {
        'transfer': transfer,
        'items': items,
        'title': f'Transfer Details - {transfer.voucher_no}'
    }
    return render(request, 'adminapp/transfer_detail.html', context)


@login_required
@require_http_methods(["POST"])
@check_permission('shipping_delete')
def delete_transfer(request, pk):
    """Delete a store transfer and its items"""
    transfer = get_object_or_404(StoreTransfer, pk=pk)
    transfer_no = transfer.voucher_no

    try:
        transfer.delete()  # This will also delete related StoreTransferItem if on_delete=CASCADE

        if request.headers.get("Content-Type") == "application/json":
            return JsonResponse({
                "success": True,
                "message": f'Transfer "{transfer_no}" deleted successfully.'
            })
        else:
            messages.success(request, f'Transfer "{transfer_no}" deleted successfully.')
            return redirect("adminapp:transfer_list")

    except Exception as e:
        if request.headers.get("Content-Type") == "application/json":
            return JsonResponse({
                "success": False,
                "message": f"Error deleting transfer: {str(e)}"
            }, status=500)
        else:
            messages.error(request, f"Error deleting transfer: {str(e)}")
            return redirect("adminapp:store_transfer_list")


@login_required
@require_http_methods(["GET"])
@check_permission('shipping_view')
def get_stock_details(request):
    stock_id = request.GET.get('stock_id')
    
    if not stock_id:
        return JsonResponse({'success': False, 'error': 'Stock ID required'})
    
    try:
        # ONLY use confirmed relational fields from the error message:
        # store, category, brand, item, item_quality, freezing_category, source_spot_entry, source_local_entry
        
        stock = Stock.objects.select_related(
            'store',
            'category', 
            'brand', 
            'item', 
            'item_quality', 
            'freezing_category'
        ).get(id=stock_id)
        
        # Build the response based on actual model fields
        stock_details = {
            'category_id': stock.category.id if stock.category else None,
            'brand_id': stock.brand.id if stock.brand else None,
            'item_id': stock.item.id if stock.item else None,
            'item_quality_id': stock.item_quality.id if stock.item_quality else None,
            'freezing_category_id': stock.freezing_category.id if stock.freezing_category else None,
        }
        
        # Handle non-relational fields safely
        # These might be direct CharField/IntegerField values, not relationships
        if hasattr(stock, 'species') and stock.species:
            stock_details['species'] = str(stock.species)
            
        if hasattr(stock, 'glaze') and stock.glaze:
            stock_details['glaze'] = str(stock.glaze)
            
        if hasattr(stock, 'grade') and stock.grade:
            stock_details['grade'] = str(stock.grade)
            
        if hasattr(stock, 'item_grade') and stock.item_grade:
            stock_details['item_grade'] = str(stock.item_grade)
            
        if hasattr(stock, 'unit') and stock.unit:
            stock_details['unit'] = str(stock.unit)
        
        return JsonResponse({
            'success': True,
            'stock_details': stock_details
        })
        
    except Stock.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Stock not found'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': f'Error: {str(e)}'})


# Alternative version if you want to inspect your model first
@login_required
@require_http_methods(["GET"])
def get_stock_details_debug(request):
    """Debug version to see what fields are available"""
    stock_id = request.GET.get('stock_id')
    
    if not stock_id:
        return JsonResponse({'success': False, 'error': 'Stock ID required'})
    
    try:
        # Get stock without select_related first
        stock = Stock.objects.get(id=stock_id)
        
        # Get all field names
        field_names = [f.name for f in stock._meta.get_fields()]
        related_fields = [f.name for f in stock._meta.get_fields() if f.is_relation]
        
        # Build response with available fields
        stock_details = {}
        
        # Check each possible field
        for field_name in ['category', 'brand', 'item', 'item_quality', 'freezing_category', 'unit', 'glaze']:
            if hasattr(stock, field_name):
                try:
                    field_value = getattr(stock, field_name)
                    if field_value and hasattr(field_value, 'id'):
                        stock_details[f'{field_name}_id'] = field_value.id
                    elif field_value:
                        stock_details[field_name] = str(field_value)
                except:
                    pass
        
        # Check for direct value fields
        for field_name in ['species', 'item_grade', 'grade']:
            if hasattr(stock, field_name):
                try:
                    field_value = getattr(stock, field_name)
                    if field_value:
                        stock_details[field_name] = str(field_value)
                except:
                    pass
        
        return JsonResponse({
            'success': True,
            'stock_details': stock_details,
            'debug_info': {
                'all_fields': field_names,
                'related_fields': related_fields
            }
        })
        
    except Stock.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Stock not found'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})


# Simplified version focusing on known working fields
@login_required
@require_http_methods(["GET"])
def get_stock_details_simple(request):
    stock_id = request.GET.get('stock_id')
    
    if not stock_id:
        return JsonResponse({'success': False, 'error': 'Stock ID required'})
    
    try:
        # Only use the confirmed working related fields
        stock = Stock.objects.select_related(
            'category',
            'brand', 
            'item', 
            'item_quality', 
            'freezing_category'
        ).get(id=stock_id)
        
        stock_details = {
            'category_id': stock.category.id if stock.category else None,
            'brand_id': stock.brand.id if stock.brand else None,
            'item_id': stock.item.id if stock.item else None,
            'item_quality_id': stock.item_quality.id if stock.item_quality else None,
            'freezing_category_id': stock.freezing_category.id if stock.freezing_category else None,
        }
        
        return JsonResponse({
            'success': True,
            'stock_details': stock_details
        })
        
    except Stock.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Stock not found'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})





class StockListView(LoginRequiredMixin,CustomPermissionMixin, ListView):
    permission_required = 'adminapp.reports_view'
    model = Stock
    template_name = 'adminapp/stock/stock_list.html'
    context_object_name = 'stocks'
    paginate_by = 20

    def get_queryset(self):
        qs = Stock.objects.select_related(
            'store', 'brand', 'item', 
            'item_quality', 'freezing_category', 'unit', 'glaze', 'species', 'item_grade'
        ).order_by('item__name')  # removed non-existent fields

        search = self.request.GET.get('search', '').strip()
        if search:
            qs = qs.filter(
                Q(item__name__icontains=search) |
                Q(brand__name__icontains=search) |
                Q(store__name__icontains=search) |
                Q(species__icontains=search) |
                Q(glaze__icontains=search)
            )

        store_id = self.request.GET.get('store')
        if store_id:
            qs = qs.filter(store_id=store_id)

        category_id = self.request.GET.get('category')
        if category_id:
            # category is now linked through item.category
            qs = qs.filter(item__category_id=category_id)

        brand_id = self.request.GET.get('brand')
        if brand_id:
            qs = qs.filter(brand_id=brand_id)

        low_stock = self.request.GET.get('low_stock')
        if low_stock == 'true':
            qs = qs.filter(Q(cs_quantity__lt=10) | Q(kg_quantity__lt=10))

        source = self.request.GET.get('source')
        if source == 'spot':
            qs = qs.filter(usd_rate_item__isnull=False)  # adjust to your actual spot field
        elif source == 'local':
            qs = qs.filter(usd_rate_item_to_inr__isnull=False)  # adjust to your actual local field

        return qs

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        qs = self.get_queryset()

        context.update({
            'stores': Store.objects.all(),
            'categories': ItemCategory.objects.all(),
            'brands': ItemBrand.objects.all(),
            'search_query': self.request.GET.get('search', ''),
            'selected_store': self.request.GET.get('store', ''),
            'selected_category': self.request.GET.get('category', ''),
            'selected_brand': self.request.GET.get('brand', ''),
            'low_stock_filter': self.request.GET.get('low_stock', ''),
            'source_filter': self.request.GET.get('source', ''),
            'total_stocks': qs.count(),
            'low_stock_count': qs.filter(Q(cs_quantity__lt=10) | Q(kg_quantity__lt=10)).count()
        })

        return context

class StockDetailView(LoginRequiredMixin,CustomPermissionMixin, DetailView):
    permission_required = 'adminapp.reports_view'
    """Detail view for individual stock item"""
    model = Stock
    template_name = 'adminapp/stock/stock_detail.html'
    context_object_name = 'stock'
    
    def get_queryset(self):
        return Stock.objects.select_related(
            'store', 'category', 'brand', 'item', 'item_quality',
            'freezing_category', 'source_spot_entry', 'source_local_entry'
        )
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        stock = self.object
        
        # Get related stock items (same item, different stores/qualities)
        related_stocks = Stock.objects.filter(
            item=stock.item
        ).exclude(pk=stock.pk).select_related(
            'store', 'brand', 'item_quality'
        )[:5]
        
        context['related_stocks'] = related_stocks
        
        # Calculate total quantity across units
        context['total_quantity_display'] = self.get_total_quantity_display(stock)
        
        # Stock status
        context['stock_status'] = self.get_stock_status(stock)
        
        return context
    
    def get_total_quantity_display(self, stock):
        """Format total quantity for display"""
        quantities = []
        if stock.cs_quantity > 0:
            quantities.append(f"{stock.cs_quantity} {stock.unit}")
        if stock.kg_quantity > 0:
            quantities.append(f"{stock.kg_quantity} kg")
        return " | ".join(quantities) if quantities else "No stock"
    
    def get_stock_status(self, stock):
        """Determine stock status based on quantities"""
        total_cs = float(stock.cs_quantity or 0)
        total_kg = float(stock.kg_quantity or 0)
        
        if total_cs == 0 and total_kg == 0:
            return {'status': 'out_of_stock', 'class': 'danger', 'text': 'Out of Stock'}
        elif total_cs < 10 and total_kg < 10:
            return {'status': 'low_stock', 'class': 'warning', 'text': 'Low Stock'}
        else:
            return {'status': 'in_stock', 'class': 'success', 'text': 'In Stock'}

class StockDashboardView(LoginRequiredMixin,CustomPermissionMixin, TemplateView):
    """Dashboard view showing stock overview and analytics"""
    permission_required = 'adminapp.reports_view'
    template_name = 'adminapp/stock/stock_dashboard.html'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        # Overall statistics
        total_items = Stock.objects.count()
        total_stores = Store.objects.count()
        total_categories = ItemCategory.objects.count()
        
        # Stock status breakdown
        out_of_stock = Stock.objects.filter(
            cs_quantity=0, kg_quantity=0
        ).count()
        
        low_stock = Stock.objects.filter(
            Q(cs_quantity__gt=0, cs_quantity__lt=10) |
            Q(kg_quantity__gt=0, kg_quantity__lt=10)
        ).exclude(cs_quantity=0, kg_quantity=0).count()
        
        in_stock = total_items - out_of_stock - low_stock
        
        # Stock by store
        stock_by_store = Stock.objects.values(
            'store__name'
        ).annotate(
            total_items=Count('id'),
            total_cs=Sum('cs_quantity'),
            total_kg=Sum('kg_quantity')
        ).order_by('-total_items')[:10]
        
        # Stock by category
        stock_by_category = Stock.objects.values(
            'category__name'
        ).annotate(
            total_items=Count('id'),
            total_cs=Sum('cs_quantity'),
            total_kg=Sum('kg_quantity')
        ).order_by('-total_items')[:10]
        
        week_ago = timezone.now() - timedelta(days=7)
        recent_spot_updates = Stock.objects.filter(
            last_updated_from_spot__gte=week_ago
        ).count()
        recent_local_updates = Stock.objects.filter(
            last_updated_from_local__gte=week_ago
        ).count()
        
        # Top brands by stock count
        top_brands = Stock.objects.values(
            'brand__name'
        ).annotate(
            total_items=Count('id')
        ).order_by('-total_items')[:5]
        
        context.update({
            'total_items': total_items,
            'total_stores': total_stores,
            'total_categories': total_categories,
            'out_of_stock': out_of_stock,
            'low_stock': low_stock,
            'in_stock': in_stock,
            'stock_by_store': stock_by_store,
            'stock_by_category': stock_by_category,
            'recent_spot_updates': recent_spot_updates,
            'recent_local_updates': recent_local_updates,
            'top_brands': top_brands,
        })
        
        return context

@login_required
@require_http_methods(["POST"])
def delete_stock(request, pk):
    """Function-based view to delete a stock item"""
    stock = get_object_or_404(Stock, pk=pk)
    stock_name = f"{stock.item.name} - {stock.store.name}"
    
    try:
        stock.delete()
        
        # Check if it's an AJAX request
        if request.headers.get('Content-Type') == 'application/json':
            return JsonResponse({
                'success': True,
                'message': f'Stock item "{stock_name}" has been successfully deleted.'
            })
        else:
            messages.success(
                request, 
                f'Stock item "{stock_name}" has been successfully deleted.'
            )
            return redirect('adminapp:list')  # Make sure this matches your URL name
        
    except Exception as e:
        if request.headers.get('Content-Type') == 'application/json':
            return JsonResponse({
                'success': False,
                'message': f'Error deleting stock item: {str(e)}'
            }, status=500)
        else:
            messages.error(
                request, 
                f'Error deleting stock item: {str(e)}'
            )
            return redirect('adminapp:detail', pk=pk)  # Make sure this matches your URL name


# API Views for AJAX requests
def stock_search_api(request):
    """API endpoint for stock search with JSON response"""
    search = request.GET.get('search', '')
    
    stocks = Stock.objects.filter(
        Q(item__name__icontains=search) |
        Q(brand__name__icontains=search) |
        Q(store__name__icontains=search)
    ).select_related(
        'store', 'item', 'brand'
    )[:10]
    
    results = []
    for stock in stocks:
        results.append({
            'id': stock.id,
            'item_name': stock.item.name,
            'store_name': stock.store.name,
            'brand_name': stock.brand.name,
            'cs_quantity': str(stock.cs_quantity),
            'kg_quantity': str(stock.kg_quantity),
            'unit': stock.unit,
        })
    
    return JsonResponse({'results': results})

def stock_quick_info(request, pk):
    """Quick info API for stock item"""
    stock = get_object_or_404(Stock, pk=pk)
    
    data = {
        'item_name': stock.item.name,
        'store_name': stock.store.name,
        'brand_name': stock.brand.name,
        'cs_quantity': str(stock.cs_quantity),
        'kg_quantity': str(stock.kg_quantity),
        'unit': stock.unit,
        'glaze': stock.glaze or 'N/A',
        'species': stock.species or 'N/A',
        'item_grade': stock.item_grade or 'N/A',
        'last_updated_spot': stock.last_updated_from_spot.strftime('%Y-%m-%d %H:%M') if stock.last_updated_from_spot else 'Never',
        'last_updated_local': stock.last_updated_from_local.strftime('%Y-%m-%d %H:%M') if stock.last_updated_from_local else 'Never',
    }
    
    return JsonResponse(data)



# STOCK REPORT

def stock_report(request):
    # First, let's check what fields actually exist on the Stock model
    from django.db import connection
    
    # Check Stock fields
    try:
        stock_fields = [field.name for field in Stock._meta.fields]
        print("Stock fields:", stock_fields)
        
        # Check foreign key relationships
        stock_fk_fields = [field.name for field in Stock._meta.fields if field.get_internal_type() == 'ForeignKey']
        print("Stock FK fields:", stock_fk_fields)
        
    except Exception as e:
        print("Error checking fields:", str(e))

    items = Item.objects.all()
    categories = ItemCategory.objects.all()
    stores = Store.objects.all()
    brands = ItemBrand.objects.all()
    
    # Check if models exist and get related objects
    try:
        units = PackingUnit.objects.all()
    except NameError:
        units = []
    
    try:
        glazes = GlazePercentage.objects.all()
    except NameError:
        glazes = []
        
    try:
        species = Species.objects.all()
    except NameError:
        species = []
        
    try:
        item_grades = ItemGrade.objects.all()
    except NameError:
        item_grades = []
        
    try:
        item_qualities = ItemQuality.objects.all()
    except NameError:
        item_qualities = []
        
    try:
        freezing_categories = FreezingCategory.objects.all()
    except NameError:
        freezing_categories = []

    # Get filter parameters
    selected_items = request.GET.getlist("items")
    selected_categories = request.GET.getlist("categories")
    selected_stores = request.GET.getlist("stores")
    selected_brands = request.GET.getlist("brands")
    selected_units = request.GET.getlist("units")
    selected_glazes = request.GET.getlist("glazes")
    selected_species = request.GET.getlist("species")
    selected_item_grades = request.GET.getlist("item_grades")
    selected_item_qualities = request.GET.getlist("item_qualities")
    selected_freezing_categories = request.GET.getlist("freezing_categories")
    
    low_stock = request.GET.get("low_stock")
    zero_stock = request.GET.get("zero_stock")
    source_type = request.GET.get("source_type", "all")  # all, spot, local
    section_by = request.GET.get("section_by", "category")
    search_query = request.GET.get("search", "").strip()

    # SAFE: Start with minimal select_related and build up
    stock_queryset = Stock.objects.select_related("store", "item", "brand", "item__category")

    # Check what other relationships exist and add them safely
    try:
        # Test if first stock record exists and has these fields
        test_stock = Stock.objects.first()
        if test_stock and hasattr(test_stock, 'item_quality'):
            stock_queryset = stock_queryset.select_related("item_quality")
            print("Added item_quality to select_related")
    except:
        print("No item_quality field found")

    try:
        if test_stock and hasattr(test_stock, 'freezing_category'):
            stock_queryset = stock_queryset.select_related("freezing_category")
            print("Added freezing_category to select_related")
    except:
        print("No freezing_category field found")

    try:
        if test_stock and hasattr(test_stock, 'unit'):
            stock_queryset = stock_queryset.select_related("unit")
            print("Added unit to select_related")
    except:
        print("No unit field found")

    try:
        if test_stock and hasattr(test_stock, 'glaze'):
            stock_queryset = stock_queryset.select_related("glaze")
            print("Added glaze to select_related")
    except:
        print("No glaze field found")

    try:
        if test_stock and hasattr(test_stock, 'species'):
            stock_queryset = stock_queryset.select_related("species")
            print("Added species to select_related")
    except:
        print("No species field found")

    try:
        if test_stock and hasattr(test_stock, 'item_grade'):
            stock_queryset = stock_queryset.select_related("item_grade")
            print("Added item_grade to select_related")
    except:
        print("No item_grade field found")

    # Apply filters with safe field checks
    def apply_filters(queryset):
        # Item filters
        if selected_items:
            queryset = queryset.filter(item__id__in=selected_items)
        
        if selected_categories:
            queryset = queryset.filter(item__category__id__in=selected_categories)
            
        if selected_stores:
            queryset = queryset.filter(store__id__in=selected_stores)
            
        if selected_brands:
            queryset = queryset.filter(brand__id__in=selected_brands)
        
        # Check if fields exist before filtering
        test_item = queryset.first()
        if test_item:
            if hasattr(test_item, 'unit') and selected_units:
                queryset = queryset.filter(unit__id__in=selected_units)
            if hasattr(test_item, 'glaze') and selected_glazes:
                queryset = queryset.filter(glaze__id__in=selected_glazes)
            if hasattr(test_item, 'species') and selected_species:
                queryset = queryset.filter(species__id__in=selected_species)
            if hasattr(test_item, 'item_grade') and selected_item_grades:
                queryset = queryset.filter(item_grade__id__in=selected_item_grades)
            if hasattr(test_item, 'item_quality') and selected_item_qualities:
                queryset = queryset.filter(item_quality__id__in=selected_item_qualities)
            if hasattr(test_item, 'freezing_category') and selected_freezing_categories:
                queryset = queryset.filter(freezing_category__id__in=selected_freezing_categories)
            
        # Stock level filters
        if low_stock == "true":
            queryset = queryset.filter(Q(cs_quantity__lt=10) | Q(kg_quantity__lt=10))
            
        if zero_stock == "true":
            queryset = queryset.filter(Q(cs_quantity=0) | Q(kg_quantity=0))
            
        # Source type filters
        if source_type == "spot":
            queryset = queryset.filter(usd_rate_item__gt=0)
        elif source_type == "local":
            queryset = queryset.filter(usd_rate_item_to_inr__gt=0)
            
        # Search filter
        if search_query:
            queryset = queryset.filter(
                Q(item__name__icontains=search_query) |
                Q(brand__name__icontains=search_query) |
                Q(store__name__icontains=search_query)
            )

        return queryset

    # Apply filters
    stock_queryset = apply_filters(stock_queryset)

    # Process data safely
    all_data = []

    for stock in stock_queryset:
        data_row = {
            'id': stock.id,
            'item__name': stock.item.name if stock.item else None,
            'item__category__name': stock.item.category.name if stock.item and stock.item.category else None,
            'store__name': stock.store.name if stock.store else None,
            'brand__name': stock.brand.name if stock.brand else None,
            'stock_count': 1
        }
        
        # Add optional fields safely
        if hasattr(stock, 'species') and stock.species:
            data_row['species__name'] = stock.species.name
        else:
            data_row['species__name'] = None
            
        if hasattr(stock, 'item_grade') and stock.item_grade:
            data_row['item_grade__grade'] = stock.item_grade.grade
        else:
            data_row['item_grade__grade'] = None
            
        # FIX: Use 'quality' field instead of 'name'
        if hasattr(stock, 'item_quality') and stock.item_quality:
            data_row['item_quality__quality'] = stock.item_quality.quality  # Changed from name to quality
        else:
            data_row['item_quality__quality'] = None
            
        if hasattr(stock, 'freezing_category') and stock.freezing_category:
            data_row['freezing_category__name'] = stock.freezing_category.name
        else:
            data_row['freezing_category__name'] = None

        # Add numeric fields
        data_row.update({
            'total_cs_quantity': float(getattr(stock, 'cs_quantity', 0) or 0),
            'total_kg_quantity': float(getattr(stock, 'kg_quantity', 0) or 0),
            'total_usd_rate_per_kg': float(getattr(stock, 'usd_rate_per_kg', 0) or 0),
            'total_usd_rate_item': float(getattr(stock, 'usd_rate_item', 0) or 0),
            'total_usd_rate_item_to_inr': float(getattr(stock, 'usd_rate_item_to_inr', 0) or 0),
        })
        
        # Add unit and glaze fields if they exist
        if hasattr(stock, 'unit') and stock.unit:
            data_row['unit__description'] = stock.unit.description
            data_row['unit__unit_code'] = stock.unit.unit_code
        else:
            data_row['unit__description'] = None
            data_row['unit__unit_code'] = None
            
        if hasattr(stock, 'glaze') and stock.glaze:
            data_row['glaze__percentage'] = stock.glaze.percentage
        else:
            data_row['glaze__percentage'] = None
            
        # Add stock status
        cs_qty = float(getattr(stock, 'cs_quantity', 0) or 0)
        kg_qty = float(getattr(stock, 'kg_quantity', 0) or 0)
        
        if cs_qty == 0 and kg_qty == 0:
            data_row['stock_status'] = 'Out of Stock'
        elif cs_qty < 10 or kg_qty < 10:
            data_row['stock_status'] = 'Low Stock'
        else:
            data_row['stock_status'] = 'In Stock'
            
        all_data.append(data_row)

    # Sectioning logic
    sectioned_data = {}
    
    for stock in all_data:
        if section_by == "category":
            section_key = stock.get("item__category__name") or "Uncategorized"
        elif section_by == "brand":
            section_key = stock.get("brand__name") or "No Brand"
        elif section_by == "store":
            section_key = stock.get("store__name") or "No Store"
        elif section_by == "species":
            section_key = stock.get("species__name") or "No Species"
        elif section_by == "item_grade":
            section_key = stock.get("item_grade__grade") or "No Grade"
        elif section_by == "item":
            section_key = stock.get("item__name") or "No Item"
        elif section_by == "unit":
            section_key = stock.get("unit__description") or "No Unit"
        elif section_by == "glaze":
            glaze_pct = stock.get("glaze__percentage")
            section_key = f"{glaze_pct}%" if glaze_pct is not None else "No Glaze"
        elif section_by == "stock_status":
            section_key = stock.get("stock_status", "Unknown")
        elif section_by == "item_quality":
            section_key = stock.get("item_quality__quality") or "No Quality"  # Changed from name to quality
        elif section_by == "freezing_category":
            section_key = stock.get("freezing_category__name") or "No Freezing Category"
        else:
            section_key = "All Stocks"
            
        if section_key not in sectioned_data:
            sectioned_data[section_key] = {
                'items': [],
                'totals': {
                    'total_cs_quantity': 0,
                    'total_kg_quantity': 0,
                    'total_usd_rate_item': 0,
                    'total_usd_rate_item_to_inr': 0,
                    'count': 0,
                    'stock_count': 0,
                    'low_stock_count': 0,
                    'zero_stock_count': 0
                }
            }
        
        sectioned_data[section_key]['items'].append(stock)
        
        # Calculate section totals
        totals = sectioned_data[section_key]['totals']
        totals['total_cs_quantity'] += float(stock.get('total_cs_quantity') or 0)
        totals['total_kg_quantity'] += float(stock.get('total_kg_quantity') or 0)
        totals['total_usd_rate_item'] += float(stock.get('total_usd_rate_item') or 0)
        totals['total_usd_rate_item_to_inr'] += float(stock.get('total_usd_rate_item_to_inr') or 0)
        totals['count'] += 1
        totals['stock_count'] += int(stock.get('stock_count') or 0)
        
        # Count stock statuses
        if stock.get('stock_status') == 'Low Stock':
            totals['low_stock_count'] += 1
        elif stock.get('stock_status') == 'Out of Stock':
            totals['zero_stock_count'] += 1

    sectioned_data = dict(sorted(sectioned_data.items()))

    # Calculate grand totals
    grand_totals = {
        'total_cs_quantity': 0,
        'total_kg_quantity': 0,
        'total_usd_rate_item': 0,
        'total_usd_rate_item_to_inr': 0,
        'count': 0,
        'stock_count': 0,
        'low_stock_count': 0,
        'zero_stock_count': 0,
        'avg_cs_per_stock': 0,
        'avg_kg_per_stock': 0,
        'avg_usd_rate_per_kg': 0
    }
    
    for section in sectioned_data.values():
        for key in ['total_cs_quantity', 'total_kg_quantity', 'total_usd_rate_item', 
                   'total_usd_rate_item_to_inr', 'count', 'stock_count', 
                   'low_stock_count', 'zero_stock_count']:
            grand_totals[key] += section['totals'][key]

    if grand_totals['count'] > 0:
        grand_totals['avg_cs_per_stock'] = grand_totals['total_cs_quantity'] / grand_totals['count']
        grand_totals['avg_kg_per_stock'] = grand_totals['total_kg_quantity'] / grand_totals['count']
        
    if grand_totals['total_kg_quantity'] > 0:
        grand_totals['avg_usd_rate_per_kg'] = grand_totals['total_usd_rate_item'] / grand_totals['total_kg_quantity']

    return render(
        request,
        "adminapp/report/stock_report.html",
        {
            "sectioned_data": sectioned_data,
            "grand_totals": grand_totals,
            "items": items,
            "categories": categories,
            "stores": stores,
            "brands": brands,
            "units": units,
            "glazes": glazes,
            "species": species,
            "item_grades": item_grades,
            "item_qualities": item_qualities,
            "freezing_categories": freezing_categories,
            "selected_items": selected_items,
            "selected_categories": selected_categories,
            "selected_stores": selected_stores,
            "selected_brands": selected_brands,
            "selected_units": selected_units,
            "selected_glazes": selected_glazes,
            "selected_species": selected_species,
            "selected_item_grades": selected_item_grades,
            "selected_item_qualities": selected_item_qualities,
            "selected_freezing_categories": selected_freezing_categories,
            "low_stock": low_stock,
            "zero_stock": zero_stock,
            "source_type": source_type,
            "section_by": section_by,
            "search_query": search_query,
        },
    )

def stock_report_print(request):
    """Separate view specifically for print format"""
    items = Item.objects.all()
    categories = ItemCategory.objects.all()
    stores = Store.objects.all()
    brands = ItemBrand.objects.all()

    # Get filter parameters (same as main view)
    selected_items = request.GET.getlist("items")
    selected_categories = request.GET.getlist("categories")
    selected_stores = request.GET.getlist("stores")
    selected_brands = request.GET.getlist("brands")
    selected_units = request.GET.getlist("units")
    selected_glazes = request.GET.getlist("glazes")
    selected_species = request.GET.getlist("species")
    selected_item_grades = request.GET.getlist("item_grades")
    selected_item_qualities = request.GET.getlist("item_qualities")
    selected_freezing_categories = request.GET.getlist("freezing_categories")
    low_stock = request.GET.get("low_stock")
    zero_stock = request.GET.get("zero_stock")
    source_type = request.GET.get("source_type", "all")
    search_query = request.GET.get("search", "").strip()

    # Base queryset with safe select_related
    stock_queryset = Stock.objects.select_related(
        "store", "item", "brand", "item__category"
    )
    
    # Try to add other relations safely
    try:
        test_stock = Stock.objects.first()
        if test_stock:
            available_relations = []
            for field in ['item_quality', 'freezing_category', 'unit', 'glaze', 'species', 'item_grade']:
                if hasattr(test_stock, field):
                    available_relations.append(field)
            
            if available_relations:
                stock_queryset = stock_queryset.select_related(*available_relations)
    except:
        pass

    # Apply same filters as main view
    def apply_filters(queryset):
        if selected_items:
            queryset = queryset.filter(item__id__in=selected_items)
        if selected_categories:
            queryset = queryset.filter(item__category__id__in=selected_categories)
        if selected_stores:
            queryset = queryset.filter(store__id__in=selected_stores)
        if selected_brands:
            queryset = queryset.filter(brand__id__in=selected_brands)
            
        # Safe filtering for optional fields
        test_item = queryset.first()
        if test_item:
            if hasattr(test_item, 'unit') and selected_units:
                queryset = queryset.filter(unit__id__in=selected_units)
            if hasattr(test_item, 'glaze') and selected_glazes:
                queryset = queryset.filter(glaze__id__in=selected_glazes)
            if hasattr(test_item, 'species') and selected_species:
                queryset = queryset.filter(species__id__in=selected_species)
            if hasattr(test_item, 'item_grade') and selected_item_grades:
                queryset = queryset.filter(item_grade__id__in=selected_item_grades)
            if hasattr(test_item, 'item_quality') and selected_item_qualities:
                queryset = queryset.filter(item_quality__id__in=selected_item_qualities)
            if hasattr(test_item, 'freezing_category') and selected_freezing_categories:
                queryset = queryset.filter(freezing_category__id__in=selected_freezing_categories)
        
        if low_stock == "true":
            queryset = queryset.filter(Q(cs_quantity__lt=10) | Q(kg_quantity__lt=10))
        if zero_stock == "true":
            queryset = queryset.filter(Q(cs_quantity=0) | Q(kg_quantity=0))
        if source_type == "spot":
            queryset = queryset.filter(usd_rate_item__gt=0)
        elif source_type == "local":
            queryset = queryset.filter(usd_rate_item_to_inr__gt=0)
        if search_query:
            queryset = queryset.filter(
                Q(item__name__icontains=search_query) |
                Q(brand__name__icontains=search_query) |
                Q(store__name__icontains=search_query)
            )

        return queryset

    # Apply filters
    stock_queryset = apply_filters(stock_queryset)

    # Create summary data with safe field access
    summary_data = []
    
    for stock in stock_queryset:
        summary_item = {
            'item__name': stock.item.name if stock.item else None,
            'item__category__name': stock.item.category.name if stock.item and stock.item.category else None,
            'store__name': stock.store.name if stock.store else None,
            'brand__name': stock.brand.name if stock.brand else None,
            'cs_quantity': float(getattr(stock, 'cs_quantity', 0) or 0),
            'kg_quantity': float(getattr(stock, 'kg_quantity', 0) or 0),
            'usd_rate_per_kg': float(getattr(stock, 'usd_rate_per_kg', 0) or 0),
            'usd_rate_item': float(getattr(stock, 'usd_rate_item', 0) or 0),
            'usd_rate_item_to_inr': float(getattr(stock, 'usd_rate_item_to_inr', 0) or 0),
        }
        
        # Add optional fields safely
        for field, display_name in [
            ('species', 'species__name'),
            ('item_grade', 'item_grade__grade'),
            ('item_quality', 'item_quality__name'),
            ('freezing_category', 'freezing_category__name'),
            ('unit', 'unit__description'),
            ('glaze', 'glaze__percentage')
        ]:
            if hasattr(stock, field):
                related_obj = getattr(stock, field)
                if related_obj:
                    if field == 'item_grade':
                        summary_item[display_name] = related_obj.grade
                    elif field == 'unit':
                        summary_item[display_name] = related_obj.description
                    elif field == 'glaze':
                        summary_item[display_name] = related_obj.percentage
                    else:
                        summary_item[display_name] = related_obj.name
                else:
                    summary_item[display_name] = None
            else:
                summary_item[display_name] = None
        
        # Add stock status
        cs_qty = summary_item['cs_quantity']
        kg_qty = summary_item['kg_quantity']
        
        if cs_qty == 0 and kg_qty == 0:
            summary_item['stock_status'] = 'Out of Stock'
        elif cs_qty < 10 or kg_qty < 10:
            summary_item['stock_status'] = 'Low Stock'
        else:
            summary_item['stock_status'] = 'In Stock'
            
        summary_data.append(summary_item)

    # Sort by item name
    summary_data = sorted(summary_data, key=lambda x: x['item__name'] or '')

    return render(
        request,
        "adminapp/report/stock_report_print.html",
        {
            "summary": summary_data,
            "selected_items": selected_items,
            "selected_categories": selected_categories,
            "selected_stores": selected_stores,
            "selected_brands": selected_brands,
            "selected_units": selected_units,
            "selected_glazes": selected_glazes,
            "selected_species": selected_species,
            "selected_item_grades": selected_item_grades,
            "selected_item_qualities": selected_item_qualities,
            "selected_freezing_categories": selected_freezing_categories,
            "low_stock": low_stock,
            "zero_stock": zero_stock,
            "source_type": source_type,
            "search_query": search_query,
        },
    )


# STOCK REPORT with amount

def stock_report_amt(request):
    # First, let's check what fields actually exist on the Stock model
    from django.db import connection
    
    # Check Stock fields
    try:
        stock_fields = [field.name for field in Stock._meta.fields]
        print("Stock fields:", stock_fields)
        
        # Check foreign key relationships
        stock_fk_fields = [field.name for field in Stock._meta.fields if field.get_internal_type() == 'ForeignKey']
        print("Stock FK fields:", stock_fk_fields)
        
    except Exception as e:
        print("Error checking fields:", str(e))

    items = Item.objects.all()
    categories = ItemCategory.objects.all()
    stores = Store.objects.all()
    brands = ItemBrand.objects.all()
    
    # Check if models exist and get related objects
    try:
        units = PackingUnit.objects.all()
    except NameError:
        units = []
    
    try:
        glazes = GlazePercentage.objects.all()
    except NameError:
        glazes = []
        
    try:
        species = Species.objects.all()
    except NameError:
        species = []
        
    try:
        item_grades = ItemGrade.objects.all()
    except NameError:
        item_grades = []
        
    try:
        item_qualities = ItemQuality.objects.all()
    except NameError:
        item_qualities = []
        
    try:
        freezing_categories = FreezingCategory.objects.all()
    except NameError:
        freezing_categories = []

    # Get filter parameters
    selected_items = request.GET.getlist("items")
    selected_categories = request.GET.getlist("categories")
    selected_stores = request.GET.getlist("stores")
    selected_brands = request.GET.getlist("brands")
    selected_units = request.GET.getlist("units")
    selected_glazes = request.GET.getlist("glazes")
    selected_species = request.GET.getlist("species")
    selected_item_grades = request.GET.getlist("item_grades")
    selected_item_qualities = request.GET.getlist("item_qualities")
    selected_freezing_categories = request.GET.getlist("freezing_categories")
    
    low_stock = request.GET.get("low_stock")
    zero_stock = request.GET.get("zero_stock")
    source_type = request.GET.get("source_type", "all")  # all, spot, local
    section_by = request.GET.get("section_by", "category")
    search_query = request.GET.get("search", "").strip()

    # SAFE: Start with minimal select_related and build up
    stock_queryset = Stock.objects.select_related("store", "item", "brand", "item__category")

    # Check what other relationships exist and add them safely
    try:
        # Test if first stock record exists and has these fields
        test_stock = Stock.objects.first()
        if test_stock and hasattr(test_stock, 'item_quality'):
            stock_queryset = stock_queryset.select_related("item_quality")
            print("Added item_quality to select_related")
    except:
        print("No item_quality field found")

    try:
        if test_stock and hasattr(test_stock, 'freezing_category'):
            stock_queryset = stock_queryset.select_related("freezing_category")
            print("Added freezing_category to select_related")
    except:
        print("No freezing_category field found")

    try:
        if test_stock and hasattr(test_stock, 'unit'):
            stock_queryset = stock_queryset.select_related("unit")
            print("Added unit to select_related")
    except:
        print("No unit field found")

    try:
        if test_stock and hasattr(test_stock, 'glaze'):
            stock_queryset = stock_queryset.select_related("glaze")
            print("Added glaze to select_related")
    except:
        print("No glaze field found")

    try:
        if test_stock and hasattr(test_stock, 'species'):
            stock_queryset = stock_queryset.select_related("species")
            print("Added species to select_related")
    except:
        print("No species field found")

    try:
        if test_stock and hasattr(test_stock, 'item_grade'):
            stock_queryset = stock_queryset.select_related("item_grade")
            print("Added item_grade to select_related")
    except:
        print("No item_grade field found")

    # Apply filters with safe field checks
    def apply_filters(queryset):
        # Item filters
        if selected_items:
            queryset = queryset.filter(item__id__in=selected_items)
        
        if selected_categories:
            queryset = queryset.filter(item__category__id__in=selected_categories)
            
        if selected_stores:
            queryset = queryset.filter(store__id__in=selected_stores)
            
        if selected_brands:
            queryset = queryset.filter(brand__id__in=selected_brands)
        
        # Check if fields exist before filtering
        test_item = queryset.first()
        if test_item:
            if hasattr(test_item, 'unit') and selected_units:
                queryset = queryset.filter(unit__id__in=selected_units)
            if hasattr(test_item, 'glaze') and selected_glazes:
                queryset = queryset.filter(glaze__id__in=selected_glazes)
            if hasattr(test_item, 'species') and selected_species:
                queryset = queryset.filter(species__id__in=selected_species)
            if hasattr(test_item, 'item_grade') and selected_item_grades:
                queryset = queryset.filter(item_grade__id__in=selected_item_grades)
            if hasattr(test_item, 'item_quality') and selected_item_qualities:
                queryset = queryset.filter(item_quality__id__in=selected_item_qualities)
            if hasattr(test_item, 'freezing_category') and selected_freezing_categories:
                queryset = queryset.filter(freezing_category__id__in=selected_freezing_categories)
            
        # Stock level filters
        if low_stock == "true":
            queryset = queryset.filter(Q(cs_quantity__lt=10) | Q(kg_quantity__lt=10))
            
        if zero_stock == "true":
            queryset = queryset.filter(Q(cs_quantity=0) | Q(kg_quantity=0))
            
        # Source type filters
        if source_type == "spot":
            queryset = queryset.filter(usd_rate_item__gt=0)
        elif source_type == "local":
            queryset = queryset.filter(usd_rate_item_to_inr__gt=0)
            
        # Search filter
        if search_query:
            queryset = queryset.filter(
                Q(item__name__icontains=search_query) |
                Q(brand__name__icontains=search_query) |
                Q(store__name__icontains=search_query)
            )

        return queryset

    # Apply filters
    stock_queryset = apply_filters(stock_queryset)

    # Process data safely
    all_data = []

    for stock in stock_queryset:
        data_row = {
            'id': stock.id,
            'item__name': stock.item.name if stock.item else None,
            'item__category__name': stock.item.category.name if stock.item and stock.item.category else None,
            'store__name': stock.store.name if stock.store else None,
            'brand__name': stock.brand.name if stock.brand else None,
            'stock_count': 1
        }
        
        # Add optional fields safely
        if hasattr(stock, 'species') and stock.species:
            data_row['species__name'] = stock.species.name
        else:
            data_row['species__name'] = None
            
        if hasattr(stock, 'item_grade') and stock.item_grade:
            data_row['item_grade__grade'] = stock.item_grade.grade
        else:
            data_row['item_grade__grade'] = None
            
        # FIX: Use 'quality' field instead of 'name'
        if hasattr(stock, 'item_quality') and stock.item_quality:
            data_row['item_quality__quality'] = stock.item_quality.quality  # Changed from name to quality
        else:
            data_row['item_quality__quality'] = None
            
        if hasattr(stock, 'freezing_category') and stock.freezing_category:
            data_row['freezing_category__name'] = stock.freezing_category.name
        else:
            data_row['freezing_category__name'] = None

        # Add numeric fields
        data_row.update({
            'total_cs_quantity': float(getattr(stock, 'cs_quantity', 0) or 0),
            'total_kg_quantity': float(getattr(stock, 'kg_quantity', 0) or 0),
            'total_usd_rate_per_kg': float(getattr(stock, 'usd_rate_per_kg', 0) or 0),
            'total_usd_rate_item': float(getattr(stock, 'usd_rate_item', 0) or 0),
            'total_usd_rate_item_to_inr': float(getattr(stock, 'usd_rate_item_to_inr', 0) or 0),
        })
        
        # Add unit and glaze fields if they exist
        if hasattr(stock, 'unit') and stock.unit:
            data_row['unit__description'] = stock.unit.description
            data_row['unit__unit_code'] = stock.unit.unit_code
        else:
            data_row['unit__description'] = None
            data_row['unit__unit_code'] = None
            
        if hasattr(stock, 'glaze') and stock.glaze:
            data_row['glaze__percentage'] = stock.glaze.percentage
        else:
            data_row['glaze__percentage'] = None
            
        # Add stock status
        cs_qty = float(getattr(stock, 'cs_quantity', 0) or 0)
        kg_qty = float(getattr(stock, 'kg_quantity', 0) or 0)
        
        if cs_qty == 0 and kg_qty == 0:
            data_row['stock_status'] = 'Out of Stock'
        elif cs_qty < 10 or kg_qty < 10:
            data_row['stock_status'] = 'Low Stock'
        else:
            data_row['stock_status'] = 'In Stock'
            
        all_data.append(data_row)

    # Sectioning logic
    sectioned_data = {}
    
    for stock in all_data:
        if section_by == "category":
            section_key = stock.get("item__category__name") or "Uncategorized"
        elif section_by == "brand":
            section_key = stock.get("brand__name") or "No Brand"
        elif section_by == "store":
            section_key = stock.get("store__name") or "No Store"
        elif section_by == "species":
            section_key = stock.get("species__name") or "No Species"
        elif section_by == "item_grade":
            section_key = stock.get("item_grade__grade") or "No Grade"
        elif section_by == "item":
            section_key = stock.get("item__name") or "No Item"
        elif section_by == "unit":
            section_key = stock.get("unit__description") or "No Unit"
        elif section_by == "glaze":
            glaze_pct = stock.get("glaze__percentage")
            section_key = f"{glaze_pct}%" if glaze_pct is not None else "No Glaze"
        elif section_by == "stock_status":
            section_key = stock.get("stock_status", "Unknown")
        elif section_by == "item_quality":
            section_key = stock.get("item_quality__quality") or "No Quality"  # Changed from name to quality
        elif section_by == "freezing_category":
            section_key = stock.get("freezing_category__name") or "No Freezing Category"
        else:
            section_key = "All Stocks"
            
        if section_key not in sectioned_data:
            sectioned_data[section_key] = {
                'items': [],
                'totals': {
                    'total_cs_quantity': 0,
                    'total_kg_quantity': 0,
                    'total_usd_rate_item': 0,
                    'total_usd_rate_item_to_inr': 0,
                    'count': 0,
                    'stock_count': 0,
                    'low_stock_count': 0,
                    'zero_stock_count': 0
                }
            }
        
        sectioned_data[section_key]['items'].append(stock)
        
        # Calculate section totals
        totals = sectioned_data[section_key]['totals']
        totals['total_cs_quantity'] += float(stock.get('total_cs_quantity') or 0)
        totals['total_kg_quantity'] += float(stock.get('total_kg_quantity') or 0)
        totals['total_usd_rate_item'] += float(stock.get('total_usd_rate_item') or 0)
        totals['total_usd_rate_item_to_inr'] += float(stock.get('total_usd_rate_item_to_inr') or 0)
        totals['count'] += 1
        totals['stock_count'] += int(stock.get('stock_count') or 0)
        
        # Count stock statuses
        if stock.get('stock_status') == 'Low Stock':
            totals['low_stock_count'] += 1
        elif stock.get('stock_status') == 'Out of Stock':
            totals['zero_stock_count'] += 1

    sectioned_data = dict(sorted(sectioned_data.items()))

    # Calculate grand totals
    grand_totals = {
        'total_cs_quantity': 0,
        'total_kg_quantity': 0,
        'total_usd_rate_item': 0,
        'total_usd_rate_item_to_inr': 0,
        'count': 0,
        'stock_count': 0,
        'low_stock_count': 0,
        'zero_stock_count': 0,
        'avg_cs_per_stock': 0,
        'avg_kg_per_stock': 0,
        'avg_usd_rate_per_kg': 0
    }
    
    for section in sectioned_data.values():
        for key in ['total_cs_quantity', 'total_kg_quantity', 'total_usd_rate_item', 
                   'total_usd_rate_item_to_inr', 'count', 'stock_count', 
                   'low_stock_count', 'zero_stock_count']:
            grand_totals[key] += section['totals'][key]

    if grand_totals['count'] > 0:
        grand_totals['avg_cs_per_stock'] = grand_totals['total_cs_quantity'] / grand_totals['count']
        grand_totals['avg_kg_per_stock'] = grand_totals['total_kg_quantity'] / grand_totals['count']
        
    if grand_totals['total_kg_quantity'] > 0:
        grand_totals['avg_usd_rate_per_kg'] = grand_totals['total_usd_rate_item'] / grand_totals['total_kg_quantity']

    return render(
        request,
        "adminapp/report/stock_report_amt.html",
        {
            "sectioned_data": sectioned_data,
            "grand_totals": grand_totals,
            "items": items,
            "categories": categories,
            "stores": stores,
            "brands": brands,
            "units": units,
            "glazes": glazes,
            "species": species,
            "item_grades": item_grades,
            "item_qualities": item_qualities,
            "freezing_categories": freezing_categories,
            "selected_items": selected_items,
            "selected_categories": selected_categories,
            "selected_stores": selected_stores,
            "selected_brands": selected_brands,
            "selected_units": selected_units,
            "selected_glazes": selected_glazes,
            "selected_species": selected_species,
            "selected_item_grades": selected_item_grades,
            "selected_item_qualities": selected_item_qualities,
            "selected_freezing_categories": selected_freezing_categories,
            "low_stock": low_stock,
            "zero_stock": zero_stock,
            "source_type": source_type,
            "section_by": section_by,
            "search_query": search_query,
        },
    )

def stock_report_print_amt(request):
    """Separate view specifically for print format"""
    items = Item.objects.all()
    categories = ItemCategory.objects.all()
    stores = Store.objects.all()
    brands = ItemBrand.objects.all()

    # Get filter parameters (same as main view)
    selected_items = request.GET.getlist("items")
    selected_categories = request.GET.getlist("categories")
    selected_stores = request.GET.getlist("stores")
    selected_brands = request.GET.getlist("brands")
    selected_units = request.GET.getlist("units")
    selected_glazes = request.GET.getlist("glazes")
    selected_species = request.GET.getlist("species")
    selected_item_grades = request.GET.getlist("item_grades")
    selected_item_qualities = request.GET.getlist("item_qualities")
    selected_freezing_categories = request.GET.getlist("freezing_categories")
    low_stock = request.GET.get("low_stock")
    zero_stock = request.GET.get("zero_stock")
    source_type = request.GET.get("source_type", "all")
    search_query = request.GET.get("search", "").strip()

    # Base queryset with safe select_related
    stock_queryset = Stock.objects.select_related(
        "store", "item", "brand", "item__category"
    )
    
    # Try to add other relations safely
    try:
        test_stock = Stock.objects.first()
        if test_stock:
            available_relations = []
            for field in ['item_quality', 'freezing_category', 'unit', 'glaze', 'species', 'item_grade']:
                if hasattr(test_stock, field):
                    available_relations.append(field)
            
            if available_relations:
                stock_queryset = stock_queryset.select_related(*available_relations)
    except:
        pass

    # Apply same filters as main view
    def apply_filters(queryset):
        if selected_items:
            queryset = queryset.filter(item__id__in=selected_items)
        if selected_categories:
            queryset = queryset.filter(item__category__id__in=selected_categories)
        if selected_stores:
            queryset = queryset.filter(store__id__in=selected_stores)
        if selected_brands:
            queryset = queryset.filter(brand__id__in=selected_brands)
            
        # Safe filtering for optional fields
        test_item = queryset.first()
        if test_item:
            if hasattr(test_item, 'unit') and selected_units:
                queryset = queryset.filter(unit__id__in=selected_units)
            if hasattr(test_item, 'glaze') and selected_glazes:
                queryset = queryset.filter(glaze__id__in=selected_glazes)
            if hasattr(test_item, 'species') and selected_species:
                queryset = queryset.filter(species__id__in=selected_species)
            if hasattr(test_item, 'item_grade') and selected_item_grades:
                queryset = queryset.filter(item_grade__id__in=selected_item_grades)
            if hasattr(test_item, 'item_quality') and selected_item_qualities:
                queryset = queryset.filter(item_quality__id__in=selected_item_qualities)
            if hasattr(test_item, 'freezing_category') and selected_freezing_categories:
                queryset = queryset.filter(freezing_category__id__in=selected_freezing_categories)
        
        if low_stock == "true":
            queryset = queryset.filter(Q(cs_quantity__lt=10) | Q(kg_quantity__lt=10))
        if zero_stock == "true":
            queryset = queryset.filter(Q(cs_quantity=0) | Q(kg_quantity=0))
        if source_type == "spot":
            queryset = queryset.filter(usd_rate_item__gt=0)
        elif source_type == "local":
            queryset = queryset.filter(usd_rate_item_to_inr__gt=0)
        if search_query:
            queryset = queryset.filter(
                Q(item__name__icontains=search_query) |
                Q(brand__name__icontains=search_query) |
                Q(store__name__icontains=search_query)
            )

        return queryset

    # Apply filters
    stock_queryset = apply_filters(stock_queryset)

    # Create summary data with safe field access
    summary_data = []
    
    for stock in stock_queryset:
        summary_item = {
            'item__name': stock.item.name if stock.item else None,
            'item__category__name': stock.item.category.name if stock.item and stock.item.category else None,
            'store__name': stock.store.name if stock.store else None,
            'brand__name': stock.brand.name if stock.brand else None,
            'cs_quantity': float(getattr(stock, 'cs_quantity', 0) or 0),
            'kg_quantity': float(getattr(stock, 'kg_quantity', 0) or 0),
            'usd_rate_per_kg': float(getattr(stock, 'usd_rate_per_kg', 0) or 0),
            'usd_rate_item': float(getattr(stock, 'usd_rate_item', 0) or 0),
            'usd_rate_item_to_inr': float(getattr(stock, 'usd_rate_item_to_inr', 0) or 0),
        }
        
        # Add optional fields safely
        for field, display_name in [
            ('species', 'species__name'),
            ('item_grade', 'item_grade__grade'),
            ('item_quality', 'item_quality__name'),
            ('freezing_category', 'freezing_category__name'),
            ('unit', 'unit__description'),
            ('glaze', 'glaze__percentage')
        ]:
            if hasattr(stock, field):
                related_obj = getattr(stock, field)
                if related_obj:
                    if field == 'item_grade':
                        summary_item[display_name] = related_obj.grade
                    elif field == 'unit':
                        summary_item[display_name] = related_obj.description
                    elif field == 'glaze':
                        summary_item[display_name] = related_obj.percentage
                    else:
                        summary_item[display_name] = related_obj.name
                else:
                    summary_item[display_name] = None
            else:
                summary_item[display_name] = None
        
        # Add stock status
        cs_qty = summary_item['cs_quantity']
        kg_qty = summary_item['kg_quantity']
        
        if cs_qty == 0 and kg_qty == 0:
            summary_item['stock_status'] = 'Out of Stock'
        elif cs_qty < 10 or kg_qty < 10:
            summary_item['stock_status'] = 'Low Stock'
        else:
            summary_item['stock_status'] = 'In Stock'
            
        summary_data.append(summary_item)

    # Sort by item name
    summary_data = sorted(summary_data, key=lambda x: x['item__name'] or '')

    return render(
        request,
        "adminapp/report/stock_report_print_amt.html",
        {
            "summary": summary_data,
            "selected_items": selected_items,
            "selected_categories": selected_categories,
            "selected_stores": selected_stores,
            "selected_brands": selected_brands,
            "selected_units": selected_units,
            "selected_glazes": selected_glazes,
            "selected_species": selected_species,
            "selected_item_grades": selected_item_grades,
            "selected_item_qualities": selected_item_qualities,
            "selected_freezing_categories": selected_freezing_categories,
            "low_stock": low_stock,
            "zero_stock": zero_stock,
            "source_type": source_type,
            "search_query": search_query,
        },
    )



# --- Spot Agent Voucher --- fix
@check_permission('voucher_add')
def create_spot_agent_voucher(request):
    if request.method == "POST":
        form = SpotAgentVoucherForm(request.POST)
        if form.is_valid():
            voucher = form.save(commit=False)

            # get last total for this agent
            last_total = SpotAgentVoucher.objects.filter(agent=voucher.agent).aggregate(
                total=Sum('total_amount')
            )['total'] or 0

            # remain amount before this entry
            voucher.remain_amount = last_total

            # compute new total after receipt/payment
            voucher.total_amount = last_total + (voucher.receipt or 0) - (voucher.payment or 0)

            voucher.save()
            messages.success(request, "Spot Agent Voucher created successfully ✅")
            return redirect("adminapp:spotagentvoucher_list")
    else:
        form = SpotAgentVoucherForm()

    return render(request, "adminapp/vouchers/spotagentvoucher_form.html", {"form": form})

@check_permission('voucher_view')
def get_agent_balance(request):
    agent_id = request.GET.get("agent_id")
    if not agent_id:
        return JsonResponse({"error": "No agent_id provided"}, status=400)

    try:
        agent = PurchasingAgent.objects.get(pk=agent_id)

        # 🔹 1. Sum of all purchases for this agent
        purchase_total = SpotPurchase.objects.filter(agent=agent).aggregate(
            total=Sum("total_purchase_amount")
        )["total"] or 0

        # 🔹 2. Sum of receipts & payments in vouchers
        voucher_sums = SpotAgentVoucher.objects.filter(agent=agent).aggregate(
            total_receipt=Sum("receipt"),
            total_payment=Sum("payment"),
        )

        total_receipt = voucher_sums["total_receipt"] or 0
        total_payment = voucher_sums["total_payment"] or 0

        # 🔹 3. Calculate remaining balance
        remain_amount = purchase_total + total_receipt - total_payment

        return JsonResponse({
            "purchase_total": float(purchase_total),
            "total_receipt": float(total_receipt),
            "total_payment": float(total_payment),
            "remain_amount": float(remain_amount),
        })

    except PurchasingAgent.DoesNotExist:
        return JsonResponse({"error": "Agent not found"}, status=404)

@check_permission('voucher_view')
def spotagentvoucher_list_with_summary(request):
    """Enhanced list view with transaction summary and filtering"""
    
    # Get filter parameters
    date_filter = request.GET.get('date_filter', 'all')  # all, today, week, month, year, custom
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    agent_filter = request.GET.get('agent')
    search_query = request.GET.get('search', '')
    
    # Base queryset
    vouchers = SpotAgentVoucher.objects.select_related('agent').order_by('-date', '-id')
    
    # Apply date filtering
    today = timezone.now().date()
    
    if date_filter == 'today':
        vouchers = vouchers.filter(date=today)
        period_name = f"Today ({today})"
    elif date_filter == 'week':
        week_start = today - timedelta(days=today.weekday())
        week_end = week_start + timedelta(days=6)
        vouchers = vouchers.filter(date__range=[week_start, week_end])
        period_name = f"This Week ({week_start} to {week_end})"
    elif date_filter == 'month':
        month_start = today.replace(day=1)
        if today.month == 12:
            month_end = today.replace(year=today.year + 1, month=1, day=1) - timedelta(days=1)
        else:
            month_end = today.replace(month=today.month + 1, day=1) - timedelta(days=1)
        vouchers = vouchers.filter(date__range=[month_start, month_end])
        period_name = f"This Month ({month_start.strftime('%B %Y')})"
    elif date_filter == 'year':
        year_start = today.replace(month=1, day=1)
        year_end = today.replace(month=12, day=31)
        vouchers = vouchers.filter(date__range=[year_start, year_end])
        period_name = f"This Year ({today.year})"
    elif date_filter == 'custom' and start_date and end_date:
        try:
            start_date_obj = datetime.strptime(start_date, '%Y-%m-%d').date()
            end_date_obj = datetime.strptime(end_date, '%Y-%m-%d').date()
            vouchers = vouchers.filter(date__range=[start_date_obj, end_date_obj])
            period_name = f"Custom Range ({start_date} to {end_date})"
        except ValueError:
            period_name = "All Time"
    else:
        period_name = "All Time"
    
    # Apply agent filtering
    if agent_filter:
        vouchers = vouchers.filter(agent_id=agent_filter)
    
    # Apply search filtering
    if search_query:
        vouchers = vouchers.filter(
            Q(voucher_no__icontains=search_query) |
            Q(agent__name__icontains=search_query) |
            Q(agent__mobile__icontains=search_query) |
            Q(description__icontains=search_query)
        )
    
    # Calculate summary statistics
    summary = vouchers.aggregate(
        total_vouchers=Count('id'),
        total_receipts=Sum('receipt'),
        total_payments=Sum('payment'),
        net_amount=Sum('receipt') - Sum('payment')
    )
    
    # Convert None to 0 for display
    for key, value in summary.items():
        if value is None:
            summary[key] = Decimal('0.00')
    
    # Get agent-wise summary - Fixed to ensure we get proper agent IDs
    agent_summary = vouchers.values(
        'agent__id',  # Make sure we include the actual ID field
        'agent__name',
        'agent__mobile'
    ).annotate(
        voucher_count=Count('id'),
        total_receipts=Sum('receipt'),
        total_payments=Sum('payment'),
        net_amount=Sum('receipt') - Sum('payment')
    ).order_by('-net_amount')
    
    # Pagination
    paginator = Paginator(vouchers, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    # Get all agents for filter dropdown
    all_agents = PurchasingAgent.objects.all().order_by('name')
    
    context = {
        'vouchers': page_obj,
        'summary': summary,
        'agent_summary': agent_summary,
        'all_agents': all_agents,
        'search_query': search_query,
        'date_filter': date_filter,
        'start_date': start_date,
        'end_date': end_date,
        'agent_filter': agent_filter,
        'period_name': period_name,
        'total_count': paginator.count,
        'today': today,
    }
    
    return render(request, "adminapp/vouchers/spotagentvoucher_list_summary.html", context)

@check_permission('voucher_view')
def spot_agent_voucher_summary_pdf(request):
    """Generate PDF summary report for spot agent vouchers"""
    
    # Get same filter parameters as list view
    date_filter = request.GET.get('date_filter', 'all')
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    agent_filter = request.GET.get('agent')
    
    # Apply same filtering logic
    vouchers = SpotAgentVoucher.objects.select_related('agent').order_by('-date', '-id')
    
    today = timezone.now().date()
    
    if date_filter == 'today':
        vouchers = vouchers.filter(date=today)
        period_name = f"Today ({today})"
    elif date_filter == 'week':
        week_start = today - timedelta(days=today.weekday())
        week_end = week_start + timedelta(days=6)
        vouchers = vouchers.filter(date__range=[week_start, week_end])
        period_name = f"This Week ({week_start} to {week_end})"
    elif date_filter == 'month':
        month_start = today.replace(day=1)
        if today.month == 12:
            month_end = today.replace(year=today.year + 1, month=1, day=1) - timedelta(days=1)
        else:
            month_end = today.replace(month=today.month + 1, day=1) - timedelta(days=1)
        vouchers = vouchers.filter(date__range=[month_start, month_end])
        period_name = f"This Month ({month_start.strftime('%B %Y')})"
    elif date_filter == 'year':
        year_start = today.replace(month=1, day=1)
        year_end = today.replace(month=12, day=31)
        vouchers = vouchers.filter(date__range=[year_start, year_end])
        period_name = f"This Year ({today.year})"
    elif date_filter == 'custom' and start_date and end_date:
        try:
            start_date_obj = datetime.strptime(start_date, '%Y-%m-%d').date()
            end_date_obj = datetime.strptime(end_date, '%Y-%m-%d').date()
            vouchers = vouchers.filter(date__range=[start_date_obj, end_date_obj])
            period_name = f"Custom Range ({start_date} to {end_date})"
        except ValueError:
            period_name = "All Time"
    else:
        period_name = "All Time"
    
    if agent_filter:
        vouchers = vouchers.filter(agent_id=agent_filter)
    
    # Calculate summary
    summary = vouchers.aggregate(
        total_vouchers=Count('id'),
        total_receipts=Sum('receipt'),
        total_payments=Sum('payment'),
        net_amount=Sum('receipt') - Sum('payment')
    )
    
    for key, value in summary.items():
        if value is None:
            summary[key] = Decimal('0.00')
    
    # Get agent-wise summary
    agent_summary = vouchers.values(
        'agent__name',
        'agent__mobile'
    ).annotate(
        voucher_count=Count('id'),
        total_receipts=Sum('receipt'),
        total_payments=Sum('payment'),
        net_amount=Sum('receipt') - Sum('payment')
    ).order_by('-net_amount')
    
    # Render PDF
    template = get_template('adminapp/vouchers/spot_agent_voucher_summary_pdf.html')
    context = {
        'vouchers': vouchers,
        'summary': summary,
        'agent_summary': agent_summary,
        'period_name': period_name,
        'generated_date': timezone.now(),
        'company_name': 'Your Company Name',  # Replace with actual company name
    }
    
    html = template.render(context)
    
    # Create PDF
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="spot_agent_voucher_summary_{date_filter}_{today}.pdf"'
    
    pisa_status = pisa.CreatePDF(html, dest=response)
    
    if pisa_status.err:
        return HttpResponse('We had some errors <pre>' + html + '</pre>')
    
    return response

@check_permission('voucher_view')
def spot_agent_statement_pdf(request, agent_id):
    """Generate PDF statement for specific spot agent"""
    
    agent = get_object_or_404(PurchasingAgent, pk=agent_id)  # Changed to pk to handle string IDs
    
    # Get filter parameters
    date_filter = request.GET.get('date_filter', 'all')
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    
    # Get agent purchases and vouchers
    today = timezone.now().date()
    
    # Filter purchases - use 'date' field instead of 'purchase_date'
    purchases = SpotPurchase.objects.filter(agent=agent)
    
    # Filter vouchers
    vouchers = SpotAgentVoucher.objects.filter(agent=agent)
    
    # Apply date filtering
    if date_filter == 'today':
        purchases = purchases.filter(date=today)  # Changed from purchase_date to date
        vouchers = vouchers.filter(date=today)
        period_name = f"Today ({today})"
    elif date_filter == 'week':
        week_start = today - timedelta(days=today.weekday())
        week_end = week_start + timedelta(days=6)
        purchases = purchases.filter(date__range=[week_start, week_end])  # Changed from purchase_date to date
        vouchers = vouchers.filter(date__range=[week_start, week_end])
        period_name = f"This Week ({week_start} to {week_end})"
    elif date_filter == 'month':
        month_start = today.replace(day=1)
        if today.month == 12:
            month_end = today.replace(year=today.year + 1, month=1, day=1) - timedelta(days=1)
        else:
            month_end = today.replace(month=today.month + 1, day=1) - timedelta(days=1)
        purchases = purchases.filter(date__range=[month_start, month_end])  # Changed from purchase_date to date
        vouchers = vouchers.filter(date__range=[month_start, month_end])
        period_name = f"This Month ({month_start.strftime('%B %Y')})"
    elif date_filter == 'year':
        year_start = today.replace(month=1, day=1)
        year_end = today.replace(month=12, day=31)
        purchases = purchases.filter(date__range=[year_start, year_end])  # Changed from purchase_date to date
        vouchers = vouchers.filter(date__range=[year_start, year_end])
        period_name = f"This Year ({today.year})"
    elif date_filter == 'custom' and start_date and end_date:
        try:
            start_date_obj = datetime.strptime(start_date, '%Y-%m-%d').date()
            end_date_obj = datetime.strptime(end_date, '%Y-%m-%d').date()
            purchases = purchases.filter(date__range=[start_date_obj, end_date_obj])  # Changed from purchase_date to date
            vouchers = vouchers.filter(date__range=[start_date_obj, end_date_obj])
            period_name = f"Custom Range ({start_date} to {end_date})"
        except ValueError:
            period_name = "All Time"
    else:
        period_name = "All Time"
    
    purchases = purchases.order_by('date')  # Changed from purchase_date to date
    vouchers = vouchers.order_by('date')
    
    # Calculate totals
    purchases_total = purchases.aggregate(total=Sum('total_purchase_amount'))['total'] or Decimal('0.00')
    vouchers_summary = vouchers.aggregate(
        total_receipts=Sum('receipt'),
        total_payments=Sum('payment')
    )
    
    total_receipts = vouchers_summary['total_receipts'] or Decimal('0.00')
    total_payments = vouchers_summary['total_payments'] or Decimal('0.00')
    outstanding_balance = purchases_total + total_receipts - total_payments
    
    # Create combined transaction list for chronological order
    transactions = []
    
    for purchase in purchases:
        transactions.append({
            'date': purchase.date,  # Changed from purchase_date to date
            'type': 'Purchase',
            'reference': purchase.voucher_number or f"Purchase #{purchase.id}",  # Use voucher_number if available
            'description': f"Purchase: {purchase.items.count()} items" if hasattr(purchase, 'items') else 'Purchase',
            'debit': purchase.total_purchase_amount,
            'credit': Decimal('0.00'),
            'balance': None  # Will calculate running balance
        })
    
    for voucher in vouchers:
        if voucher.receipt > 0:
            transactions.append({
                'date': voucher.date,
                'type': 'Receipt',
                'reference': voucher.voucher_no,
                'description': voucher.description or 'Amount received from agent',
                'debit': Decimal('0.00'),
                'credit': voucher.receipt,
                'balance': None
            })
        
        if voucher.payment > 0:
            transactions.append({
                'date': voucher.date,
                'type': 'Payment',
                'reference': voucher.voucher_no,
                'description': voucher.description or 'Payment made to agent',
                'debit': voucher.payment,
                'credit': Decimal('0.00'),
                'balance': None
            })
    
    # Sort by date
    transactions.sort(key=lambda x: x['date'])
    
    # Calculate running balance
    running_balance = Decimal('0.00')
    for transaction in transactions:
        running_balance += transaction['debit'] - transaction['credit']
        transaction['balance'] = running_balance
    
    # Render PDF
    template = get_template('adminapp/vouchers/spot_agent_statement_pdf.html')
    context = {
        'agent': agent,
        'transactions': transactions,
        'purchases_total': purchases_total,
        'total_receipts': total_receipts,
        'total_payments': total_payments,
        'outstanding_balance': outstanding_balance,
        'period_name': period_name,
        'generated_date': timezone.now(),
        'company_name': 'Your Company Name',  # Replace with actual company name
    }
    
    html = template.render(context)
    
    # Create PDF
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="spot_agent_statement_{agent.pk}_{date_filter}_{today}.pdf"'
    
    pisa_status = pisa.CreatePDF(html, dest=response)
    
    if pisa_status.err:
        return HttpResponse('We had some errors <pre>' + html + '</pre>')
    
    return response






# --- Supervisor Voucher ---
class SupervisorVoucherCreateView(CustomPermissionMixin,CreateView):
    permission_required = 'adminapp.voucher_add'
    model = SupervisorVoucher
    form_class = SupervisorVoucherForm
    template_name = "adminapp/vouchers/supervisorvoucher_form.html"
    success_url = reverse_lazy("supervisorvoucher_list")

class SupervisorVoucherListView(CustomPermissionMixin,ListView):
    permission_required = 'adminapp.voucher_view'
    model = SupervisorVoucher
    template_name = "adminapp/vouchers/supervisorvoucher_list.html"
    context_object_name = "vouchers"
    ordering = ["-date", "-id"]




# --- Local Purchase Voucher ---fix

@check_permission('voucher_add')
def create_local_purchase_voucher(request):
    if request.method == "POST":
        form = LocalPurchaseVoucherForm(request.POST)
        if form.is_valid():
            voucher = form.save(commit=False)

            # Get combined total for all parties with same name
            party_name = voucher.party.party_name.party
            last_total = LocalPurchaseVoucher.objects.filter(
                party__party_name__party=party_name
            ).aggregate(total=Sum('total_amount'))['total'] or 0

            # Remain amount before this entry
            voucher.remain_amount = last_total

            # Compute new total after receipt/payment
            voucher.total_amount = last_total + (voucher.receipt or 0) - (voucher.payment or 0)

            voucher.save()
            messages.success(request, "Local Purchase Voucher created successfully ✅")
            return redirect("adminapp:localpurchasevoucher_list")
    else:
        # Create custom form with unique party names
        form = LocalPurchaseVoucherForm()
        
        # Get unique party names and create choices
        unique_parties = LocalPurchase.objects.select_related('party_name').values(
            'party_name__party', 'party_name__district', 'party_name__state'
        ).distinct()
        
        # Create a mapping of party names to representative LocalPurchase objects
        party_choices = []
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
        form.fields['party'].choices = [('', '--- Select Party ---')] + party_choices

    return render(request, "adminapp/vouchers/localpurchasevoucher_form.html", {"form": form})

@check_permission('voucher_view')
def get_party_balance(request):
    party_id = request.GET.get("party_id")
    if not party_id:
        return JsonResponse({"error": "No party_id provided"}, status=400)

    try:
        party = LocalPurchase.objects.get(pk=party_id)
        party_name = party.party_name.party

        # 🔹 1. Sum of ALL purchases for parties with same name
        purchase_total = LocalPurchase.objects.filter(
            party_name__party=party_name
        ).aggregate(total=Sum("total_amount"))["total"] or 0

        # 🔹 2. Sum of receipts & payments in vouchers for parties with same name
        voucher_sums = LocalPurchaseVoucher.objects.filter(
            party__party_name__party=party_name
        ).aggregate(
            total_receipt=Sum("receipt"),
            total_payment=Sum("payment"),
        )

        total_receipt = voucher_sums["total_receipt"] or 0
        total_payment = voucher_sums["total_payment"] or 0

        # 🔹 3. Calculate remaining balance
        remain_amount = purchase_total + total_receipt - total_payment

        return JsonResponse({
            "purchase_total": float(purchase_total),
            "total_receipt": float(total_receipt),
            "total_payment": float(total_payment),
            "remain_amount": float(remain_amount),
            "party_name": party_name,
        })

    except LocalPurchase.DoesNotExist:
        return JsonResponse({"error": "Party not found"}, status=404)

@check_permission('voucher_view')
def localpurchasevoucher_list_with_summary(request):
    """Enhanced list view with transaction summary and filtering"""
    
    # Get filter parameters
    date_filter = request.GET.get('date_filter', 'all')  # all, today, week, month, year, custom
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    party_filter = request.GET.get('party')
    search_query = request.GET.get('search', '')
    
    # Base queryset
    vouchers = LocalPurchaseVoucher.objects.select_related(
        'party__party_name'
    ).order_by('-date', '-id')
    
    # Apply date filtering
    today = timezone.now().date()
    
    if date_filter == 'today':
        vouchers = vouchers.filter(date=today)
        period_name = f"Today ({today})"
    elif date_filter == 'week':
        week_start = today - timedelta(days=today.weekday())
        week_end = week_start + timedelta(days=6)
        vouchers = vouchers.filter(date__range=[week_start, week_end])
        period_name = f"This Week ({week_start} to {week_end})"
    elif date_filter == 'month':
        month_start = today.replace(day=1)
        if today.month == 12:
            month_end = today.replace(year=today.year + 1, month=1, day=1) - timedelta(days=1)
        else:
            month_end = today.replace(month=today.month + 1, day=1) - timedelta(days=1)
        vouchers = vouchers.filter(date__range=[month_start, month_end])
        period_name = f"This Month ({month_start.strftime('%B %Y')})"
    elif date_filter == 'year':
        year_start = today.replace(month=1, day=1)
        year_end = today.replace(month=12, day=31)
        vouchers = vouchers.filter(date__range=[year_start, year_end])
        period_name = f"This Year ({today.year})"
    elif date_filter == 'custom' and start_date and end_date:
        try:
            start_date_obj = datetime.strptime(start_date, '%Y-%m-%d').date()
            end_date_obj = datetime.strpython(end_date, '%Y-%m-%d').date()
            vouchers = vouchers.filter(date__range=[start_date_obj, end_date_obj])
            period_name = f"Custom Range ({start_date} to {end_date})"
        except ValueError:
            period_name = "All Time"
    else:
        period_name = "All Time"
    
    # Apply party filtering
    if party_filter:
        vouchers = vouchers.filter(party_id=party_filter)
    
    # Apply search filtering
    if search_query:
        vouchers = vouchers.filter(
            Q(voucher_no__icontains=search_query) |
            Q(party__party_name__party__icontains=search_query) |
            Q(party__party_name__district__icontains=search_query) |
            Q(party__party_name__state__icontains=search_query) |
            Q(description__icontains=search_query)
        )
    
    # Calculate summary statistics
    summary = vouchers.aggregate(
        total_vouchers=Count('id'),
        total_receipts=Sum('receipt'),
        total_payments=Sum('payment'),
        net_amount=Sum('receipt') - Sum('payment')
    )
    
    # Convert None to 0 for display
    for key, value in summary.items():
        if value is None:
            summary[key] = Decimal('0.00')
    
    # Get party-wise summary
    party_summary = vouchers.values(
        'party__party_name__party',
        'party__party_name__district', 
        'party__party_name__state'
    ).annotate(
        voucher_count=Count('id'),
        total_receipts=Sum('receipt'),
        total_payments=Sum('payment'),
        net_amount=Sum('receipt') - Sum('payment')
    ).order_by('-net_amount')
    
    # Pagination
    paginator = Paginator(vouchers, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    # Get all unique parties for filter dropdown
    unique_parties = LocalPurchase.objects.select_related('party_name').values(
        'id', 'party_name__party', 'party_name__district', 'party_name__state'
    ).distinct()
    
    # Create party choices for dropdown
    party_choices = []
    party_mapping = {}
    
    for party_data in unique_parties:
        party_name = party_data['party_name__party']
        if party_name not in party_mapping:
            party_mapping[party_name] = party_data
            display_name = f"{party_name}"
            if party_data['party_name__district']:
                display_name += f" - {party_data['party_name__district']}"
            if party_data['party_name__state']:
                display_name += f", {party_data['party_name__state']}"
            
            party_choices.append((party_data['id'], display_name))
    
    context = {
        'vouchers': page_obj,
        'summary': summary,
        'party_summary': party_summary,
        'all_parties': party_choices,
        'search_query': search_query,
        'date_filter': date_filter,
        'start_date': start_date,
        'end_date': end_date,
        'party_filter': party_filter,
        'period_name': period_name,
        'total_count': paginator.count,
        'today': today,
    }
    
    return render(request, "adminapp/vouchers/localpurchasevoucher_list_summary.html", context)

@check_permission('voucher_view')
def localpurchase_voucher_summary_pdf(request):
    """Generate PDF summary report for local purchase vouchers"""
    
    # Get same filter parameters as list view
    date_filter = request.GET.get('date_filter', 'all')
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    party_filter = request.GET.get('party')
    
    # Apply same filtering logic
    vouchers = LocalPurchaseVoucher.objects.select_related(
        'party__party_name'
    ).order_by('-date', '-id')
    
    today = timezone.now().date()
    
    if date_filter == 'today':
        vouchers = vouchers.filter(date=today)
        period_name = f"Today ({today})"
    elif date_filter == 'week':
        week_start = today - timedelta(days=today.weekday())
        week_end = week_start + timedelta(days=6)
        vouchers = vouchers.filter(date__range=[week_start, week_end])
        period_name = f"This Week ({week_start} to {week_end})"
    elif date_filter == 'month':
        month_start = today.replace(day=1)
        if today.month == 12:
            month_end = today.replace(year=today.year + 1, month=1, day=1) - timedelta(days=1)
        else:
            month_end = today.replace(month=today.month + 1, day=1) - timedelta(days=1)
        vouchers = vouchers.filter(date__range=[month_start, month_end])
        period_name = f"This Month ({month_start.strftime('%B %Y')})"
    elif date_filter == 'year':
        year_start = today.replace(month=1, day=1)
        year_end = today.replace(month=12, day=31)
        vouchers = vouchers.filter(date__range=[year_start, year_end])
        period_name = f"This Year ({today.year})"
    elif date_filter == 'custom' and start_date and end_date:
        try:
            start_date_obj = datetime.strptime(start_date, '%Y-%m-%d').date()
            end_date_obj = datetime.strptime(end_date, '%Y-%m-%d').date()
            vouchers = vouchers.filter(date__range=[start_date_obj, end_date_obj])
            period_name = f"Custom Range ({start_date} to {end_date})"
        except ValueError:
            period_name = "All Time"
    else:
        period_name = "All Time"
    
    if party_filter:
        vouchers = vouchers.filter(party_id=party_filter)
    
    # Calculate summary
    summary = vouchers.aggregate(
        total_vouchers=Count('id'),
        total_receipts=Sum('receipt'),
        total_payments=Sum('payment'),
        net_amount=Sum('receipt') - Sum('payment')
    )
    
    for key, value in summary.items():
        if value is None:
            summary[key] = Decimal('0.00')
    
    # Get party-wise summary
    party_summary = vouchers.values(
        'party__party_name__party',
        'party__party_name__district',
        'party__party_name__state'
    ).annotate(
        voucher_count=Count('id'),
        total_receipts=Sum('receipt'),
        total_payments=Sum('payment'),
        net_amount=Sum('receipt') - Sum('payment')
    ).order_by('-net_amount')
    
    # Render PDF
    template = get_template('adminapp/vouchers/localpurchase_voucher_summary_pdf.html')
    context = {
        'vouchers': vouchers,
        'summary': summary,
        'party_summary': party_summary,
        'period_name': period_name,
        'generated_date': timezone.now(),
        'company_name': 'Your Company Name',  # Replace with actual company name
    }
    
    html = template.render(context)
    
    # Create PDF
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="localpurchase_voucher_summary_{date_filter}_{today}.pdf"'
    
    pisa_status = pisa.CreatePDF(html, dest=response)
    
    if pisa_status.err:
        return HttpResponse('We had some errors <pre>' + html + '</pre>')
    
    return response

@check_permission('voucher_view')
def localpurchase_party_statement_pdf(request, party_id):
    """Generate PDF statement for specific local purchase party"""
    
    party = get_object_or_404(LocalPurchase, id=party_id)
    party_name = party.party_name.party
    
    # Get filter parameters
    date_filter = request.GET.get('date_filter', 'all')
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    
    today = timezone.now().date()
    
    # Get all purchases for parties with same name
    purchases = LocalPurchase.objects.filter(
        party_name__party=party_name
    )
    
    # Get all vouchers for parties with same name
    vouchers = LocalPurchaseVoucher.objects.filter(
        party__party_name__party=party_name
    )
    
    # Apply date filtering
    if date_filter == 'today':
        purchases = purchases.filter(date=today)
        vouchers = vouchers.filter(date=today)
        period_name = f"Today ({today})"
    elif date_filter == 'week':
        week_start = today - timedelta(days=today.weekday())
        week_end = week_start + timedelta(days=6)
        purchases = purchases.filter(date__range=[week_start, week_end])
        vouchers = vouchers.filter(date__range=[week_start, week_end])
        period_name = f"This Week ({week_start} to {week_end})"
    elif date_filter == 'month':
        month_start = today.replace(day=1)
        if today.month == 12:
            month_end = today.replace(year=today.year + 1, month=1, day=1) - timedelta(days=1)
        else:
            month_end = today.replace(month=today.month + 1, day=1) - timedelta(days=1)
        purchases = purchases.filter(date__range=[month_start, month_end])
        vouchers = vouchers.filter(date__range=[month_start, month_end])
        period_name = f"This Month ({month_start.strftime('%B %Y')})"
    elif date_filter == 'year':
        year_start = today.replace(month=1, day=1)
        year_end = today.replace(month=12, day=31)
        purchases = purchases.filter(date__range=[year_start, year_end])
        vouchers = vouchers.filter(date__range=[year_start, year_end])
        period_name = f"This Year ({today.year})"
    elif date_filter == 'custom' and start_date and end_date:
        try:
            start_date_obj = datetime.strptime(start_date, '%Y-%m-%d').date()
            end_date_obj = datetime.strptime(end_date, '%Y-%m-%d').date()
            purchases = purchases.filter(date__range=[start_date_obj, end_date_obj])
            vouchers = vouchers.filter(date__range=[start_date_obj, end_date_obj])
            period_name = f"Custom Range ({start_date} to {end_date})"
        except ValueError:
            period_name = "All Time"
    else:
        period_name = "All Time"
    
    purchases = purchases.order_by('date')
    vouchers = vouchers.order_by('date')
    
    # Calculate totals
    purchases_total = purchases.aggregate(total=Sum('total_amount'))['total'] or Decimal('0.00')
    vouchers_summary = vouchers.aggregate(
        total_receipts=Sum('receipt'),
        total_payments=Sum('payment')
    )
    
    total_receipts = vouchers_summary['total_receipts'] or Decimal('0.00')
    total_payments = vouchers_summary['total_payments'] or Decimal('0.00')
    outstanding_balance = purchases_total + total_receipts - total_payments
    
    # Create combined transaction list for chronological order
    transactions = []
    
    for purchase in purchases:
        transactions.append({
            'date': purchase.date,
            'type': 'Purchase',
            'reference': purchase.bill_number or f"Purchase #{purchase.id}",
            'description': f"Local Purchase - {purchase.party_name.party}",
            'debit': purchase.total_amount,
            'credit': Decimal('0.00'),
            'balance': None  # Will calculate running balance
        })
    
    for voucher in vouchers:
        if voucher.receipt > 0:
            transactions.append({
                'date': voucher.date,
                'type': 'Receipt',
                'reference': voucher.voucher_no,
                'description': voucher.description or 'Amount received',
                'debit': Decimal('0.00'),
                'credit': voucher.receipt,
                'balance': None
            })
        
        if voucher.payment > 0:
            transactions.append({
                'date': voucher.date,
                'type': 'Payment',
                'reference': voucher.voucher_no,
                'description': voucher.description or 'Payment made',
                'debit': voucher.payment,
                'credit': Decimal('0.00'),
                'balance': None
            })
    
    # Sort by date
    transactions.sort(key=lambda x: x['date'])
    
    # Calculate running balance
    running_balance = Decimal('0.00')
    for transaction in transactions:
        running_balance += transaction['debit'] - transaction['credit']
        transaction['balance'] = running_balance
    
    # Render PDF
    template = get_template('adminapp/vouchers/localpurchase_party_statement_pdf.html')
    context = {
        'party': party,
        'party_name': party_name,
        'transactions': transactions,
        'purchases_total': purchases_total,
        'total_receipts': total_receipts,
        'total_payments': total_payments,
        'outstanding_balance': outstanding_balance,
        'period_name': period_name,
        'generated_date': timezone.now(),
        'company_name': 'Your Company Name',  # Replace with actual company name
    }
    
    html = template.render(context)
    
    # Create PDF
    response = HttpResponse(content_type='application/pdf')
    safe_party_name = re.sub(r'[^\w\s-]', '', party_name).strip()
    response['Content-Disposition'] = f'attachment; filename="localpurchase_statement_{safe_party_name}_{date_filter}_{today}.pdf"'
    
    pisa_status = pisa.CreatePDF(html, dest=response)
    
    if pisa_status.err:
        return HttpResponse('We had some errors <pre>' + html + '</pre>')
    
    return response



# --- Peeling Shed Voucher --- fix
@check_permission('voucher_add')
def create_peeling_shed_voucher(request):
    """Enhanced create voucher view with better calculation handling"""
    if request.method == 'POST':
        form = PeelingShedVoucherForm(request.POST)
        
        if form.is_valid():
            try:
                with transaction.atomic():
                    voucher = form.save(commit=False)
                    shed = voucher.shed
                    
                    # Get current transaction amounts
                    current_receipt = form.cleaned_data.get('receipt') or Decimal('0.00')
                    current_payment = form.cleaned_data.get('payment') or Decimal('0.00')
                    
                    # Calculate base amount from work done
                    base_calculation = calculate_shed_base_amount(shed)
                    if base_calculation['error']:
                        messages.error(request, base_calculation['error'])
                        return render(request, 'adminapp/vouchers/peelingshedvoucher_form.html', {
                            'form': form,
                            'sheds_with_freezing': get_sheds_with_freezing(),
                        })
                    
                    # Get previous cumulative amounts
                    previous_totals = get_cumulative_amounts_for_shed(shed, exclude_voucher=None)
                    
                    # Set voucher amounts
                    voucher.total_amount = base_calculation['base_amount']
                    voucher.receipt = current_receipt
                    voucher.payment = current_payment
                    
                    # Calculate new balance
                    new_total_receipts = previous_totals['total_receipts'] + current_receipt
                    new_total_payments = previous_totals['total_payments'] + current_payment
                    voucher.remain_amount = base_calculation['base_amount'] + new_total_receipts - new_total_payments
                    
                    # Save voucher
                    voucher.save()
                    
                    # Create success message with detailed breakdown
                    success_msg = (
                        f'Peeling Shed Voucher #{voucher.voucher_no} created successfully! '
                        f'Base Work Value: ₹{base_calculation["base_amount"]}, '
                        f'Total Receipts: ₹{new_total_receipts}, '
                        f'Total Payments: ₹{new_total_payments}, '
                        f'New Balance: ₹{voucher.remain_amount}'
                    )
                    
                    # Add balance status
                    if voucher.remain_amount < 0:
                        success_msg += f' (Customer owes ₹{abs(voucher.remain_amount)})'
                    elif voucher.remain_amount == 0:
                        success_msg += ' (Account fully settled)'
                    else:
                        success_msg += f' (₹{voucher.remain_amount} owed to customer)'
                    
                    messages.success(request, success_msg)
                    return redirect('adminapp:peeling_shed_voucher_list')
                    
            except Exception as e:
                logger.error(f"Error creating peeling shed voucher: {str(e)}")
                messages.error(request, f"Error creating voucher: {str(e)}")
    else:
        form = PeelingShedVoucherForm()
    
    context = {
        'form': form,
        'sheds_with_freezing': get_sheds_with_freezing(),
    }
    
    return render(request, 'adminapp/vouchers/peelingshedvoucher_form.html', context)

def get_sheds_with_freezing():
    """Get sheds that have completed freezing entries"""
    return Shed.objects.filter(
        freezing_shed_items__freezing_entry__freezing_status='complete'
    ).distinct().order_by('name')

@check_permission('voucher_view')
def get_cumulative_amounts_for_shed(shed, exclude_voucher=None):
    """
    Get cumulative receipts and payments from all vouchers for this shed
    Args:
        shed: The shed object
        exclude_voucher: Voucher to exclude (for updates)
    Returns:
        dict: {'total_receipts': Decimal, 'total_payments': Decimal, 'voucher_count': int}
    """
    queryset = PeelingShedVoucher.objects.filter(shed=shed)
    
    if exclude_voucher:
        queryset = queryset.exclude(id=exclude_voucher.id)
    
    totals = queryset.aggregate(
        total_receipts=Sum('receipt'),
        total_payments=Sum('payment')
    )
    
    return {
        'total_receipts': totals['total_receipts'] or Decimal('0.00'),
        'total_payments': totals['total_payments'] or Decimal('0.00'),
        'voucher_count': queryset.count()
    }

def calculate_shed_base_amount(shed):
    """
    Calculate base amount for a shed based on freezing entries and shed item rates
    Returns:
        dict: {
            'base_amount': Decimal,
            'calculation_breakdown': list,
            'error': str or None,
            'warnings': list
        }
    """
    try:
        # Get completed freezing items for this shed
        freezing_items = FreezingEntrySpotItem.objects.filter(
            shed=shed,
            freezing_entry__freezing_status='complete'
        ).select_related('peeling_type', 'item', 'freezing_entry')
        
        if not freezing_items.exists():
            return {
                'base_amount': Decimal('0.00'),
                'calculation_breakdown': [],
                'error': 'No completed freezing entries found for this shed',
                'warnings': []
            }
        
        # Group by peeling type and sum quantities
        peeling_summary = {}
        for freezing_item in freezing_items:
            if freezing_item.peeling_type:
                peeling_type_id = freezing_item.peeling_type.id
                if peeling_type_id not in peeling_summary:
                    peeling_summary[peeling_type_id] = {
                        'peeling_type': freezing_item.peeling_type,
                        'total_kg': Decimal('0.00'),
                        'entries': []
                    }
                peeling_summary[peeling_type_id]['total_kg'] += freezing_item.kg
                peeling_summary[peeling_type_id]['entries'].append({
                    'entry_id': freezing_item.freezing_entry.id,
                    'kg': freezing_item.kg,
                    'date': freezing_item.freezing_entry.created_at
                })
        
        # Calculate amount for each peeling type using shed item rates
        calculation_breakdown = []
        total_amount = Decimal('0.00')
        warnings = []
        
        for peeling_data in peeling_summary.values():
            peeling_type = peeling_data['peeling_type']
            total_kg = peeling_data['total_kg']
            
            try:
                # Get rate from ShedItem for this peeling type
                shed_item = ShedItem.objects.get(
                    shed=shed,
                    item_type=peeling_type
                )
                rate = shed_item.amount
                amount = total_kg * rate
                total_amount += amount
                
                calculation_breakdown.append({
                    'peeling_type': peeling_type.name,
                    'peeling_type_id': peeling_type.id,
                    'quantity': str(total_kg),
                    'rate': str(rate),
                    'amount': str(amount),
                    'entries_count': len(peeling_data['entries']),
                    'error': None
                })
                
            except ShedItem.DoesNotExist:
                warnings.append(f"No rate configured for {peeling_type.name} in shed {shed.name}")
                calculation_breakdown.append({
                    'peeling_type': peeling_type.name,
                    'peeling_type_id': peeling_type.id,
                    'quantity': str(total_kg),
                    'rate': 'N/A',
                    'amount': '0.00',
                    'entries_count': len(peeling_data['entries']),
                    'error': 'Rate not configured in shed items'
                })
            except Exception as e:
                logger.error(f"Error calculating amount for {peeling_type.name}: {str(e)}")
                warnings.append(f"Calculation error for {peeling_type.name}: {str(e)}")
        
        return {
            'base_amount': total_amount,
            'calculation_breakdown': calculation_breakdown,
            'error': None,
            'warnings': warnings
        }
        
    except Exception as e:
        logger.error(f"Error in calculate_shed_base_amount: {str(e)}")
        return {
            'base_amount': Decimal('0.00'),
            'calculation_breakdown': [],
            'error': f'Calculation error: {str(e)}',
            'warnings': []
        }

@csrf_exempt
@require_http_methods(["POST"])
@check_permission('voucher_view')
def get_shed_calculation_preview(request):
    """
    Enhanced AJAX view to preview calculation for selected shed with complete financial summary
    """
    try:
        data = json.loads(request.body)
        shed_id = data.get('shed_id')
        current_receipt = Decimal(str(data.get('receipt', '0') or '0'))
        current_payment = Decimal(str(data.get('payment', '0') or '0'))
        
        if not shed_id:
            return JsonResponse({'error': 'Shed ID is required'}, status=400)
        
        try:
            shed = get_object_or_404(Shed, id=shed_id)
            
            # Calculate base amount using enhanced function
            base_calculation = calculate_shed_base_amount(shed)
            
            if base_calculation['error']:
                return JsonResponse({'error': base_calculation['error']}, status=404)
            
            # Get cumulative amounts from previous vouchers
            cumulative_totals = get_cumulative_amounts_for_shed(shed)
            
            # Calculate new totals including current transaction
            new_total_receipts = cumulative_totals['total_receipts'] + current_receipt
            new_total_payments = cumulative_totals['total_payments'] + current_payment
            new_balance = base_calculation['base_amount'] + new_total_receipts - new_total_payments
            
            # Calculate previous balance for comparison
            previous_balance = base_calculation['base_amount'] + cumulative_totals['total_receipts'] - cumulative_totals['total_payments']
            balance_change = new_balance - previous_balance
            
            # Prepare response data
            response_data = {
                'success': True,
                'shed_name': f"{shed.name} - {shed.code}",
                'shed_id': shed.id,
                
                # Base calculation data
                'calculation_preview': base_calculation['calculation_breakdown'],
                'base_amount': str(base_calculation['base_amount']),
                
                # Previous cumulative data
                'cumulative_receipts': str(cumulative_totals['total_receipts']),
                'cumulative_payments': str(cumulative_totals['total_payments']),
                'previous_balance': str(previous_balance),
                'voucher_count': cumulative_totals['voucher_count'],
                
                # Current transaction data
                'current_receipt': str(current_receipt),
                'current_payment': str(current_payment),
                
                # New totals
                'new_total_receipts': str(new_total_receipts),
                'new_total_payments': str(new_total_payments),
                'new_balance': str(new_balance),
                'balance_change': str(balance_change),
                
                # Additional info
                'warnings': base_calculation['warnings'],
                'has_warnings': len(base_calculation['warnings']) > 0,
                'balance_status': get_balance_status(new_balance),
                
                # Statistics
                'stats': {
                    'total_peeling_types': len([item for item in base_calculation['calculation_breakdown'] if not item['error']]),
                    'missing_rates': len([item for item in base_calculation['calculation_breakdown'] if item['error']]),
                    'total_work_entries': sum(item['entries_count'] for item in base_calculation['calculation_breakdown']),
                }
            }
            
            return JsonResponse(response_data)
            
        except Shed.DoesNotExist:
            return JsonResponse({'error': 'Shed not found'}, status=404)
            
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON data'}, status=400)
    except ValueError as e:
        return JsonResponse({'error': f'Invalid number format: {str(e)}'}, status=400)
    except Exception as e:
        logger.error(f"Error in get_shed_calculation_preview: {str(e)}")
        return JsonResponse({'error': f'Server error: {str(e)}'}, status=500)

@check_permission('voucher_view')
def get_balance_status(balance):
    """
    Get human-readable balance status
    Args:
        balance: Decimal balance amount
    Returns:
        dict: {'status': str, 'message': str, 'class': str}
    """
    if balance > 0:
        return {
            'status': 'positive',
            'message': f'₹{balance} owed to customer',
            'class': 'text-success'
        }
    elif balance < 0:
        return {
            'status': 'negative', 
            'message': f'Customer owes ₹{abs(balance)}',
            'class': 'text-danger'
        }
    else:
        return {
            'status': 'settled',
            'message': 'Account fully settled',
            'class': 'text-success'
        }

@check_permission('voucher_edit')
def update_peeling_shed_voucher(request, voucher_id):
    """
    Enhanced update view that recalculates amounts correctly
    """
    voucher = get_object_or_404(PeelingShedVoucher, id=voucher_id)
    
    if request.method == 'POST':
        form = PeelingShedVoucherForm(request.POST, instance=voucher)
        
        if form.is_valid():
            try:
                with transaction.atomic():
                    # Get current values
                    old_receipt = voucher.receipt
                    old_payment = voucher.payment
                    
                    updated_voucher = form.save(commit=False)
                    new_receipt = form.cleaned_data.get('receipt') or Decimal('0.00')
                    new_payment = form.cleaned_data.get('payment') or Decimal('0.00')
                    
                    # Recalculate base amount (in case shed items changed)
                    base_calculation = calculate_shed_base_amount(updated_voucher.shed)
                    if base_calculation['error']:
                        messages.error(request, f"Calculation error: {base_calculation['error']}")
                        return render(request, 'adminapp/vouchers/peelingshedvoucher_form.html', {
                            'form': form,
                            'voucher': voucher,
                            'is_update': True,
                        })
                    
                    # Get cumulative amounts excluding current voucher
                    cumulative_totals = get_cumulative_amounts_for_shed(
                        updated_voucher.shed, 
                        exclude_voucher=voucher
                    )
                    
                    # Update voucher amounts
                    updated_voucher.total_amount = base_calculation['base_amount']
                    updated_voucher.receipt = new_receipt
                    updated_voucher.payment = new_payment
                    
                    # Calculate new balance
                    new_total_receipts = cumulative_totals['total_receipts'] + new_receipt
                    new_total_payments = cumulative_totals['total_payments'] + new_payment
                    updated_voucher.remain_amount = base_calculation['base_amount'] + new_total_receipts - new_total_payments
                    
                    updated_voucher.save()
                    
                    # Show what changed
                    changes = []
                    if old_receipt != new_receipt:
                        changes.append(f"Receipt: ₹{old_receipt} → ₹{new_receipt}")
                    if old_payment != new_payment:
                        changes.append(f"Payment: ₹{old_payment} → ₹{new_payment}")
                    
                    change_summary = ", ".join(changes) if changes else "No amount changes"
                    
                    messages.success(
                        request,
                        f'Voucher updated successfully! {change_summary}. '
                        f'New balance: ₹{updated_voucher.remain_amount}'
                    )
                    
                    return redirect('adminapp:peeling_shed_voucher_list')
                    
            except Exception as e:
                logger.error(f"Error updating voucher: {str(e)}")
                messages.error(request, f"Error updating voucher: {str(e)}")
    else:
        form = PeelingShedVoucherForm(instance=voucher)
    
    context = {
        'form': form,
        'voucher': voucher,
        'is_update': True,
        'sheds_with_freezing': get_sheds_with_freezing(),
    }
    
    return render(request, 'adminapp/vouchers/peelingshedvoucher_form.html', context)

@check_permission('voucher_view')
def peeling_shed_voucher_detail(request, voucher_id):
    """
    Enhanced detail view showing complete calculation breakdown
    """
    voucher = get_object_or_404(PeelingShedVoucher, id=voucher_id)
    
    # Get calculation breakdown
    base_calculation = calculate_shed_base_amount(voucher.shed)
    
    # Get all vouchers for this shed to show cumulative progression
    all_vouchers = PeelingShedVoucher.objects.filter(
        shed=voucher.shed
    ).order_by('date', 'created_at')
    
    # Calculate running totals
    running_receipts = Decimal('0.00')
    running_payments = Decimal('0.00')
    voucher_progression = []
    
    for v in all_vouchers:
        running_receipts += v.receipt
        running_payments += v.payment
        running_balance = base_calculation['base_amount'] + running_receipts - running_payments
        
        voucher_progression.append({
            'voucher': v,
            'running_receipts': running_receipts,
            'running_payments': running_payments,
            'running_balance': running_balance,
            'is_current': v.id == voucher.id
        })
    
    context = {
        'voucher': voucher,
        'base_calculation': base_calculation,
        'voucher_progression': voucher_progression,
        'balance_status': get_balance_status(voucher.remain_amount),
    }
    
    return render(request, 'adminapp/vouchers/peelingshedvoucher_detail.html', context)

class PeelingShedVoucherListView(CustomPermissionMixin,ListView):
    permission_required = 'adminapp.voucher_view'
    model = PeelingShedVoucher
    template_name = "adminapp/vouchers/peelingshedvoucher_list.html"
    context_object_name = "vouchers"
    ordering = ["-date", "-id"]

@check_permission('voucher_view')
def peeling_shed_voucher_list_with_summary(request):
    """Enhanced list view with transaction summary and filtering"""
    
    # Get filter parameters
    date_filter = request.GET.get('date_filter', 'all')  # all, today, week, month, year, custom
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    shed_filter = request.GET.get('shed')
    search_query = request.GET.get('search', '')
    
    # Base queryset
    vouchers = PeelingShedVoucher.objects.select_related('shed').order_by('-date', '-id')
    
    # Apply date filtering
    today = timezone.now().date()
    
    if date_filter == 'today':
        vouchers = vouchers.filter(date=today)
        period_name = f"Today ({today})"
    elif date_filter == 'week':
        week_start = today - timedelta(days=today.weekday())
        week_end = week_start + timedelta(days=6)
        vouchers = vouchers.filter(date__range=[week_start, week_end])
        period_name = f"This Week ({week_start} to {week_end})"
    elif date_filter == 'month':
        month_start = today.replace(day=1)
        if today.month == 12:
            month_end = today.replace(year=today.year + 1, month=1, day=1) - timedelta(days=1)
        else:
            month_end = today.replace(month=today.month + 1, day=1) - timedelta(days=1)
        vouchers = vouchers.filter(date__range=[month_start, month_end])
        period_name = f"This Month ({month_start.strftime('%B %Y')})"
    elif date_filter == 'year':
        year_start = today.replace(month=1, day=1)
        year_end = today.replace(month=12, day=31)
        vouchers = vouchers.filter(date__range=[year_start, year_end])
        period_name = f"This Year ({today.year})"
    elif date_filter == 'custom' and start_date and end_date:
        try:
            start_date_obj = datetime.strptime(start_date, '%Y-%m-%d').date()
            end_date_obj = datetime.strptime(end_date, '%Y-%m-%d').date()
            vouchers = vouchers.filter(date__range=[start_date_obj, end_date_obj])
            period_name = f"Custom Range ({start_date} to {end_date})"
        except ValueError:
            period_name = "All Time"
    else:
        period_name = "All Time"
    
    # Apply shed filtering
    if shed_filter:
        vouchers = vouchers.filter(shed_id=shed_filter)
    
    # Apply search filtering
    if search_query:
        vouchers = vouchers.filter(
            Q(voucher_no__icontains=search_query) |
            Q(shed__name__icontains=search_query) |
            Q(shed__code__icontains=search_query) |
            Q(description__icontains=search_query)
        )
    
    # Calculate summary statistics
    summary = vouchers.aggregate(
        total_vouchers=Count('id'),
        total_receipts=Sum('receipt'),
        total_payments=Sum('payment'),
        total_work_amount=Sum('total_amount'),
        total_remaining=Sum('remain_amount')
    )
    
    # Convert None to 0 for display
    for key, value in summary.items():
        if value is None:
            summary[key] = Decimal('0.00') if 'total' in key or 'remaining' in key else 0
    
    # Calculate net amount (receipts - payments)
    summary['net_amount'] = summary['total_receipts'] - summary['total_payments']
    
    # Get shed-wise summary
    shed_summary = vouchers.values(
        'shed__id', 
        'shed__name',
        'shed__code'
    ).annotate(
        voucher_count=Count('id'),
        total_receipts=Sum('receipt'),
        total_payments=Sum('payment'),
        total_work_amount=Sum('total_amount'),
        total_remaining=Sum('remain_amount'),
        net_amount=Sum('receipt') - Sum('payment')
    ).order_by('-total_remaining')
    
    # Pagination
    paginator = Paginator(vouchers, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    # Get all sheds for filter dropdown
    all_sheds = Shed.objects.all().order_by('name')
    
    context = {
        'vouchers': page_obj,
        'summary': summary,
        'shed_summary': shed_summary,
        'all_sheds': all_sheds,
        'search_query': search_query,
        'date_filter': date_filter,
        'start_date': start_date,
        'end_date': end_date,
        'shed_filter': shed_filter,
        'period_name': period_name,
        'total_count': paginator.count,
        'today': today,
    }
    
    return render(request, "adminapp/vouchers/peelingshedvoucher_list_summary.html", context)

@check_permission('voucher_view')
def peeling_shed_voucher_summary_pdf(request):
    """Generate PDF summary report for Peeling Shed Vouchers"""
    
    # Get same filter parameters as list view
    date_filter = request.GET.get('date_filter', 'all')
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    shed_filter = request.GET.get('shed')
    
    # Apply same filtering logic
    vouchers = PeelingShedVoucher.objects.select_related('shed').order_by('-date', '-id')
    
    today = timezone.now().date()
    
    if date_filter == 'today':
        vouchers = vouchers.filter(date=today)
        period_name = f"Today ({today})"
    elif date_filter == 'week':
        week_start = today - timedelta(days=today.weekday())
        week_end = week_start + timedelta(days=6)
        vouchers = vouchers.filter(date__range=[week_start, week_end])
        period_name = f"This Week ({week_start} to {week_end})"
    elif date_filter == 'month':
        month_start = today.replace(day=1)
        if today.month == 12:
            month_end = today.replace(year=today.year + 1, month=1, day=1) - timedelta(days=1)
        else:
            month_end = today.replace(month=today.month + 1, day=1) - timedelta(days=1)
        vouchers = vouchers.filter(date__range=[month_start, month_end])
        period_name = f"This Month ({month_start.strftime('%B %Y')})"
    elif date_filter == 'year':
        year_start = today.replace(month=1, day=1)
        year_end = today.replace(month=12, day=31)
        vouchers = vouchers.filter(date__range=[year_start, year_end])
        period_name = f"This Year ({today.year})"
    elif date_filter == 'custom' and start_date and end_date:
        try:
            start_date_obj = datetime.strptime(start_date, '%Y-%m-%d').date()
            end_date_obj = datetime.strptime(end_date, '%Y-%m-%d').date()
            vouchers = vouchers.filter(date__range=[start_date_obj, end_date_obj])
            period_name = f"Custom Range ({start_date} to {end_date})"
        except ValueError:
            period_name = "All Time"
    else:
        period_name = "All Time"
    
    if shed_filter:
        vouchers = vouchers.filter(shed_id=shed_filter)
    
    # Calculate summary
    summary = vouchers.aggregate(
        total_vouchers=Count('id'),
        total_receipts=Sum('receipt'),
        total_payments=Sum('payment'),
        total_work_amount=Sum('total_amount'),
        total_remaining=Sum('remain_amount')
    )
    
    for key, value in summary.items():
        if value is None:
            summary[key] = Decimal('0.00') if 'total' in key or 'remaining' in key else 0
    
    summary['net_amount'] = summary['total_receipts'] - summary['total_payments']
    
    # Get shed-wise summary
    shed_summary = vouchers.values(
        'shed__name',
        'shed__code'
    ).annotate(
        voucher_count=Count('id'),
        total_receipts=Sum('receipt'),
        total_payments=Sum('payment'),
        total_work_amount=Sum('total_amount'),
        total_remaining=Sum('remain_amount'),
        net_amount=Sum('receipt') - Sum('payment')
    ).order_by('-total_remaining')
    
    # Render PDF
    template = get_template('adminapp/vouchers/peeling_shed_voucher_summary_pdf.html')
    context = {
        'vouchers': vouchers,
        'summary': summary,
        'shed_summary': shed_summary,
        'period_name': period_name,
        'generated_date': timezone.now(),
        'company_name': 'Your Company Name',  # Replace with actual company name
    }
    
    html = template.render(context)
    
    # Create PDF
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="peeling_shed_voucher_summary_{date_filter}_{today}.pdf"'
    
    pisa_status = pisa.CreatePDF(html, dest=response)
    
    if pisa_status.err:
        return HttpResponse('We had some errors <pre>' + html + '</pre>')
    
    return response

@check_permission('voucher_view')
def shed_statement_pdf(request, shed_id):
    """Generate PDF statement for specific shed"""
    
    shed = get_object_or_404(Shed, id=shed_id)
    
    # Get filter parameters
    date_filter = request.GET.get('date_filter', 'all')
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    
    today = timezone.now().date()
    
    # Filter vouchers for this shed
    vouchers = PeelingShedVoucher.objects.filter(shed=shed)
    
    # Apply date filtering
    if date_filter == 'today':
        vouchers = vouchers.filter(date=today)
        period_name = f"Today ({today})"
    elif date_filter == 'week':
        week_start = today - timedelta(days=today.weekday())
        week_end = week_start + timedelta(days=6)
        vouchers = vouchers.filter(date__range=[week_start, week_end])
        period_name = f"This Week ({week_start} to {week_end})"
    elif date_filter == 'month':
        month_start = today.replace(day=1)
        if today.month == 12:
            month_end = today.replace(year=today.year + 1, month=1, day=1) - timedelta(days=1)
        else:
            month_end = today.replace(month=today.month + 1, day=1) - timedelta(days=1)
        vouchers = vouchers.filter(date__range=[month_start, month_end])
        period_name = f"This Month ({month_start.strftime('%B %Y')})"
    elif date_filter == 'year':
        year_start = today.replace(month=1, day=1)
        year_end = today.replace(month=12, day=31)
        vouchers = vouchers.filter(date__range=[year_start, year_end])
        period_name = f"This Year ({today.year})"
    elif date_filter == 'custom' and start_date and end_date:
        try:
            start_date_obj = datetime.strptime(start_date, '%Y-%m-%d').date()
            end_date_obj = datetime.strptime(end_date, '%Y-%m-%d').date()
            vouchers = vouchers.filter(date__range=[start_date_obj, end_date_obj])
            period_name = f"Custom Range ({start_date} to {end_date})"
        except ValueError:
            period_name = "All Time"
    else:
        period_name = "All Time"
    
    vouchers = vouchers.order_by('date')
    
    # Get base calculation for total work amount
    base_calculation = calculate_shed_base_amount(shed)
    total_work_amount = base_calculation['base_amount']
    
    # Calculate totals
    vouchers_summary = vouchers.aggregate(
        total_receipts=Sum('receipt'),
        total_payments=Sum('payment')
    )
    
    total_receipts = vouchers_summary['total_receipts'] or Decimal('0.00')
    total_payments = vouchers_summary['total_payments'] or Decimal('0.00')
    outstanding_balance = total_work_amount + total_receipts - total_payments
    
    # Create transaction list for chronological order
    transactions = []
    
    # Add work done as first entry
    transactions.append({
        'date': vouchers.first().date if vouchers.exists() else today,
        'type': 'Work Done',
        'reference': 'Base Calculation',
        'description': f'Total work completed for shed {shed.name}',
        'debit': total_work_amount,
        'credit': Decimal('0.00'),
        'balance': None
    })
    
    for voucher in vouchers:
        if voucher.receipt > 0:
            transactions.append({
                'date': voucher.date,
                'type': 'Receipt',
                'reference': voucher.voucher_no,
                'description': voucher.description or 'Payment received',
                'debit': Decimal('0.00'),
                'credit': voucher.receipt,
                'balance': None
            })
        
        if voucher.payment > 0:
            transactions.append({
                'date': voucher.date,
                'type': 'Payment',
                'reference': voucher.voucher_no,
                'description': voucher.description or 'Payment made',
                'debit': voucher.payment,
                'credit': Decimal('0.00'),
                'balance': None
            })
    
    # Sort by date
    transactions.sort(key=lambda x: x['date'])
    
    # Calculate running balance
    running_balance = Decimal('0.00')
    for transaction in transactions:
        running_balance += transaction['debit'] - transaction['credit']
        transaction['balance'] = running_balance
    
    # Render PDF
    template = get_template('adminapp/vouchers/shed_statement_pdf.html')
    context = {
        'shed': shed,
        'transactions': transactions,
        'total_work_amount': total_work_amount,
        'total_receipts': total_receipts,
        'total_payments': total_payments,
        'outstanding_balance': outstanding_balance,
        'period_name': period_name,
        'generated_date': timezone.now(),
        'company_name': 'Your Company Name',  # Replace with actual company name
        'base_calculation': base_calculation,
    }
    
    html = template.render(context)
    
    # Create PDF
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="shed_statement_{shed.name}_{date_filter}_{today}.pdf"'
    
    pisa_status = pisa.CreatePDF(html, dest=response)
    
    if pisa_status.err:
        return HttpResponse('We had some errors <pre>' + html + '</pre>')
    
    return response




# --- Tenant Voucher Views --- fix
@check_permission('voucher_add')
def create_tenant_voucher(request):
    if request.method == "POST":
        form = TenantVoucherForm(request.POST)
        if form.is_valid():
            voucher = form.save(commit=False)

            # Get combined balance for all tenants with same company name
            tenant_company_name = voucher.tenant.company_name
            
            # Get total bills amount
            bills_total = TenantBill.objects.filter(
                tenant__company_name=tenant_company_name,
                status__in=['finalized', 'sent', 'paid']
            ).aggregate(total=Sum('total_amount'))['total'] or 0
            
            # Get previous voucher totals
            voucher_sums = TenantVoucher.objects.filter(
                tenant__company_name=tenant_company_name
            ).aggregate(
                total_receipt=Sum('receipt'),
                total_payment=Sum('payment')
            )
            
            total_receipt = voucher_sums['total_receipt'] or 0
            total_payment = voucher_sums['total_payment'] or 0
            
            # Calculate previous balance: Bills - Receipts + Payments
            last_total = bills_total - total_receipt + total_payment

            # Remain amount before this entry
            voucher.remain_amount = last_total

            # Compute new total after receipt/payment
            voucher.total_amount = last_total - (voucher.receipt or 0) + (voucher.payment or 0)

            voucher.save()
            messages.success(request, "Tenant Voucher created successfully ✅")
            return redirect("adminapp:tenantvoucher_list")
    else:
        form = TenantVoucherForm()

    return render(request, "adminapp/vouchers/tenantvoucher_form.html", {"form": form})

@check_permission('voucher_view')
def get_tenant_balance(request):
    tenant_id = request.GET.get("tenant_id")
    if not tenant_id:
        return JsonResponse({"error": "No tenant_id provided"}, status=400)

    try:
        tenant = Tenant.objects.get(pk=tenant_id)
        tenant_company_name = tenant.company_name

        # 🔹 1. Sum of all tenant bills for tenants with same company name
        bills_total = TenantBill.objects.filter(
            tenant__company_name=tenant_company_name,
            status__in=['draft']  # Only include finalized bills
        ).aggregate(total=Sum("total_amount"))["total"] or 0

        # 🔹 2. Sum of receipts & payments in vouchers for tenants with same company name
        voucher_sums = TenantVoucher.objects.filter(
            tenant__company_name=tenant_company_name
        ).aggregate(
            total_receipt=Sum("receipt"),
            total_payment=Sum("payment"),
        )

        total_receipt = voucher_sums["total_receipt"] or 0
        total_payment = voucher_sums["total_payment"] or 0

        # 🔹 3. Calculate remaining balance
        # Bills increase the amount owed (positive)
        # Receipts reduce the amount owed (negative for tenant)
        # Payments increase the amount owed (positive - we pay tenant)
        remain_amount = bills_total - total_receipt + total_payment

        return JsonResponse({
            "bills_total": float(bills_total),
            "total_receipt": float(total_receipt),
            "total_payment": float(total_payment),
            "remain_amount": float(remain_amount),
            "tenant_name": tenant_company_name,
        })

    except Tenant.DoesNotExist:
        return JsonResponse({"error": "Tenant not found"}, status=404)
    
@check_permission('voucher_view')
def tenantvoucher_list_with_summary(request):
    """Enhanced list view with transaction summary and filtering"""
    
    # Get filter parameters
    date_filter = request.GET.get('date_filter', 'all')  # all, today, week, month, year, custom
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    tenant_filter = request.GET.get('tenant')
    search_query = request.GET.get('search', '')
    
    # Base queryset
    vouchers = TenantVoucher.objects.select_related('tenant').order_by('-date', '-id')
    
    # Apply date filtering
    today = timezone.now().date()
    
    if date_filter == 'today':
        vouchers = vouchers.filter(date=today)
        period_name = f"Today ({today})"
    elif date_filter == 'week':
        week_start = today - timedelta(days=today.weekday())
        week_end = week_start + timedelta(days=6)
        vouchers = vouchers.filter(date__range=[week_start, week_end])
        period_name = f"This Week ({week_start} to {week_end})"
    elif date_filter == 'month':
        month_start = today.replace(day=1)
        if today.month == 12:
            month_end = today.replace(year=today.year + 1, month=1, day=1) - timedelta(days=1)
        else:
            month_end = today.replace(month=today.month + 1, day=1) - timedelta(days=1)
        vouchers = vouchers.filter(date__range=[month_start, month_end])
        period_name = f"This Month ({month_start.strftime('%B %Y')})"
    elif date_filter == 'year':
        year_start = today.replace(month=1, day=1)
        year_end = today.replace(month=12, day=31)
        vouchers = vouchers.filter(date__range=[year_start, year_end])
        period_name = f"This Year ({today.year})"
    elif date_filter == 'custom' and start_date and end_date:
        try:
            start_date_obj = datetime.strptime(start_date, '%Y-%m-%d').date()
            end_date_obj = datetime.strptime(end_date, '%Y-%m-%d').date()
            vouchers = vouchers.filter(date__range=[start_date_obj, end_date_obj])
            period_name = f"Custom Range ({start_date} to {end_date})"
        except ValueError:
            period_name = "All Time"
    else:
        period_name = "All Time"
    
    # Apply tenant filtering
    if tenant_filter:
        vouchers = vouchers.filter(tenant_id=tenant_filter)
    
    # Apply search filtering
    if search_query:
        vouchers = vouchers.filter(
            Q(voucher_no__icontains=search_query) |
            Q(tenant__company_name__icontains=search_query) |
            Q(tenant__contact_person__icontains=search_query) |
            Q(description__icontains=search_query)
        )
    
    # Calculate summary statistics
    summary = vouchers.aggregate(
        total_vouchers=Count('id'),
        total_receipts=Sum('receipt'),
        total_payments=Sum('payment'),
        net_amount=Sum('receipt') - Sum('payment')
    )
    
    # Convert None to 0 for display
    for key, value in summary.items():
        if value is None:
            summary[key] = Decimal('0.00')
    
    # Get tenant-wise summary
    tenant_summary = vouchers.values(
        'tenant__id', 
        'tenant__company_name'
    ).annotate(
        voucher_count=Count('id'),
        total_receipts=Sum('receipt'),
        total_payments=Sum('payment'),
        net_amount=Sum('receipt') - Sum('payment')
    ).order_by('-net_amount')
    
    # Pagination
    paginator = Paginator(vouchers, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    # Get all tenants for filter dropdown
    all_tenants = Tenant.objects.all().order_by('company_name')
    
    context = {
        'vouchers': page_obj,
        'summary': summary,
        'tenant_summary': tenant_summary,
        'all_tenants': all_tenants,
        'search_query': search_query,
        'date_filter': date_filter,
        'start_date': start_date,
        'end_date': end_date,
        'tenant_filter': tenant_filter,
        'period_name': period_name,
        'total_count': paginator.count,
        'today': today,
    }
    
    return render(request, "adminapp/vouchers/tenantvoucher_list_summary.html", context)

@check_permission('voucher_view')
def tenant_voucher_summary_pdf(request):
    """Generate PDF summary report"""
    
    # Get same filter parameters as list view
    date_filter = request.GET.get('date_filter', 'all')
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    tenant_filter = request.GET.get('tenant')
    
    # Apply same filtering logic
    vouchers = TenantVoucher.objects.select_related('tenant').order_by('-date', '-id')
    
    today = timezone.now().date()
    
    if date_filter == 'today':
        vouchers = vouchers.filter(date=today)
        period_name = f"Today ({today})"
    elif date_filter == 'week':
        week_start = today - timedelta(days=today.weekday())
        week_end = week_start + timedelta(days=6)
        vouchers = vouchers.filter(date__range=[week_start, week_end])
        period_name = f"This Week ({week_start} to {week_end})"
    elif date_filter == 'month':
        month_start = today.replace(day=1)
        if today.month == 12:
            month_end = today.replace(year=today.year + 1, month=1, day=1) - timedelta(days=1)
        else:
            month_end = today.replace(month=today.month + 1, day=1) - timedelta(days=1)
        vouchers = vouchers.filter(date__range=[month_start, month_end])
        period_name = f"This Month ({month_start.strftime('%B %Y')})"
    elif date_filter == 'year':
        year_start = today.replace(month=1, day=1)
        year_end = today.replace(month=12, day=31)
        vouchers = vouchers.filter(date__range=[year_start, year_end])
        period_name = f"This Year ({today.year})"
    elif date_filter == 'custom' and start_date and end_date:
        try:
            start_date_obj = datetime.strptime(start_date, '%Y-%m-%d').date()
            end_date_obj = datetime.strptime(end_date, '%Y-%m-%d').date()
            vouchers = vouchers.filter(date__range=[start_date_obj, end_date_obj])
            period_name = f"Custom Range ({start_date} to {end_date})"
        except ValueError:
            period_name = "All Time"
    else:
        period_name = "All Time"
    
    if tenant_filter:
        vouchers = vouchers.filter(tenant_id=tenant_filter)
    
    # Calculate summary
    summary = vouchers.aggregate(
        total_vouchers=Count('id'),
        total_receipts=Sum('receipt'),
        total_payments=Sum('payment'),
        net_amount=Sum('receipt') - Sum('payment')
    )
    
    for key, value in summary.items():
        if value is None:
            summary[key] = Decimal('0.00')
    
    # Get tenant-wise summary
    tenant_summary = vouchers.values(
        'tenant__company_name',
        'tenant__contact_person'
    ).annotate(
        voucher_count=Count('id'),
        total_receipts=Sum('receipt'),
        total_payments=Sum('payment'),
        net_amount=Sum('receipt') - Sum('payment')
    ).order_by('-net_amount')
    
    # Render PDF
    template = get_template('adminapp/vouchers/tenant_voucher_summary_pdf.html')
    context = {
        'vouchers': vouchers,
        'summary': summary,
        'tenant_summary': tenant_summary,
        'period_name': period_name,
        'generated_date': timezone.now(),
        'company_name': 'Your Company Name',  # Replace with actual company name
    }
    
    html = template.render(context)
    
    # Create PDF
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="tenant_voucher_summary_{date_filter}_{today}.pdf"'
    
    pisa_status = pisa.CreatePDF(html, dest=response)
    
    if pisa_status.err:
        return HttpResponse('We had some errors <pre>' + html + '</pre>')
    
    return response

@check_permission('voucher_view')
def tenant_statement_pdf(request, tenant_id):
    """Generate PDF statement for specific tenant"""
    
    tenant = get_object_or_404(Tenant, id=tenant_id)
    
    # Get filter parameters
    date_filter = request.GET.get('date_filter', 'all')
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    
    # Get tenant bills and vouchers
    today = timezone.now().date()
    
    # Filter bills
    bills = TenantBill.objects.filter(
        tenant__company_name=tenant.company_name,
        status__in=['finalized', 'sent', 'paid']
    )
    
    # Filter vouchers
    vouchers = TenantVoucher.objects.filter(
        tenant__company_name=tenant.company_name
    )
    
    # Apply date filtering
    if date_filter == 'today':
        bills = bills.filter(bill_date=today)
        vouchers = vouchers.filter(date=today)
        period_name = f"Today ({today})"
    elif date_filter == 'week':
        week_start = today - timedelta(days=today.weekday())
        week_end = week_start + timedelta(days=6)
        bills = bills.filter(bill_date__range=[week_start, week_end])
        vouchers = vouchers.filter(date__range=[week_start, week_end])
        period_name = f"This Week ({week_start} to {week_end})"
    elif date_filter == 'month':
        month_start = today.replace(day=1)
        if today.month == 12:
            month_end = today.replace(year=today.year + 1, month=1, day=1) - timedelta(days=1)
        else:
            month_end = today.replace(month=today.month + 1, day=1) - timedelta(days=1)
        bills = bills.filter(bill_date__range=[month_start, month_end])
        vouchers = vouchers.filter(date__range=[month_start, month_end])
        period_name = f"This Month ({month_start.strftime('%B %Y')})"
    elif date_filter == 'year':
        year_start = today.replace(month=1, day=1)
        year_end = today.replace(month=12, day=31)
        bills = bills.filter(bill_date__range=[year_start, year_end])
        vouchers = vouchers.filter(date__range=[year_start, year_end])
        period_name = f"This Year ({today.year})"
    elif date_filter == 'custom' and start_date and end_date:
        try:
            start_date_obj = datetime.strptime(start_date, '%Y-%m-%d').date()
            end_date_obj = datetime.strptime(end_date, '%Y-%m-%d').date()
            bills = bills.filter(bill_date__range=[start_date_obj, end_date_obj])
            vouchers = vouchers.filter(date__range=[start_date_obj, end_date_obj])
            period_name = f"Custom Range ({start_date} to {end_date})"
        except ValueError:
            period_name = "All Time"
    else:
        period_name = "All Time"
    
    bills = bills.order_by('bill_date')
    vouchers = vouchers.order_by('date')
    
    # Calculate totals
    bills_total = bills.aggregate(total=Sum('total_amount'))['total'] or Decimal('0.00')
    vouchers_summary = vouchers.aggregate(
        total_receipts=Sum('receipt'),
        total_payments=Sum('payment')
    )
    
    total_receipts = vouchers_summary['total_receipts'] or Decimal('0.00')
    total_payments = vouchers_summary['total_payments'] or Decimal('0.00')
    outstanding_balance = bills_total - total_receipts + total_payments
    
    # Create combined transaction list for chronological order
    transactions = []
    
    for bill in bills:
        transactions.append({
            'date': bill.bill_date,
            'type': 'Bill',
            'reference': bill.bill_number,
            'description': f"Bill from {bill.from_date} to {bill.to_date}",
            'debit': bill.total_amount,
            'credit': Decimal('0.00'),
            'balance': None  # Will calculate running balance
        })
    
    for voucher in vouchers:
        if voucher.receipt > 0:
            transactions.append({
                'date': voucher.date,
                'type': 'Receipt',
                'reference': voucher.voucher_no,
                'description': voucher.description or 'Payment received',
                'debit': Decimal('0.00'),
                'credit': voucher.receipt,
                'balance': None
            })
        
        if voucher.payment > 0:
            transactions.append({
                'date': voucher.date,
                'type': 'Payment',
                'reference': voucher.voucher_no,
                'description': voucher.description or 'Payment made',
                'debit': voucher.payment,
                'credit': Decimal('0.00'),
                'balance': None
            })
    
    # Sort by date
    transactions.sort(key=lambda x: x['date'])
    
    # Calculate running balance
    running_balance = Decimal('0.00')
    for transaction in transactions:
        running_balance += transaction['debit'] - transaction['credit']
        transaction['balance'] = running_balance
    
    # Render PDF
    template = get_template('adminapp/vouchers/tenant_statement_pdf.html')
    context = {
        'tenant': tenant,
        'transactions': transactions,
        'bills_total': bills_total,
        'total_receipts': total_receipts,
        'total_payments': total_payments,
        'outstanding_balance': outstanding_balance,
        'period_name': period_name,
        'generated_date': timezone.now(),
        'company_name': 'Your Company Name',  # Replace with actual company name
    }
    
    html = template.render(context)
    
    # Create PDF
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="tenant_statement_{tenant.company_name}_{date_filter}_{today}.pdf"'
    
    pisa_status = pisa.CreatePDF(html, dest=response)
    
    if pisa_status.err:
        return HttpResponse('We had some errors <pre>' + html + '</pre>')
    
    return response


# ADMIN WORKINGS

def admin_dashboard(request):
    # Count incomplete freezing entries from both spot and local freezing
    # Assuming 'Incomplete' or 'Pending' status indicates incomplete freezing
    
    # Count incomplete spot freezing entries
    incomplete_spot_freezing = FreezingEntrySpot.objects.filter(
        Q(freezing_status__iexact='Incomplete') | 
        Q(freezing_status__iexact='Pending') |
        Q(freezing_status__iexact='In Progress')
    ).count()
    
    # Count incomplete local freezing entries  
    incomplete_local_freezing = FreezingEntryLocal.objects.filter(
        Q(freezing_status__iexact='Incomplete') |
        Q(freezing_status__iexact='Pending') |
        Q(freezing_status__iexact='In Progress')
    ).count()
    
    # Total incomplete freezing count
    incomplete_freezing_count = incomplete_spot_freezing + incomplete_local_freezing
    
    # ADD THIS: Total freezing entries (needed for template calculation)
    total_freezing_entries = FreezingEntrySpot.objects.count() + FreezingEntryLocal.objects.count()
    
    # Calculate completed entries (recommended approach)
    completed_today = total_freezing_entries - incomplete_freezing_count
    
    # You can also get other dashboard statistics here
    total_subscribers = 1303  # This seems to be hardcoded in your template
    total_sales = 1345
    total_orders = 576
    
    context = {
        'incomplete_freezing_count': incomplete_freezing_count,
        'total_freezing_entries': total_freezing_entries,  # ADD THIS
        'completed_today': completed_today,  # ADD THIS
        'incomplete_spot_freezing': incomplete_spot_freezing,
        'incomplete_local_freezing': incomplete_local_freezing,
        'total_subscribers': total_subscribers,
        'total_sales': total_sales,
        'total_orders': total_orders,
    }
    
    return render(request, 'adminapp/dashboard.html', context)

# Alternative approach if you want to filter by other criteria
def admin_dashboard_alternative(request):
    """
    Alternative approach - you can modify the filtering logic based on your specific needs
    """
    # Count entries that don't have 'Active' or 'Completed' status
    incomplete_spot_freezing = FreezingEntrySpot.objects.exclude(
        freezing_status__iexact='Active'
    ).exclude(
        freezing_status__iexact='Completed'
    ).count()
    
    incomplete_local_freezing = FreezingEntryLocal.objects.exclude(
        freezing_status__iexact='Active'
    ).exclude(
        freezing_status__iexact='Completed'  
    ).count()
    
    incomplete_freezing_count = incomplete_spot_freezing + incomplete_local_freezing
    
    context = {
        'incomplete_freezing_count': incomplete_freezing_count,
        
    }
    
    return render(request, 'adminapp/dashboard.html', context)


# If you want to show more detailed breakdown in dashboard
def admin_dashboard_detailed(request):
    """
    Detailed dashboard with breakdown of different freezing statuses
    """
    # Spot freezing breakdown
    spot_pending = FreezingEntrySpot.objects.filter(freezing_status__iexact='Pending').count()
    spot_in_progress = FreezingEntrySpot.objects.filter(freezing_status__iexact='In Progress').count()
    spot_incomplete = FreezingEntrySpot.objects.filter(freezing_status__iexact='Incomplete').count()
    spot_active = FreezingEntrySpot.objects.filter(freezing_status__iexact='Active').count()
    
    # Local freezing breakdown
    local_pending = FreezingEntryLocal.objects.filter(freezing_status__iexact='Pending').count()
    local_in_progress = FreezingEntryLocal.objects.filter(freezing_status__iexact='In Progress').count()
    local_incomplete = FreezingEntryLocal.objects.filter(freezing_status__iexact='Incomplete').count()
    local_active = FreezingEntryLocal.objects.filter(freezing_status__iexact='Active').count()
    
    # Total counts
    incomplete_freezing_count = spot_pending + spot_in_progress + spot_incomplete + local_pending + local_in_progress + local_incomplete
    total_freezing_entries = FreezingEntrySpot.objects.count() + FreezingEntryLocal.objects.count()
    
    context = {
        'incomplete_freezing_count': incomplete_freezing_count,
        'total_freezing_entries': total_freezing_entries,
        
        # Spot freezing stats
        'spot_pending': spot_pending,
        'spot_in_progress': spot_in_progress,  
        'spot_incomplete': spot_incomplete,
        'spot_active': spot_active,
        
        # Local freezing stats
        'local_pending': local_pending,
        'local_in_progress': local_in_progress,
        'local_incomplete': local_incomplete,
        'local_active': local_active,
        
        # Other dashboard data
        'total_subscribers': 1303,
        'total_sales': 1345,
        'total_orders': 576,
    }
    
    return render(request, 'adminapp/dashboard.html', context)

def incomplete_freezing_list(request):
    # Get incomplete entries from both tables
    incomplete_spot = FreezingEntrySpot.objects.filter(
        Q(freezing_status__iexact='Incomplete') | 
        Q(freezing_status__iexact='Pending')
    )
    incomplete_local = FreezingEntryLocal.objects.filter(
        Q(freezing_status__iexact='Incomplete') | 
        Q(freezing_status__iexact='Pending')
    )
    
    context = {
        'incomplete_spot': incomplete_spot,
        'incomplete_local': incomplete_local,
    }
    return render(request, 'adminapp/incomplete_freezing_list.html', context)











