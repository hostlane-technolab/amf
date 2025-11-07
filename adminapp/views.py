# Create your views here.
from .models import *
from .forms import *
from .stock_helpers import update_stock_with_tracking, record_stock_movement
from django.db.models import Max
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
from xhtml2pdf import pisa
from io import BytesIO
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.db import IntegrityError
from django.http import JsonResponse
from django.core.paginator import Paginator
from .models import Stock
from .forms import StockForm




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


def user_profile_view(request, user_id):
    user = get_object_or_404(CustomUser, id=user_id)
    
    context = {
        'user': user,
    }
    
    return render(request, 'adminapp/user_profile_view.html', context)

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
    template_name = 'adminapp/forms/localparty_form.html'
    success_url = reverse_lazy('adminapp:LocalParty_create')

class LocalPartyListView(ListView):
    model = LocalParty
    template_name = 'adminapp/list/LocalParty_list.html'
    context_object_name = 'purchasing_spots'

class LocalPartyUpdateView(UpdateView):
    model = LocalParty
    form_class = LocalPartyForm
    template_name = 'adminapp/forms/localparty_form.html'
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
    success_url = reverse_lazy('adminapp:purchasing_supervisor_list')

    def form_valid(self, form):
        name = form.cleaned_data['name']
        mobile = form.cleaned_data['mobile']

        # Check for active supervisor with same mobile number
        mobile_exists = PurchasingSupervisor.objects.filter(
            mobile=mobile, is_active=True
        ).exists()

        if mobile_exists:
            messages.error(self.request, f'Supervisor with mobile "{mobile}" already exists.')
            return self.form_invalid(form)

        form.instance.is_active = True
        form.instance.created_at = timezone.now()
        messages.success(self.request, f'Supervisor "{name}" created successfully.')
        return super().form_valid(form)

class PurchasingSupervisorUpdateView(UpdateView):
    model = PurchasingSupervisor
    form_class = PurchasingSupervisorForm
    template_name = 'adminapp/forms/purchasingsupervisor_form.html'
    success_url = reverse_lazy('adminapp:purchasing_supervisor_list')

    def get_queryset(self):
        return PurchasingSupervisor.objects.filter(is_active=True)

    def form_valid(self, form):
        old_supervisor = self.get_object()
        name = form.cleaned_data['name']
        mobile = form.cleaned_data['mobile']
        email = form.cleaned_data.get('email')
        joining_date = form.cleaned_data.get('joining_date')
        commission = form.cleaned_data.get('commission')

        # Check for another active record with same mobile
        mobile_exists = PurchasingSupervisor.objects.filter(
            mobile=mobile, is_active=True
        ).exclude(pk=old_supervisor.pk).exists()

        if mobile_exists:
            messages.error(self.request, f'Supervisor with mobile "{mobile}" already exists.')
            return self.form_invalid(form)

        # Mark old record as inactive
        old_supervisor.is_active = False
        old_supervisor.save()

        # Create new active record
        new_supervisor = PurchasingSupervisor.objects.create(
            name=name,
            mobile=mobile,
            email=email,
            joining_date=joining_date,
            commission=commission,
            is_active=True,
            created_at=timezone.now(),
        )

        messages.success(self.request, f'Supervisor "{name}" updated successfully.')
        return redirect(self.success_url)

class PurchasingSupervisorDeleteView(DeleteView):
    model = PurchasingSupervisor
    template_name = 'adminapp/confirm_delete.html'
    success_url = reverse_lazy('adminapp:purchasing_supervisor_list')

    def get_queryset(self):
        return PurchasingSupervisor.objects.filter(is_active=True)

    def delete(self, request, *args, **kwargs):
        self.object = self.get_object()
        supervisor_name = self.object.name

        # Soft delete
        self.object.is_active = False
        self.object.save()

        messages.success(request, f'Supervisor "{supervisor_name}" deactivated successfully.')
        return redirect(self.success_url)

class PurchasingSupervisorListView(ListView):
    model = PurchasingSupervisor
    template_name = 'adminapp/list/purchasingsupervisor_list.html'
    context_object_name = 'supervisors'

    def get_queryset(self):
        return PurchasingSupervisor.objects.filter(is_active=True).order_by('-created_at')





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
    success_url = reverse_lazy('adminapp:item_grade_create')

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
    success_url = reverse_lazy('adminapp:freezing_category_list')

    def form_valid(self, form):
        name = form.cleaned_data['name']
        code = form.cleaned_data['code']

        # Check if active record with same name or code exists
        name_exists = FreezingCategory.objects.filter(name=name, is_active=True).exists()
        code_exists = FreezingCategory.objects.filter(code=code, is_active=True).exists() if code else False
        
        if name_exists:
            messages.error(self.request, f'An active category with name "{name}" already exists.')
            return self.form_invalid(form)
            
        if code_exists:
            messages.error(self.request, f'An active category with code "{code}" already exists.')
            return self.form_invalid(form)

        form.instance.is_active = True
        messages.success(self.request, f'FreezingCategory "{name}" created successfully.')
        return super().form_valid(form)

class FreezingCategoryUpdateView(UpdateView):
    model = FreezingCategory
    form_class = FreezingCategoryForm
    template_name = 'adminapp/forms/freezingcategory_form.html'
    success_url = reverse_lazy('adminapp:freezing_category_list')

    def get_queryset(self):
        return FreezingCategory.objects.filter(is_active=True)

    def form_valid(self, form):
        old_category = self.get_object()
        name = form.cleaned_data['name']
        code = form.cleaned_data['code']
        tariff = form.cleaned_data['tariff']

        # Check if another active record with same name or code exists
        name_exists = FreezingCategory.objects.filter(
            name=name, is_active=True
        ).exclude(pk=old_category.pk).exists()
        
        code_exists = FreezingCategory.objects.filter(
            code=code, is_active=True
        ).exclude(pk=old_category.pk).exists() if code else False
        
        if name_exists:
            messages.error(self.request, f'An active category with name "{name}" already exists.')
            return self.form_invalid(form)
            
        if code_exists:
            messages.error(self.request, f'An active category with code "{code}" already exists.')
            return self.form_invalid(form)

        # Mark old record as inactive
        old_category.is_active = False
        old_category.save()

        # Create new record
        new_category = FreezingCategory.objects.create(
            name=name,
            code=code,
            tariff=tariff,
            is_active=True
        )
        
        messages.success(self.request, f'FreezingCategory "{name}" updated successfully.')
        return redirect(self.success_url)

class FreezingCategoryDeleteView(DeleteView):
    model = FreezingCategory
    template_name = 'adminapp/confirm_delete.html'
    success_url = reverse_lazy('adminapp:freezing_category_list')

    def get_queryset(self):
        return FreezingCategory.objects.filter(is_active=True)

    def delete(self, request, *args, **kwargs):
        self.object = self.get_object()
        category_name = self.object.name
        
        # Only mark as inactive, don't delete
        self.object.is_active = False
        self.object.save()
        
        messages.success(request, f'FreezingCategory "{category_name}" deactivated.')
        return redirect(self.success_url)

class FreezingCategoryListView(ListView):
    model = FreezingCategory
    template_name = 'adminapp/list/freezingcategory_list.html'
    context_object_name = 'freezing_categories'

    def get_queryset(self):
        return FreezingCategory.objects.filter(is_active=True).order_by('-created_at')




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


from django.db.models import Sum

class TenantListView(ListView):
    model = Tenant
    template_name = 'adminapp/list/tenant_list.html'
    context_object_name = 'tenants'
    
    def get_queryset(self):
        return Tenant.objects.annotate(
            total_tariff=Sum('freezing_tariffs__tariff', default=0)
        ).prefetch_related('freezing_tariffs')


from django.contrib import messages
from django.db import transaction

class TenantUpdateView(UpdateView):
    model = Tenant
    form_class = TenantForm
    template_name = 'adminapp/forms/tenant_form.html'
    success_url = reverse_lazy('adminapp:tenant_list')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        if self.request.POST:
            context['formset'] = TenantFreezingTariffFormSet(
                self.request.POST, 
                instance=self.object
            )
        else:
            context['formset'] = TenantFreezingTariffFormSet(
                instance=self.object
            )
        return context

    def post(self, request, *args, **kwargs):
        self.object = self.get_object()
        form = self.get_form()
        formset = TenantFreezingTariffFormSet(
            self.request.POST, 
            instance=self.object
        )
        
        # Debugging
        print("=" * 50)
        print("Form valid:", form.is_valid())
        if not form.is_valid():
            print("Form errors:", form.errors)
        
        print("Formset valid:", formset.is_valid())
        if not formset.is_valid():
            print("Formset errors:", formset.errors)
            for i, form_errors in enumerate(formset.errors):
                if form_errors:
                    print(f"Form {i} errors:", form_errors)
        print("=" * 50)
        
        if form.is_valid() and formset.is_valid():
            return self.form_valid(form, formset)
        else:
            return self.form_invalid(form, formset)

    def form_valid(self, form, formset):
        try:
            with transaction.atomic():
                # Save the tenant
                self.object = form.save()
                
                # Save the formset - this will handle deletions
                instances = formset.save(commit=False)
                
                # Save new/updated instances
                for instance in instances:
                    instance.tenant = self.object
                    instance.save()
                
                # Delete marked instances
                for obj in formset.deleted_objects:
                    obj.delete()
                
                messages.success(self.request, 'Tenant updated successfully!')
                return redirect(self.success_url)
        except Exception as e:
            print(f"Exception during save: {str(e)}")
            messages.error(self.request, f'Error updating tenant: {str(e)}')
            return self.form_invalid(form, formset)

    def form_invalid(self, form, formset):
        messages.error(self.request, 'Please correct the errors below.')
        return self.render_to_response(
            self.get_context_data(form=form, formset=formset)
        )


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
    success_url = reverse_lazy('adminapp:processing_overhead_list')

    def form_valid(self, form):
        # Get form data to check for duplicates (adjust field names as per your model)
        name = form.cleaned_data.get('name')  # Adjust field name as per your ProcessingOverhead model
        code = form.cleaned_data.get('code')  # Adjust field name as per your model
        
        # Check if active record with same name exists
        if name:
            active_by_name = ProcessingOverhead.objects.filter(name=name, is_active=True).first()
            if active_by_name:
                messages.error(self.request, f'An active processing overhead with name "{name}" already exists.')
                return self.form_invalid(form)

        # Check if active record with same code exists (if code field exists)
        if code:
            active_by_code = ProcessingOverhead.objects.filter(code=code, is_active=True).first()
            if active_by_code:
                messages.error(self.request, f'An active processing overhead with code "{code}" already exists.')
                return self.form_invalid(form)

        # Check for inactive records to reactivate
        if name:
            inactive_by_name = ProcessingOverhead.objects.filter(name=name, is_active=False).first()
            if inactive_by_name:
                # Reactivate existing inactive record
                for field in form.cleaned_data:
                    setattr(inactive_by_name, field, form.cleaned_data[field])
                inactive_by_name.is_active = True
                inactive_by_name.created_at = timezone.now()
                inactive_by_name.save()
                messages.success(self.request, f'ProcessingOverhead "{name}" has been reactivated and updated.')
                return redirect(self.success_url)

        if code:
            inactive_by_code = ProcessingOverhead.objects.filter(code=code, is_active=False).first()
            if inactive_by_code:
                # Reactivate existing inactive record
                for field in form.cleaned_data:
                    setattr(inactive_by_code, field, form.cleaned_data[field])
                inactive_by_code.is_active = True
                inactive_by_code.created_at = timezone.now()
                inactive_by_code.save()
                messages.success(self.request, f'ProcessingOverhead with code "{code}" has been reactivated and updated.')
                return redirect(self.success_url)

        # Create new record
        form.instance.is_active = True
        messages.success(self.request, 'ProcessingOverhead created successfully.')
        return super().form_valid(form)

class ProcessingOverheadListView(ListView):
    model = ProcessingOverhead
    template_name = 'adminapp/list/processingoverhead_list.html'
    context_object_name = 'processing_overheads'

    def get_queryset(self):
        # Only show active records
        return ProcessingOverhead.objects.filter(is_active=True).order_by('-created_at')

class ProcessingOverheadUpdateView(UpdateView):
    model = ProcessingOverhead
    form_class = ProcessingOverheadForm
    template_name = 'adminapp/forms/processingoverhead_form.html'
    success_url = reverse_lazy('adminapp:processing_overhead_list')

    def get_queryset(self):
        # Only allow updating active records
        return ProcessingOverhead.objects.filter(is_active=True)

    def form_valid(self, form):
        # Get the old instance
        old_overhead = self.get_object()
        
        # Get form data for duplicate checking
        name = form.cleaned_data.get('name')
        code = form.cleaned_data.get('code')
        
        # Check if another active record with same name exists (excluding current one)
        if name:
            name_exists = ProcessingOverhead.objects.filter(
                name=name, is_active=True
            ).exclude(pk=old_overhead.pk).exists()
            
            if name_exists:
                messages.error(self.request, f'An active processing overhead with name "{name}" already exists.')
                return self.form_invalid(form)

        # Check if another active record with same code exists (excluding current one)
        if code:
            code_exists = ProcessingOverhead.objects.filter(
                code=code, is_active=True
            ).exclude(pk=old_overhead.pk).exists()
            
            if code_exists:
                messages.error(self.request, f'An active processing overhead with code "{code}" already exists.')
                return self.form_invalid(form)

        # Mark old record as inactive (preserve history)
        old_overhead.is_active = False
        old_overhead.save()

        # Create new record with updated values
        new_overhead = ProcessingOverhead()
        for field in form.cleaned_data:
            setattr(new_overhead, field, form.cleaned_data[field])
        new_overhead.is_active = True
        new_overhead.save()
        
        messages.success(self.request, 'ProcessingOverhead updated successfully. Previous version preserved.')
        return redirect(self.success_url)

class ProcessingOverheadDeleteView(DeleteView):
    model = ProcessingOverhead
    template_name = 'adminapp/confirm_delete.html'
    success_url = reverse_lazy('adminapp:processing_overhead_list')

    def get_queryset(self):
        # Only allow deleting active records
        return ProcessingOverhead.objects.filter(is_active=True)

    def delete(self, request, *args, **kwargs):
        # Override delete to just mark inactive (soft delete)
        self.object = self.get_object()
        overhead_name = getattr(self.object, 'name', f'ProcessingOverhead #{self.object.pk}')
        
        # Mark as inactive instead of deleting
        self.object.is_active = False
        self.object.save()
        
        messages.success(request, f'ProcessingOverhead "{overhead_name}" has been deactivated (preserved in database).')
        return redirect(self.success_url)



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
                
                return redirect('adminapp:local_purchase_list')
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
class PeelingShedSupplyListView(CustomPermissionMixin, ListView):
    permission_required = 'adminapp.processing_view'
    model = PeelingShedSupply
    template_name = 'adminapp/purchases/peeling_shed_supply_list.html'
    context_object_name = 'supplies'
    ordering = ['-date'] 

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
def update_peeling_shed_supply(request, pk):
    supply = get_object_or_404(PeelingShedSupply, pk=pk)
    
    if request.method == 'POST':
        form = PeelingShedSupplyForm(request.POST, instance=supply)
        formset = PeelingShedPeelingTypeFormSet(request.POST, instance=supply, prefix='form')

        if form.is_valid() and formset.is_valid():
            with transaction.atomic():
                # Get the spot purchase item and new boxes received
                spot_purchase_item = form.cleaned_data.get('spot_purchase_item')
                new_boxes_received = float(form.cleaned_data.get('boxes_received_shed', 0))
                
                if spot_purchase_item:
                    # Get total boxes from the spot purchase item
                    total_boxes = float(spot_purchase_item.boxes or 0)
                    
                    # Calculate already used boxes from database (excluding current supply)
                    used_boxes = float(PeelingShedSupply.objects.filter(
                        spot_purchase_item=spot_purchase_item
                    ).exclude(id=supply.id).aggregate(
                        total_used=models.Sum('boxes_received_shed')
                    )['total_used'] or 0)
                    
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
                    balance_boxes = max(0, balance_boxes)
                    
                    # Calculate quantity received
                    avg_weight = float(spot_purchase_item.quantity or 0) / float(spot_purchase_item.boxes or 1) if spot_purchase_item.boxes else 0
                    quantity_received = new_boxes_received * avg_weight
                    
                    # Set the calculated values
                    form.instance.SpotPurchase_balance_boxes = int(balance_boxes)
                    form.instance.quantity_received_shed = quantity_received
                    form.instance.SpotPurchase_total_boxes = int(total_boxes)
                    form.instance.SpotPurchase_quantity = float(spot_purchase_item.quantity or 0)
                    form.instance.SpotPurchase_average_box_weight = avg_weight
                
                supply = form.save()
                formset.save()
                
                messages.success(request, 
                    f'Peeling Shed Supply updated successfully. '
                    f'Boxes received: {int(new_boxes_received)}, '
                    f'Remaining balance: {int(balance_boxes)}')
                
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
            used_boxes = float(PeelingShedSupply.objects.filter(
                spot_purchase_item=spot_item
            ).exclude(id=supply.id).aggregate(
                total_used=models.Sum('boxes_received_shed')
            )['total_used'] or 0)
            
            total_boxes = float(spot_item.boxes or 0)
            available_boxes = total_boxes - used_boxes
            current_balance = max(0, available_boxes - float(supply.boxes_received_shed or 0))
            
            avg_weight = float(spot_item.quantity or 0) / float(spot_item.boxes or 1) if spot_item.boxes else 0
            
            # Set the initial form data for readonly fields
            form.initial.update({
                'SpotPurchase_total_boxes': int(total_boxes),
                'SpotPurchase_quantity': float(spot_item.quantity or 0),
                'SpotPurchase_average_box_weight': round(avg_weight, 2),
                'SpotPurchase_balance_boxes': int(current_balance),
                'quantity_received_shed': float(supply.quantity_received_shed or 0)
            })

    return render(request, 'adminapp/purchases/update_peeling_shed_supply_form.html', {
        'form': form,
        'formset': formset,
        'is_update': True,
        'supply': supply,
    })


# Add this AJAX endpoint if it doesn't exist
@check_permission('processing_edit')
def get_spot_purchase_item_details_for_update(request):
    """Get spot purchase item details for update form with balance calculation"""
    item_id = request.GET.get('item_id')
    supply_id = request.GET.get('supply_id')
    
    if not item_id:
        return JsonResponse({'error': 'Item ID required'}, status=400)
    
    try:
        item = SpotPurchaseItem.objects.get(id=item_id)
        total_boxes = float(item.boxes or 0)
        quantity = float(item.quantity or 0)
        avg_weight = quantity / total_boxes if total_boxes > 0 else 0
        
        # Calculate used boxes (excluding current supply if updating)
        query = PeelingShedSupply.objects.filter(spot_purchase_item=item)
        if supply_id:
            query = query.exclude(id=supply_id)
        
        used_boxes = float(query.aggregate(
            total_used=models.Sum('boxes_received_shed')
        )['total_used'] or 0)
        
        available_boxes = total_boxes - used_boxes
        is_fully_used = available_boxes <= 0
        
        return JsonResponse({
            'total_boxes': int(total_boxes),
            'quantity': quantity,
            'average_weight': round(avg_weight, 2),
            'used_boxes': int(used_boxes),
            'available_boxes': int(max(0, available_boxes)),
            'is_fully_used': is_fully_used
        })
    except SpotPurchaseItem.DoesNotExist:
        return JsonResponse({'error': 'Item not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


 



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
            try:
                with transaction.atomic():
                    # First calculate totals
                    total_kg = Decimal(0)
                    total_slab = Decimal(0)
                    total_c_s = Decimal(0)
                    total_usd = Decimal(0)
                    total_inr = Decimal(0)
                    yield_sum = Decimal(0)  # Sum of all yields
                    unique_sheds = set()  # Track unique sheds
                    stock_updates = []

                    # Process formset and collect stock data
                    for f in formset:
                        if f.cleaned_data and not f.cleaned_data.get('DELETE', False):
                            slab = f.cleaned_data.get('slab_quantity') or Decimal(0)
                            cs = f.cleaned_data.get('c_s_quantity') or Decimal(0)
                            kg = f.cleaned_data.get('kg') or Decimal(0)
                            usd = f.cleaned_data.get('usd_rate_item') or Decimal(0)
                            inr = f.cleaned_data.get('usd_rate_item_to_inr') or Decimal(0)
                            yield_percent = f.cleaned_data.get('yield_percentage')
                            shed = f.cleaned_data.get('shed')

                            # Extract data from formset for stock creation
                            store = f.cleaned_data.get('store')
                            item = f.cleaned_data.get('item')
                            item_quality = f.cleaned_data.get('item_quality')
                            unit = f.cleaned_data.get('unit')
                            glaze = f.cleaned_data.get('glaze')
                            brand = f.cleaned_data.get('brand')
                            species = f.cleaned_data.get('species')
                            grade = f.cleaned_data.get('grade')
                            peeling_type = f.cleaned_data.get('peeling_type')
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
                                    'unit': unit,
                                    'glaze': glaze,
                                    'brand': brand,
                                    'species': species,
                                    'grade': grade,
                                    'peeling_type': peeling_type,
                                    'freezing_category': freezing_category,
                                    'cs': cs,
                                    'kg': kg,
                                    'slab': slab,
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
                            
                            # Sum all yields
                            if yield_percent is not None:
                                yield_sum += yield_percent
                            
                            # Track unique sheds (only count rows with data)
                            if shed and (slab > 0 or kg > 0):
                                unique_sheds.add(shed.id if hasattr(shed, 'id') else shed)

                    # Calculate average yield: Sum of all yields / Number of unique sheds
                    num_sheds = len(unique_sheds)
                    average_yield = (yield_sum / num_sheds) if num_sheds > 0 else Decimal(0)
                    
                    print(f"Yield calculation: Sum={yield_sum}, Sheds={num_sheds}, Average={average_yield}")

                    # Create and save the main freezing entry first
                    freezing_entry = form.save(commit=False)
                    freezing_entry.total_slab = total_slab
                    freezing_entry.total_c_s = total_c_s
                    freezing_entry.total_kg = total_kg
                    freezing_entry.total_usd = total_usd
                    freezing_entry.total_inr = total_inr
                    freezing_entry.total_yield_percentage = average_yield
                    freezing_entry.save()

                    # Save formset with the saved instance
                    formset.instance = freezing_entry
                    formset.save()

                    # Now process stock updates with the saved freezing entry
                    stock_errors = []

                    for stock_data in stock_updates:
                        try:
                            # Prepare filter criteria
                            stock_filters = {
                                'store': stock_data['store'],
                                'item': stock_data['item'],
                                'brand': stock_data['brand'],
                                'freezing_category': stock_data['freezing_category'],
                                'item_quality': stock_data.get('item_quality'),
                                'unit': stock_data.get('unit'),
                                'glaze': stock_data.get('glaze'),
                                'species': stock_data.get('species'),
                                'item_grade': stock_data.get('grade'),
                                'peeling_type': stock_data.get('peeling_type'),
                            }
                            
                            print(f"Looking for stock with filters: {stock_filters}")
                            
                            # Use get_or_create to handle race conditions atomically
                            existing_stock, created = Stock.objects.get_or_create(
                                **stock_filters,
                                defaults={
                                    'cs_quantity': stock_data['cs'],
                                    'kg_quantity': stock_data['kg'],
                                    'usd_rate_per_kg': stock_data['usd_rate_per_kg'],
                                    'usd_rate_item': stock_data['usd_rate_item'],
                                    'usd_rate_item_to_inr': stock_data['usd_rate_item_to_inr'],
                                }
                            )
                            
                            if created:
                                print(f"\n✓ New stock created for {stock_data['item'].name}:")
                                print(f"  CS={existing_stock.cs_quantity}, KG={existing_stock.kg_quantity}")
                                print(f"  Rates - USD/kg: {existing_stock.usd_rate_per_kg}, USD/item: {existing_stock.usd_rate_item}, INR: {existing_stock.usd_rate_item_to_inr}")
                            else:
                                # Stock already existed, update with weighted average
                                old_cs = existing_stock.cs_quantity
                                old_kg = existing_stock.kg_quantity
                                old_usd_per_kg = existing_stock.usd_rate_per_kg or Decimal(0)
                                old_usd_item = existing_stock.usd_rate_item or Decimal(0)
                                old_inr = existing_stock.usd_rate_item_to_inr or Decimal(0)
                                
                                add_cs = stock_data['cs']
                                add_kg = stock_data['kg']
                                new_usd_per_kg = stock_data['usd_rate_per_kg']
                                new_usd_item = stock_data['usd_rate_item']
                                new_inr = stock_data['usd_rate_item_to_inr']
                                
                                total_kg = old_kg + add_kg
                                
                                print(f"\nUpdating stock for {stock_data['item'].name}:")
                                print(f"  Old: CS={old_cs}, KG={old_kg}")
                                print(f"  Adding: CS={add_cs}, KG={add_kg}")
                                print(f"  New Total KG: {total_kg}")
                                
                                # Calculate weighted average rates
                                if total_kg > 0:
                                    existing_stock.usd_rate_per_kg = (
                                        (old_kg * old_usd_per_kg) + (add_kg * new_usd_per_kg)
                                    ) / total_kg
                                    
                                    existing_stock.usd_rate_item = (
                                        (old_kg * old_usd_item) + (add_kg * new_usd_item)
                                    ) / total_kg
                                    
                                    existing_stock.usd_rate_item_to_inr = (
                                        (old_kg * old_inr) + (add_kg * new_inr)
                                    ) / total_kg
                                    
                                    print(f"  Rates (Weighted Avg):")
                                    print(f"    USD/kg: {old_usd_per_kg:.2f} → {existing_stock.usd_rate_per_kg:.2f}")
                                    print(f"    USD/item: {old_usd_item:.2f} → {existing_stock.usd_rate_item:.2f}")
                                    print(f"    INR: {old_inr:.2f} → {existing_stock.usd_rate_item_to_inr:.2f}")
                                else:
                                    existing_stock.usd_rate_per_kg = new_usd_per_kg
                                    existing_stock.usd_rate_item = new_usd_item
                                    existing_stock.usd_rate_item_to_inr = new_inr
                                
                                # Update quantities
                                existing_stock.cs_quantity += add_cs
                                existing_stock.kg_quantity += add_kg
                                existing_stock.save()
                                
                                print(f"  Final: CS={existing_stock.cs_quantity}, KG={existing_stock.kg_quantity}")
                                print(f"  ✓ Stock updated successfully")

                            # CREATE STOCK MOVEMENT RECORD
                            # Get the movement date from freezing entry (adjust field name as needed)
                            movement_date = getattr(freezing_entry, 'date_entry', None) or \
                                          getattr(freezing_entry, 'entry_date', None) or \
                                          getattr(freezing_entry, 'date', None) or \
                                          timezone.now().date()
                            
                            # Get voucher number if available
                            voucher_number = getattr(freezing_entry, 'voucher_number', None) or \
                                           getattr(freezing_entry, 'entry_number', None) or \
                                           f"FE-SPOT-{freezing_entry.id}"
                            
                            StockMovement.objects.create(
                                movement_type='freezing_spot',
                                movement_date=movement_date,
                                voucher_number=voucher_number,
                                store=stock_data['store'],
                                item=stock_data['item'],
                                brand=stock_data['brand'],
                                item_quality=stock_data.get('item_quality'),
                                freezing_category=stock_data.get('freezing_category'),
                                peeling_type=stock_data.get('peeling_type'),
                                unit=stock_data.get('unit'),
                                glaze=stock_data.get('glaze'),
                                species=stock_data.get('species'),
                                item_grade=stock_data.get('grade'),
                                cs_quantity=stock_data['cs'],  # Positive value for incoming stock
                                kg_quantity=stock_data['kg'],
                                slab_quantity=stock_data.get('slab', 0),
                                usd_rate_per_kg=stock_data['usd_rate_per_kg'],
                                usd_rate_item=stock_data['usd_rate_item'],
                                usd_rate_item_to_inr=stock_data['usd_rate_item_to_inr'],
                                reference_model='FreezingEntrySpot',
                                reference_id=str(freezing_entry.id),
                                created_by=request.user if request.user.is_authenticated else None,
                                notes=f"Stock added from freezing spot entry"
                            )
                            
                            print(f"  ✓ Stock movement record created")

                        except Exception as stock_error:
                            error_msg = f"Error with stock for {stock_data.get('item', 'Unknown')}: {str(stock_error)}"
                            print(error_msg)
                            print(f"Stock data causing error: {stock_data}")
                            import traceback
                            print(f"Stock error traceback: {traceback.format_exc()}")
                            stock_errors.append(error_msg)
                            continue

                    # Add any stock errors as warning messages
                    for error in stock_errors:
                        messages.warning(request, error)

                messages.success(request, 'Freezing entry created successfully!')
                return redirect('adminapp:freezing_entry_spot_list')
                
            except Exception as e:
                print(f"Error in transaction: {e}")
                import traceback
                print(f"Full traceback: {traceback.format_exc()}")
                messages.error(request, f'Error creating freezing entry: {str(e)}')
    else:
        form = FreezingEntrySpotForm()
        form.fields['spot_agent'].queryset = PurchasingAgent.objects.none()
        form.fields['spot_supervisor'].queryset = PurchasingSupervisor.objects.none()
        formset = FreezingEntrySpotItemFormSet(prefix='form')

        # Set initial querysets for formset forms
        for f in formset.forms:
            f.fields['shed'].queryset = Shed.objects.all()

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
            try:
                with transaction.atomic():
                    entry = form.save(commit=False)

                    # STEP 0: DELETE ALL EXISTING STOCK MOVEMENTS FOR THIS ENTRY
                    print(f"\n=== STEP 0: DELETING EXISTING STOCK MOVEMENTS ===")
                    deleted_count = StockMovement.objects.filter(
                        reference_model='FreezingEntrySpot',
                        reference_id=str(freezing_entry.id)
                    ).delete()[0]
                    print(f"Deleted {deleted_count} existing stock movement records")

                    # STEP 1: REMOVE old stock quantities AND RECALCULATE RATES
                    print(f"\n=== STEP 1: REMOVING OLD STOCK QUANTITIES ===")
                    old_items = freezing_entry.items.all()
                    
                    for old_item in old_items:
                        try:
                            # Build stock filters
                            stock_filters = {
                                'store': old_item.store,
                                'item': old_item.item,
                                'brand': old_item.brand,
                                'item_quality': old_item.item_quality,
                                'unit': old_item.unit,
                                'glaze': old_item.glaze,
                                'species': old_item.species,
                                'item_grade': old_item.grade,
                                'peeling_type': old_item.peeling_type,
                                'freezing_category': old_item.freezing_category,
                            }
                            # Remove None values
                            stock_filters = {k: v for k, v in stock_filters.items() if v is not None}
                            
                            # Find matching stock with row-level lock
                            existing_stock = Stock.objects.select_for_update().filter(**stock_filters).first()
                            
                            if existing_stock:
                                old_cs = old_item.c_s_quantity or Decimal(0)
                                old_kg = old_item.kg or Decimal(0)
                                
                                print(f"\nRemoving from {old_item.item.name}:")
                                print(f"  Current Stock: CS={existing_stock.cs_quantity}, KG={existing_stock.kg_quantity}")
                                print(f"  Removing: CS={old_cs}, KG={old_kg}")
                                
                                # Calculate new quantity after removal
                                new_kg = existing_stock.kg_quantity - old_kg
                                
                                # Recalculate weighted average rates by REMOVING the old contribution
                                if existing_stock.kg_quantity > 0 and old_kg > 0:
                                    # Get the rates that were stored with this item
                                    old_usd_per_kg = old_item.usd_rate_per_kg or Decimal(0)
                                    old_usd_item = old_item.usd_rate_item or Decimal(0)
                                    old_inr = old_item.usd_rate_item_to_inr or Decimal(0)
                                    
                                    # Current weighted total
                                    current_usd_per_kg_total = existing_stock.kg_quantity * existing_stock.usd_rate_per_kg
                                    current_usd_item_total = existing_stock.kg_quantity * existing_stock.usd_rate_item
                                    current_inr_total = existing_stock.kg_quantity * existing_stock.usd_rate_item_to_inr
                                    
                                    # Remove the old contribution
                                    remaining_usd_per_kg_total = current_usd_per_kg_total - (old_kg * old_usd_per_kg)
                                    remaining_usd_item_total = current_usd_item_total - (old_kg * old_usd_item)
                                    remaining_inr_total = current_inr_total - (old_kg * old_inr)
                                    
                                    # Recalculate average if we still have stock
                                    if new_kg > 0:
                                        existing_stock.usd_rate_per_kg = remaining_usd_per_kg_total / new_kg
                                        existing_stock.usd_rate_item = remaining_usd_item_total / new_kg
                                        existing_stock.usd_rate_item_to_inr = remaining_inr_total / new_kg
                                        
                                        print(f"  Recalculated Rates:")
                                        print(f"    USD/kg: {existing_stock.usd_rate_per_kg:.2f}")
                                        print(f"    USD/item: {existing_stock.usd_rate_item:.2f}")
                                        print(f"    INR: {existing_stock.usd_rate_item_to_inr:.2f}")
                                    else:
                                        # No stock left, rates become 0
                                        existing_stock.usd_rate_per_kg = Decimal(0)
                                        existing_stock.usd_rate_item = Decimal(0)
                                        existing_stock.usd_rate_item_to_inr = Decimal(0)
                                        print(f"  Stock will be depleted, rates set to 0")
                                
                                # Subtract quantities
                                existing_stock.cs_quantity -= old_cs
                                existing_stock.kg_quantity -= old_kg
                                
                                print(f"  New Stock: CS={existing_stock.cs_quantity}, KG={existing_stock.kg_quantity}")
                                
                                # Delete if both are zero
                                if existing_stock.cs_quantity == 0 and existing_stock.kg_quantity == 0:
                                    print(f"  Stock depleted to zero, deleting entry")
                                    existing_stock.delete()
                                else:
                                    existing_stock.save()
                                    if existing_stock.cs_quantity < 0 or existing_stock.kg_quantity < 0:
                                        print(f"  ⚠ WARNING: Stock is now NEGATIVE!")
                                        messages.warning(
                                            request,
                                            f"Warning: {old_item.item.name} stock is negative "
                                            f"(CS: {existing_stock.cs_quantity}, KG: {existing_stock.kg_quantity})"
                                        )
                                    else:
                                        print(f"  ✓ Stock updated successfully")
                            else:
                                # Stock not found - this shouldn't happen but handle it
                                print(f"\n⚠ WARNING: No stock found for {old_item.item.name}")
                                messages.warning(request, f"No stock record found for {old_item.item.name}")
                                
                        except Exception as e:
                            print(f"Error removing old stock: {e}")
                            import traceback
                            traceback.print_exc()
                            messages.warning(request, f"Error removing stock for {old_item.item.name}: {str(e)}")

                    # STEP 2: Process new data and calculate totals
                    print(f"\n=== STEP 2: PROCESSING NEW DATA ===")
                    total_kg = Decimal(0)
                    total_slab = Decimal(0)
                    total_c_s = Decimal(0)
                    total_usd = Decimal(0)
                    total_inr = Decimal(0)
                    yield_sum = Decimal(0)  # Sum of all yields
                    unique_sheds = set()  # Track unique sheds
                    
                    stock_updates = []

                    # Process formset
                    for f in formset:
                        if f.cleaned_data and not f.cleaned_data.get("DELETE", False):
                            slab = f.cleaned_data.get("slab_quantity") or Decimal(0)
                            cs = f.cleaned_data.get("c_s_quantity") or Decimal(0)
                            kg = f.cleaned_data.get("kg") or Decimal(0)
                            usd = f.cleaned_data.get("usd_rate_item") or Decimal(0)
                            inr = f.cleaned_data.get("usd_rate_item_to_inr") or Decimal(0)
                            yield_percent = f.cleaned_data.get("yield_percentage") or Decimal(0)
                            shed = f.cleaned_data.get("shed")

                            # Extract data for stock
                            stock_data = {
                                'store': f.cleaned_data.get('store'),
                                'item': f.cleaned_data.get('item'),
                                'item_quality': f.cleaned_data.get('item_quality'),
                                'unit': f.cleaned_data.get('unit'),
                                'glaze': f.cleaned_data.get('glaze'),
                                'brand': f.cleaned_data.get('brand'),
                                'species': f.cleaned_data.get('species'),
                                'grade': f.cleaned_data.get('grade'),
                                'peeling_type': f.cleaned_data.get('peeling_type'),
                                'freezing_category': f.cleaned_data.get('freezing_category'),
                                'cs': cs,
                                'kg': kg,
                                'slab': slab,
                                'usd_rate_per_kg': f.cleaned_data.get('usd_rate_per_kg') or Decimal(0),
                                'usd_rate_item': f.cleaned_data.get('usd_rate_item') or Decimal(0),
                                'usd_rate_item_to_inr': f.cleaned_data.get('usd_rate_item_to_inr') or Decimal(0),
                            }

                            if stock_data['store'] and stock_data['item'] and stock_data['brand']:
                                stock_updates.append(stock_data)
                                print(f"\nItem to add: {stock_data['item'].name}")
                                print(f"  CS={cs}, KG={kg}")

                            # Calculate totals
                            total_slab += slab
                            total_c_s += cs
                            total_kg += kg
                            total_usd += usd
                            total_inr += inr
                            
                            # Sum all yields
                            yield_sum += yield_percent
                            
                            # Track unique sheds (only count rows with data)
                            if shed and (slab > 0 or kg > 0):
                                unique_sheds.add(shed.id if hasattr(shed, 'id') else shed)

                    # Calculate average yield: Sum of all yields / Number of unique sheds
                    num_sheds = len(unique_sheds)
                    average_yield = (yield_sum / num_sheds) if num_sheds > 0 else Decimal(0)
                    
                    print(f"\nYield calculation: Sum={yield_sum}, Sheds={num_sheds}, Average={average_yield}")

                    # Assign totals
                    entry.total_slab = total_slab
                    entry.total_c_s = total_c_s
                    entry.total_kg = total_kg
                    entry.total_usd = total_usd
                    entry.total_inr = total_inr
                    entry.total_yield_percentage = average_yield

                    entry.save()
                    formset.instance = entry
                    formset.save()

                    # STEP 3: ADD new stock quantities AND CREATE FRESH STOCK MOVEMENTS
                    print(f"\n=== STEP 3: ADDING NEW STOCK QUANTITIES ===")
                    
                    # Get movement date and voucher number once
                    movement_date = getattr(entry, 'date_entry', None) or \
                                  getattr(entry, 'entry_date', None) or \
                                  getattr(entry, 'date', None) or \
                                  timezone.now().date()
                    
                    voucher_number = getattr(entry, 'voucher_number', None) or \
                                   getattr(entry, 'entry_number', None) or \
                                   f"FE-SPOT-{entry.id}"
                    
                    for stock_data in stock_updates:
                        try:
                            # Build stock filters
                            stock_filters = {
                                'store': stock_data['store'],
                                'item': stock_data['item'],
                                'brand': stock_data['brand'],
                                'item_quality': stock_data['item_quality'],
                                'unit': stock_data['unit'],
                                'glaze': stock_data['glaze'],
                                'species': stock_data['species'],
                                'item_grade': stock_data['grade'],
                                'peeling_type': stock_data['peeling_type'],
                                'freezing_category': stock_data['freezing_category'],
                            }
                            # Remove None values
                            stock_filters = {k: v for k, v in stock_filters.items() if v is not None}

                            # Find existing stock with row-level lock
                            existing_stock = Stock.objects.select_for_update().filter(**stock_filters).first()
                            
                            if existing_stock:
                                print(f"\nAdding to {stock_data['item'].name}:")
                                print(f"  Current Stock: CS={existing_stock.cs_quantity}, KG={existing_stock.kg_quantity}")
                                print(f"  Adding: CS={stock_data['cs']}, KG={stock_data['kg']}")
                                
                                # Get old and new values
                                old_kg = existing_stock.kg_quantity
                                add_kg = stock_data['kg']
                                new_total_kg = old_kg + add_kg
                                
                                # Calculate weighted average rates
                                if new_total_kg > 0 and add_kg > 0:
                                    old_usd_per_kg = existing_stock.usd_rate_per_kg or Decimal(0)
                                    old_usd_item = existing_stock.usd_rate_item or Decimal(0)
                                    old_inr = existing_stock.usd_rate_item_to_inr or Decimal(0)
                                    
                                    new_usd_per_kg = stock_data['usd_rate_per_kg']
                                    new_usd_item = stock_data['usd_rate_item']
                                    new_inr = stock_data['usd_rate_item_to_inr']
                                    
                                    # Weighted average formula: (old_qty * old_rate + new_qty * new_rate) / total_qty
                                    existing_stock.usd_rate_per_kg = (
                                        (old_kg * old_usd_per_kg) + (add_kg * new_usd_per_kg)
                                    ) / new_total_kg
                                    
                                    existing_stock.usd_rate_item = (
                                        (old_kg * old_usd_item) + (add_kg * new_usd_item)
                                    ) / new_total_kg
                                    
                                    existing_stock.usd_rate_item_to_inr = (
                                        (old_kg * old_inr) + (add_kg * new_inr)
                                    ) / new_total_kg
                                    
                                    print(f"  Rates (Weighted Avg):")
                                    print(f"    USD/kg: {old_usd_per_kg:.2f} → {existing_stock.usd_rate_per_kg:.2f}")
                                    print(f"    USD/item: {old_usd_item:.2f} → {existing_stock.usd_rate_item:.2f}")
                                    print(f"    INR: {old_inr:.2f} → {existing_stock.usd_rate_item_to_inr:.2f}")
                                elif add_kg > 0:
                                    # No existing stock, use new rates
                                    existing_stock.usd_rate_per_kg = stock_data['usd_rate_per_kg']
                                    existing_stock.usd_rate_item = stock_data['usd_rate_item']
                                    existing_stock.usd_rate_item_to_inr = stock_data['usd_rate_item_to_inr']
                                    print(f"  Using new rates (no existing stock)")
                                
                                # Add new quantities
                                existing_stock.cs_quantity += stock_data['cs']
                                existing_stock.kg_quantity += stock_data['kg']
                                existing_stock.save()
                                
                                print(f"  New Stock: CS={existing_stock.cs_quantity}, KG={existing_stock.kg_quantity}")
                                print(f"  ✓ Stock updated successfully")
                                
                            else:
                                # Create new stock entry
                                new_stock_data = {
                                    **stock_filters,
                                    'cs_quantity': stock_data['cs'],
                                    'kg_quantity': stock_data['kg'],
                                    'usd_rate_per_kg': stock_data['usd_rate_per_kg'],
                                    'usd_rate_item': stock_data['usd_rate_item'],
                                    'usd_rate_item_to_inr': stock_data['usd_rate_item_to_inr'],
                                }
                                
                                existing_stock = Stock.objects.create(**new_stock_data)
                                print(f"\n✓ Stock CREATED for {stock_data['item'].name}:")
                                print(f"  CS={existing_stock.cs_quantity}, KG={existing_stock.kg_quantity}")
                                print(f"  Rates - USD/kg: {existing_stock.usd_rate_per_kg}, USD/item: {existing_stock.usd_rate_item}, INR: {existing_stock.usd_rate_item_to_inr}")

                            # CREATE FRESH STOCK MOVEMENT (same voucher number as original)
                            StockMovement.objects.create(
                                movement_type='freezing_spot',
                                movement_date=movement_date,
                                voucher_number=voucher_number,  # Same voucher as original
                                store=stock_data['store'],
                                item=stock_data['item'],
                                brand=stock_data['brand'],
                                item_quality=stock_data.get('item_quality'),
                                freezing_category=stock_data.get('freezing_category'),
                                peeling_type=stock_data.get('peeling_type'),
                                unit=stock_data.get('unit'),
                                glaze=stock_data.get('glaze'),
                                species=stock_data.get('species'),
                                item_grade=stock_data.get('grade'),
                                cs_quantity=stock_data['cs'],
                                kg_quantity=stock_data['kg'],
                                slab_quantity=stock_data.get('slab', 0),
                                usd_rate_per_kg=stock_data['usd_rate_per_kg'],
                                usd_rate_item=stock_data['usd_rate_item'],
                                usd_rate_item_to_inr=stock_data['usd_rate_item_to_inr'],
                                reference_model='FreezingEntrySpot',
                                reference_id=str(entry.id),
                                created_by=request.user if request.user.is_authenticated else None,
                                notes=f"Stock from freezing spot entry (updated)"
                            )
                            print(f"  ✓ Stock movement recorded")

                        except Exception as e:
                            print(f"\n✗ Error updating stock for {stock_data['item'].name}: {e}")
                            import traceback
                            traceback.print_exc()
                            messages.warning(request, f"Error updating stock for {stock_data['item'].name}: {str(e)}")

                    print(f"\n=== UPDATE COMPLETE ===")
                    messages.success(request, 'Freezing entry updated successfully!')
                    return redirect("adminapp:freezing_entry_spot_list")
                    
            except ValueError as e:
                # Validation error
                print(f"\n✗ Validation Error: {e}")
                messages.error(request, str(e))
            except Exception as e:
                # Other errors
                print(f"\n✗ Transaction failed: {e}")
                import traceback
                traceback.print_exc()
                messages.error(request, f'Error updating freezing entry: {str(e)}')
        else:
            print("Form Errors:", form.errors)
            print("Formset Errors:", formset.errors)
            messages.error(request, 'Please correct the errors below.')

    else:
        form = FreezingEntrySpotForm(instance=freezing_entry)
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
                print(f"\n=== DELETING FREEZING ENTRY SPOT {pk} ===")
                
                # STEP 1: Delete all stock movements related to this entry
                print(f"\n--- Step 1: Deleting Stock Movements ---")
                deleted_movements = StockMovement.objects.filter(
                    reference_model='FreezingEntrySpot',
                    reference_id=str(entry.id)
                ).delete()[0]
                print(f"✓ Deleted {deleted_movements} stock movement record(s)")
                
                # STEP 2: Subtract quantities from stock entries
                print(f"\n--- Step 2: Removing Stock Quantities ---")
                delete_stock_entries_for_spot_entry(entry)
                print(f"✓ Stock quantities updated")
                
                # STEP 3: Delete the freezing entry
                print(f"\n--- Step 3: Deleting Freezing Entry ---")
                entry.delete()
                print(f"✓ Freezing entry deleted")
                
                messages.success(request, 'Freezing entry deleted successfully! Stock movements and quantities have been removed.')
                print(f"\n=== DELETION COMPLETE ===\n")
                
        except Exception as e:
            print(f"\n✗ Error deleting freezing entry: {e}")
            import traceback
            print(f"Traceback: {traceback.format_exc()}")
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

    # Get all spot purchase items for this date
    items = SpotPurchaseItem.objects.filter(
        purchase__date=date
    ).select_related("item", "purchase")

    # Group by item and calculate total quantities
    item_totals = {}
    
    for item in items:
        item_id = item.item.id
        quantity = float(item.quantity)
        
        if item_id in item_totals:
            item_totals[item_id]['total_quantity'] += quantity
            item_totals[item_id]['purchase_count'] += 1
        else:
            item_totals[item_id] = {
                'item_id': item_id,
                'item_name': str(item.item),
                'total_quantity': quantity,
                'purchase_count': 1,
                'voucher_numbers': [item.purchase.voucher_number] if hasattr(item.purchase, 'voucher_number') else []
            }

    # Convert to list format
    data = []
    for item_id, item_data in item_totals.items():
        print(f"Item: {item_data['item_name']}, Total Quantity: {item_data['total_quantity']} (from {item_data['purchase_count']} purchases)")
        
        data.append({
            "id": item_id,  # Using item_id as id for consistency
            "item_id": item_id,
            "name": item_data['item_name'],
            "quantity": str(item_data['total_quantity']),  # This is the TOTAL quantity for all purchases of this item on this date
            "purchase_count": item_data['purchase_count'],
            "voucher_numbers": item_data.get('voucher_numbers', [])
        })

    print(f"Returning aggregated purchase data for date {date}: Total {len(data)} unique items")
    return JsonResponse({"items": data})

def get_sheds_by_date(request):
    date_str = request.GET.get('date')
    spot_id = request.GET.get('spot_id')
    
    if not date_str:
        return JsonResponse({'error': 'Missing date'}, status=400)

    try:
        date_obj = datetime.strptime(date_str, "%Y-%m-%d").date()
    except ValueError:
        return JsonResponse({'error': 'Invalid date format'}, status=400)

    # Build query - start with supplies for the date
    supplies_query = PeelingShedSupply.objects.filter(
        spot_purchase__date=date_obj
    ).select_related(
        'shed', 
        'spot_purchase_item__item', 
        'spot_purchase',
        'spot_purchase_item'
    )

    # CRITICAL FIX: If specific spot purchase ID provided, filter by it ONLY
    if spot_id:
        supplies_query = supplies_query.filter(spot_purchase__id=spot_id)
        print(f"FILTERED: Getting ONLY spot purchase ID: {spot_id} on date: {date_obj}")
    else:
        print(f"UNFILTERED: Getting ALL shed supplies for date: {date_obj}")

    supplies = supplies_query.all()
    
    # DEBUG: Show actual query results
    print(f"Query result count: {supplies.count()}")
    for supply in supplies:
        print(f"  - Supply from Spot Purchase ID: {supply.spot_purchase.id} ({supply.spot_purchase_item.quantity}kg)")

    result = []

    for supply in supplies:
        shed = supply.shed
        item = supply.spot_purchase_item.item
        spot_purchase = supply.spot_purchase
        spot_purchase_item = supply.spot_purchase_item

        # Only process if this is the requested spot purchase (double check)
        if spot_id and str(spot_purchase.id) != str(spot_id):
            print(f"SKIPPING: Supply belongs to spot purchase {spot_purchase.id}, but requested {spot_id}")
            continue
            
        print(f"PROCESSING: Spot Purchase ID {spot_purchase.id} - Shed '{shed}' + Item '{item}'")
        
        # Get the quantities
        original_purchase_qty = spot_purchase_item.quantity
        qty_received_shed = supply.quantity_received_shed
        boxes_received = supply.boxes_received_shed
        total_boxes = supply.SpotPurchase_total_boxes

        print(f"  - Original purchase quantity: {original_purchase_qty}kg")
        print(f"  - Quantity received at shed: {qty_received_shed}kg") 
        print(f"  - Boxes received: {boxes_received}/{total_boxes}")

        result.append({
            'shed_id': shed.id,
            'shed_name': str(shed),
            'item_id': item.id,
            'item_name': str(item),
            'boxes_received_shed': boxes_received,
            'quantity_received_shed': str(qty_received_shed),
            'original_purchase_quantity': str(original_purchase_qty),
            'spot_purchase_id': spot_purchase.id,
            'spot_purchase_item_id': spot_purchase_item.id,
            'voucher_number': getattr(spot_purchase, 'voucher_number', ''),
            'total_boxes': total_boxes,
            'boxes_balance': supply.SpotPurchase_balance_boxes,
        })

    print(f"FINAL: Returning {len(result)} records for spot_id={spot_id}")
    return JsonResponse({'sheds': result})

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
    FreezingEntryLocalItemFormSet = inlineformset_factory(
        FreezingEntryLocal,
        FreezingEntryLocalItem,
        form=FreezingEntryLocalItemForm,
        extra=1,
        can_delete=True
    )
    
    if request.method == "POST":
        form = FreezingEntryLocalForm(request.POST)
        formset = FreezingEntryLocalItemFormSet(
            request.POST, prefix="form"
        )
        
        if form.is_valid() and formset.is_valid():
            try:
                with transaction.atomic():
                    # Get Dollar Rate from active Settings
                    try:
                        from adminapp.models import Settings
                        active_settings = Settings.objects.filter(is_active=True).first()
                        if active_settings:
                            dollar_rate_to_inr = active_settings.dollar_rate_to_inr
                            print(f"✓ Using active dollar rate: {dollar_rate_to_inr}")
                        else:
                            raise ValueError("No active settings found in database")
                    except Exception as e:
                        print(f"✗ Error loading dollar rate: {e}")
                        messages.error(request, f"Error: {str(e)}")
                        raise

                    # Process formset data
                    total_kg = Decimal('0')
                    total_slab = Decimal('0')
                    total_c_s = Decimal('0')
                    total_usd = Decimal('0')
                    total_inr = Decimal('0')
                    stock_updates = []

                    # Save formset
                    instances = formset.save(commit=False)
                    
                    for obj in formset.deleted_objects:
                        obj.delete()

                    # Process formset
                    for f in formset.forms:
                        if f.cleaned_data and not f.cleaned_data.get('DELETE', False):
                            slab = f.cleaned_data.get('slab_quantity') or Decimal('0')
                            cs = f.cleaned_data.get('c_s_quantity') or Decimal('0')
                            kg = f.cleaned_data.get('kg') or Decimal('0')
                            usd_rate_per_kg = f.cleaned_data.get('usd_rate_per_kg') or Decimal('0')

                            usd_item = kg * usd_rate_per_kg
                            inr_item = usd_item * dollar_rate_to_inr

                            stock_data = {
                                'store': f.cleaned_data.get('store'),
                                'item': f.cleaned_data.get('item'),
                                'item_quality': f.cleaned_data.get('item_quality'),
                                'unit': f.cleaned_data.get('unit'),
                                'glaze': f.cleaned_data.get('glaze'),
                                'brand': f.cleaned_data.get('brand'),
                                'species': f.cleaned_data.get('species'),
                                'grade': f.cleaned_data.get('grade'),
                                'peeling_type': f.cleaned_data.get('peeling_type'),
                                'freezing_category': f.cleaned_data.get('freezing_category'),
                                'slab': slab,
                                'cs': cs,
                                'kg': kg,
                                'usd_rate_per_kg': usd_rate_per_kg,
                                'usd_rate_item': usd_item,
                                'usd_rate_item_to_inr': inr_item,
                                'form_instance': f,
                            }

                            if stock_data['store'] and stock_data['item'] and stock_data['brand']:
                                stock_updates.append(stock_data)

                            total_slab += slab
                            total_c_s += cs
                            total_kg += kg
                            total_usd += usd_item
                            total_inr += inr_item

                    # Create and save the main freezing entry first
                    entry = form.save(commit=False)
                    entry.total_slab = total_slab
                    entry.total_c_s = total_c_s
                    entry.total_kg = total_kg
                    entry.total_usd = total_usd
                    entry.total_inr = total_inr
                    entry.save()

                    # Save formset instances
                    for instance in instances:
                        for stock_update in stock_updates:
                            if stock_update['form_instance'].instance == instance:
                                kg = stock_update['kg']
                                usd_rate_per_kg = stock_update['usd_rate_per_kg']
                                usd_item = kg * usd_rate_per_kg
                                inr_item = usd_item * dollar_rate_to_inr
                                
                                instance.usd_rate_item = usd_item
                                instance.usd_rate_item_to_inr = inr_item
                                break
                        
                        instance.freezing_entry = entry
                        instance.save()

                    # ADD to stock WITH WEIGHTED AVERAGE
                    print(f"\n=== ADDING STOCK QUANTITIES ===")
                    for stock_data in stock_updates:
                        try:
                            stock_filters = {
                                'store': stock_data['store'],
                                'item': stock_data['item'],
                                'brand': stock_data['brand'],
                                'item_quality': stock_data['item_quality'],
                                'unit': stock_data['unit'],
                                'glaze': stock_data['glaze'],
                                'species': stock_data['species'],
                                'item_grade': stock_data['grade'],
                                'peeling_type': stock_data['peeling_type'],
                                'freezing_category': stock_data['freezing_category'],
                            }
                            stock_filters = {k: v for k, v in stock_filters.items() if v is not None}

                            existing_stock = Stock.objects.select_for_update().filter(**stock_filters).first()
                            
                            if existing_stock:
                                print(f"\nAdding to {stock_data['item'].name}:")
                                
                                old_kg = existing_stock.kg_quantity
                                add_kg = stock_data['kg']
                                new_total_kg = old_kg + add_kg
                                
                                # Weighted average calculation
                                if new_total_kg > 0 and add_kg > 0:
                                    old_usd_per_kg = existing_stock.usd_rate_per_kg or Decimal(0)
                                    old_usd_item = existing_stock.usd_rate_item or Decimal(0)
                                    old_inr = existing_stock.usd_rate_item_to_inr or Decimal(0)
                                    
                                    new_usd_per_kg = stock_data['usd_rate_per_kg']
                                    new_usd_item = stock_data['usd_rate_item']
                                    new_inr = stock_data['usd_rate_item_to_inr']
                                    
                                    existing_stock.usd_rate_per_kg = (
                                        (old_kg * old_usd_per_kg) + (add_kg * new_usd_per_kg)
                                    ) / new_total_kg
                                    
                                    existing_stock.usd_rate_item = (
                                        (old_kg * old_usd_item) + (add_kg * new_usd_item)
                                    ) / new_total_kg
                                    
                                    existing_stock.usd_rate_item_to_inr = (
                                        (old_kg * old_inr) + (add_kg * new_inr)
                                    ) / new_total_kg
                                    
                                    print(f"  Rates (Weighted Avg):")
                                    print(f"    USD/kg: {old_usd_per_kg:.2f} → {existing_stock.usd_rate_per_kg:.2f}")
                                elif add_kg > 0:
                                    existing_stock.usd_rate_per_kg = stock_data['usd_rate_per_kg']
                                    existing_stock.usd_rate_item = stock_data['usd_rate_item']
                                    existing_stock.usd_rate_item_to_inr = stock_data['usd_rate_item_to_inr']
                                
                                existing_stock.cs_quantity += stock_data['cs']
                                existing_stock.kg_quantity += add_kg
                                existing_stock.save()
                                print(f"  ✓ Stock updated")
                                
                            else:
                                # Create new stock
                                new_stock_data = {
                                    **stock_filters,
                                    'cs_quantity': stock_data['cs'],
                                    'kg_quantity': stock_data['kg'],
                                    'usd_rate_per_kg': stock_data['usd_rate_per_kg'],
                                    'usd_rate_item': stock_data['usd_rate_item'],
                                    'usd_rate_item_to_inr': stock_data['usd_rate_item_to_inr'],
                                }
                                
                                stock = Stock.objects.create(**new_stock_data)
                                print(f"\n✓ Stock CREATED for {stock_data['item'].name}")

                            # ✅ CREATE STOCK MOVEMENT RECORD
                            StockMovement.objects.create(
                                movement_type='freezing_local',
                                movement_date=entry.date if hasattr(entry, 'date') else entry.created_at.date(),
                                voucher_number=entry.voucher_number if hasattr(entry, 'voucher_number') else f"FEL-{entry.id}",
                                store=stock_data['store'],
                                item=stock_data['item'],
                                brand=stock_data['brand'],
                                item_quality=stock_data['item_quality'],
                                freezing_category=stock_data['freezing_category'],
                                peeling_type=stock_data['peeling_type'],
                                unit=stock_data['unit'],
                                glaze=stock_data['glaze'],
                                species=stock_data['species'],
                                item_grade=stock_data['grade'],
                                cs_quantity=stock_data['cs'],  # positive for addition
                                kg_quantity=stock_data['kg'],  # positive for addition
                                slab_quantity=stock_data['slab'],
                                usd_rate_per_kg=stock_data['usd_rate_per_kg'],
                                usd_rate_item=stock_data['usd_rate_item'],
                                usd_rate_item_to_inr=stock_data['usd_rate_item_to_inr'],
                                reference_model='FreezingEntryLocal',
                                reference_id=str(entry.id),
                                created_by=request.user if request.user.is_authenticated else None,
                                notes=f"Freezing Entry Local - {entry}"
                            )
                            print(f"  ✓ StockMovement recorded")

                        except Exception as e:
                            print(f"\n✗ Error updating stock: {e}")
                            import traceback
                            traceback.print_exc()
                            messages.warning(request, f"Error updating stock for {stock_data['item'].name}: {str(e)}")

                    print(f"\n=== CREATE COMPLETE ===")
                    messages.success(request, "Freezing Entry created successfully ✅")
                    return redirect("adminapp:freezing_entry_local_list")

            except Exception as e:
                print(f"Error in transaction: {e}")
                import traceback
                print(f"Full traceback: {traceback.format_exc()}")
                messages.error(request, f'Error creating freezing entry: {str(e)}')

        else:
            print("Form Errors:", form.errors)
            print("Formset Errors:", [f.errors for f in formset.forms if f.errors])
            messages.error(request, 'Please correct the errors below.')
    else:
        form = FreezingEntryLocalForm()
        formset = FreezingEntryLocalItemFormSet(prefix="form")
        
    return render(
        request,
        "adminapp/freezing/freezing_entry_local_create.html",
        {"form": form, "formset": formset},
    )

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
            try:
                with transaction.atomic():
                    entry = form.save(commit=False)

                    # STEP 1: REMOVE old stock quantities AND RECALCULATE RATES
                    print(f"\n=== STEP 1: REMOVING OLD STOCK QUANTITIES ===")
                    old_items = freezing_entry.items.all()
                    
                    for old_item in old_items:
                        try:
                            stock_filters = {
                                'store': old_item.store,
                                'item': old_item.item,
                                'brand': old_item.brand,
                                'item_quality': old_item.item_quality,
                                'unit': old_item.unit,
                                'glaze': old_item.glaze,
                                'species': old_item.species,
                                'item_grade': old_item.grade,
                                'peeling_type': old_item.peeling_type,
                                'freezing_category': old_item.freezing_category,
                            }
                            stock_filters = {k: v for k, v in stock_filters.items() if v is not None}
                            
                            existing_stock = Stock.objects.select_for_update().filter(**stock_filters).first()
                            
                            if existing_stock:
                                old_cs = old_item.c_s_quantity or Decimal(0)
                                old_kg = old_item.kg or Decimal(0)
                                
                                print(f"\nRemoving from {old_item.item.name}:")
                                print(f"  Current Stock: CS={existing_stock.cs_quantity}, KG={existing_stock.kg_quantity}")
                                print(f"  Removing: CS={old_cs}, KG={old_kg}")
                                
                                new_kg = existing_stock.kg_quantity - old_kg
                                
                                # Recalculate weighted average rates by REMOVING
                                if existing_stock.kg_quantity > 0 and old_kg > 0:
                                    old_usd_per_kg = old_item.usd_rate_per_kg or Decimal(0)
                                    old_usd_item = old_item.usd_rate_item or Decimal(0)
                                    old_inr = old_item.usd_rate_item_to_inr or Decimal(0)
                                    
                                    # Current weighted total
                                    current_usd_per_kg_total = existing_stock.kg_quantity * existing_stock.usd_rate_per_kg
                                    current_usd_item_total = existing_stock.kg_quantity * existing_stock.usd_rate_item
                                    current_inr_total = existing_stock.kg_quantity * existing_stock.usd_rate_item_to_inr
                                    
                                    # Remove the old contribution
                                    remaining_usd_per_kg_total = current_usd_per_kg_total - (old_kg * old_usd_per_kg)
                                    remaining_usd_item_total = current_usd_item_total - (old_kg * old_usd_item)
                                    remaining_inr_total = current_inr_total - (old_kg * old_inr)
                                    
                                    if new_kg > 0:
                                        existing_stock.usd_rate_per_kg = remaining_usd_per_kg_total / new_kg
                                        existing_stock.usd_rate_item = remaining_usd_item_total / new_kg
                                        existing_stock.usd_rate_item_to_inr = remaining_inr_total / new_kg
                                        
                                        print(f"  Recalculated Rates:")
                                        print(f"    USD/kg: {existing_stock.usd_rate_per_kg:.2f}")
                                        print(f"    USD/item: {existing_stock.usd_rate_item:.2f}")
                                        print(f"    INR: {existing_stock.usd_rate_item_to_inr:.2f}")
                                    else:
                                        existing_stock.usd_rate_per_kg = Decimal(0)
                                        existing_stock.usd_rate_item = Decimal(0)
                                        existing_stock.usd_rate_item_to_inr = Decimal(0)
                                
                                # Subtract quantities
                                existing_stock.cs_quantity -= old_cs
                                existing_stock.kg_quantity -= old_kg
                                
                                print(f"  New Stock: CS={existing_stock.cs_quantity}, KG={existing_stock.kg_quantity}")
                                
                                if existing_stock.cs_quantity == 0 and existing_stock.kg_quantity == 0:
                                    print(f"  Stock depleted, deleting entry")
                                    existing_stock.delete()
                                else:
                                    existing_stock.save()
                                    if existing_stock.cs_quantity < 0 or existing_stock.kg_quantity < 0:
                                        print(f"  ⚠ WARNING: Stock is NEGATIVE!")
                                        messages.warning(
                                            request,
                                            f"Warning: {old_item.item.name} stock is negative"
                                        )
                                    else:
                                        print(f"  ✓ Stock updated successfully")
                            else:
                                print(f"\n⚠ WARNING: No stock found for {old_item.item.name}")
                                messages.warning(request, f"No stock record found for {old_item.item.name}")
                                
                        except Exception as e:
                            print(f"Error removing old stock: {e}")
                            import traceback
                            traceback.print_exc()
                            messages.warning(request, f"Error removing stock for {old_item.item.name}: {str(e)}")

                    # DELETE ALL OLD STOCK MOVEMENTS for this entry
                    print(f"\n=== DELETING OLD STOCK MOVEMENTS ===")
                    old_movements = StockMovement.objects.filter(
                        reference_model='FreezingEntryLocal',
                        reference_id=str(freezing_entry.id)
                    )
                    movement_count = old_movements.count()
                    old_movements.delete()
                    print(f"  ✓ Deleted {movement_count} old stock movement(s)")

                    # STEP 2: Process new data
                    print(f"\n=== STEP 2: PROCESSING NEW DATA ===")
                    total_kg = Decimal('0')
                    total_slab = Decimal('0')
                    total_c_s = Decimal('0')
                    total_usd = Decimal('0')
                    total_inr = Decimal('0')
                    stock_updates = []

                    # Get Dollar Rate from active Settings
                    try:
                        from adminapp.models import Settings
                        active_settings = Settings.objects.filter(is_active=True).first()
                        if active_settings:
                            dollar_rate_to_inr = active_settings.dollar_rate_to_inr
                            print(f"✓ Using active dollar rate: {dollar_rate_to_inr}")
                        else:
                            raise ValueError("No active settings found in database")
                    except Exception as e:
                        print(f"✗ Error loading dollar rate: {e}")
                        messages.error(request, f"Error: {str(e)}")
                        raise

                    # Save formset
                    instances = formset.save(commit=False)
                    
                    for obj in formset.deleted_objects:
                        obj.delete()

                    # Process formset
                    for f in formset.forms:
                        if f.cleaned_data and not f.cleaned_data.get('DELETE', False):
                            slab = f.cleaned_data.get('slab_quantity') or Decimal('0')
                            cs = f.cleaned_data.get('c_s_quantity') or Decimal('0')
                            kg = f.cleaned_data.get('kg') or Decimal('0')
                            usd_rate_per_kg = f.cleaned_data.get('usd_rate_per_kg') or Decimal('0')

                            usd_item = kg * usd_rate_per_kg
                            inr_item = usd_item * dollar_rate_to_inr

                            stock_data = {
                                'store': f.cleaned_data.get('store'),
                                'item': f.cleaned_data.get('item'),
                                'item_quality': f.cleaned_data.get('item_quality'),
                                'unit': f.cleaned_data.get('unit'),
                                'glaze': f.cleaned_data.get('glaze'),
                                'brand': f.cleaned_data.get('brand'),
                                'species': f.cleaned_data.get('species'),
                                'grade': f.cleaned_data.get('grade'),
                                'peeling_type': f.cleaned_data.get('peeling_type'),
                                'freezing_category': f.cleaned_data.get('freezing_category'),
                                'slab': slab,
                                'cs': cs,
                                'kg': kg,
                                'usd_rate_per_kg': usd_rate_per_kg,
                                'usd_rate_item': usd_item,
                                'usd_rate_item_to_inr': inr_item,
                                'form_instance': f,
                            }

                            if stock_data['store'] and stock_data['item'] and stock_data['brand']:
                                stock_updates.append(stock_data)

                            total_slab += slab
                            total_c_s += cs
                            total_kg += kg
                            total_usd += usd_item
                            total_inr += inr_item

                    # Update totals
                    entry.total_slab = total_slab
                    entry.total_c_s = total_c_s
                    entry.total_kg = total_kg
                    entry.total_usd = total_usd
                    entry.total_inr = total_inr
                    entry.save()

                    # Save formset instances
                    for instance in instances:
                        for stock_update in stock_updates:
                            if stock_update['form_instance'].instance == instance:
                                kg = stock_update['kg']
                                usd_rate_per_kg = stock_update['usd_rate_per_kg']
                                usd_item = kg * usd_rate_per_kg
                                inr_item = usd_item * dollar_rate_to_inr
                                
                                instance.usd_rate_item = usd_item
                                instance.usd_rate_item_to_inr = inr_item
                                break
                        
                        instance.freezing_entry = freezing_entry
                        instance.save()

                    # STEP 3: ADD new stock WITH WEIGHTED AVERAGE
                    print(f"\n=== STEP 3: ADDING NEW STOCK QUANTITIES ===")
                    for stock_data in stock_updates:
                        try:
                            stock_filters = {
                                'store': stock_data['store'],
                                'item': stock_data['item'],
                                'brand': stock_data['brand'],
                                'item_quality': stock_data['item_quality'],
                                'unit': stock_data['unit'],
                                'glaze': stock_data['glaze'],
                                'species': stock_data['species'],
                                'item_grade': stock_data['grade'],
                                'peeling_type': stock_data['peeling_type'],
                                'freezing_category': stock_data['freezing_category'],
                            }
                            stock_filters = {k: v for k, v in stock_filters.items() if v is not None}

                            existing_stock = Stock.objects.select_for_update().filter(**stock_filters).first()
                            
                            if existing_stock:
                                print(f"\nAdding to {stock_data['item'].name}:")
                                
                                old_kg = existing_stock.kg_quantity
                                add_kg = stock_data['kg']
                                new_total_kg = old_kg + add_kg
                                
                                # Weighted average
                                if new_total_kg > 0 and add_kg > 0:
                                    old_usd_per_kg = existing_stock.usd_rate_per_kg or Decimal(0)
                                    old_usd_item = existing_stock.usd_rate_item or Decimal(0)
                                    old_inr = existing_stock.usd_rate_item_to_inr or Decimal(0)
                                    
                                    new_usd_per_kg = stock_data['usd_rate_per_kg']
                                    new_usd_item = stock_data['usd_rate_item']
                                    new_inr = stock_data['usd_rate_item_to_inr']
                                    
                                    existing_stock.usd_rate_per_kg = (
                                        (old_kg * old_usd_per_kg) + (add_kg * new_usd_per_kg)
                                    ) / new_total_kg
                                    
                                    existing_stock.usd_rate_item = (
                                        (old_kg * old_usd_item) + (add_kg * new_usd_item)
                                    ) / new_total_kg
                                    
                                    existing_stock.usd_rate_item_to_inr = (
                                        (old_kg * old_inr) + (add_kg * new_inr)
                                    ) / new_total_kg
                                    
                                    print(f"  Rates (Weighted Avg):")
                                    print(f"    USD/kg: {old_usd_per_kg:.2f} → {existing_stock.usd_rate_per_kg:.2f}")
                                elif add_kg > 0:
                                    existing_stock.usd_rate_per_kg = stock_data['usd_rate_per_kg']
                                    existing_stock.usd_rate_item = stock_data['usd_rate_item']
                                    existing_stock.usd_rate_item_to_inr = stock_data['usd_rate_item_to_inr']
                                
                                existing_stock.cs_quantity += stock_data['cs']
                                existing_stock.kg_quantity += add_kg
                                existing_stock.save()
                                print(f"  ✓ Stock updated")
                                
                            else:
                                # Create new stock
                                new_stock_data = {
                                    **stock_filters,
                                    'cs_quantity': stock_data['cs'],
                                    'kg_quantity': stock_data['kg'],
                                    'usd_rate_per_kg': stock_data['usd_rate_per_kg'],
                                    'usd_rate_item': stock_data['usd_rate_item'],
                                    'usd_rate_item_to_inr': stock_data['usd_rate_item_to_inr'],
                                }
                                
                                stock = Stock.objects.create(**new_stock_data)
                                print(f"\n✓ Stock CREATED for {stock_data['item'].name}")

                            # ✅ CREATE NEW STOCK MOVEMENT RECORD
                            StockMovement.objects.create(
                                movement_type='freezing_local',
                                movement_date=entry.date if hasattr(entry, 'date') else entry.created_at.date(),
                                voucher_number=entry.voucher_number if hasattr(entry, 'voucher_number') else f"FEL-{entry.id}",
                                store=stock_data['store'],
                                item=stock_data['item'],
                                brand=stock_data['brand'],
                                item_quality=stock_data['item_quality'],
                                freezing_category=stock_data['freezing_category'],
                                peeling_type=stock_data['peeling_type'],
                                unit=stock_data['unit'],
                                glaze=stock_data['glaze'],
                                species=stock_data['species'],
                                item_grade=stock_data['grade'],
                                cs_quantity=stock_data['cs'],
                                kg_quantity=stock_data['kg'],
                                slab_quantity=stock_data['slab'],
                                usd_rate_per_kg=stock_data['usd_rate_per_kg'],
                                usd_rate_item=stock_data['usd_rate_item'],
                                usd_rate_item_to_inr=stock_data['usd_rate_item_to_inr'],
                                reference_model='FreezingEntryLocal',
                                reference_id=str(entry.id),
                                created_by=request.user if request.user.is_authenticated else None,
                                notes=f"Freezing Entry Local (Updated) - {entry}"
                            )
                            print(f"  ✓ NEW StockMovement recorded")

                        except Exception as e:
                            print(f"\n✗ Error updating stock: {e}")
                            import traceback
                            traceback.print_exc()
                            messages.warning(request, f"Error updating stock for {stock_data['item'].name}: {str(e)}")

                    print(f"\n=== UPDATE COMPLETE ===")
                    messages.success(request, "Freezing Entry updated successfully ✅")
                    return redirect("adminapp:freezing_entry_local_list")

            except Exception as e:
                print(f"Error in transaction: {e}")
                import traceback
                print(f"Full traceback: {traceback.format_exc()}")
                messages.error(request, f'Error updating freezing entry: {str(e)}')

        else:
            print("Form Errors:", form.errors)
            print("Formset Errors:", [f.errors for f in formset.forms if f.errors])
            messages.error(request, 'Please correct the errors below.')
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

@check_permission('freezing_delete')
def delete_freezing_entry_local(request, pk):
    entry = get_object_or_404(FreezingEntryLocal, pk=pk)
    
    if request.method == 'POST':
        try:
            with transaction.atomic():
                print(f"\n=== DELETING FREEZING ENTRY LOCAL: {entry} ===")
                
                # STEP 1: Remove stock quantities
                print(f"\n=== STEP 1: REMOVING STOCK QUANTITIES ===")
                items = entry.items.all()
                
                for item in items:
                    try:
                        stock_filters = {
                            'store': item.store,
                            'item': item.item,
                            'brand': item.brand,
                            'item_quality': item.item_quality,
                            'unit': item.unit,
                            'glaze': item.glaze,
                            'species': item.species,
                            'item_grade': item.grade,
                            'peeling_type': item.peeling_type,
                            'freezing_category': item.freezing_category,
                        }
                        stock_filters = {k: v for k, v in stock_filters.items() if v is not None}
                        
                        existing_stock = Stock.objects.select_for_update().filter(**stock_filters).first()
                        
                        if existing_stock:
                            cs = item.c_s_quantity or Decimal(0)
                            kg = item.kg or Decimal(0)
                            
                            print(f"\nRemoving from {item.item.name}:")
                            print(f"  Current Stock: CS={existing_stock.cs_quantity}, KG={existing_stock.kg_quantity}")
                            print(f"  Removing: CS={cs}, KG={kg}")
                            
                            new_kg = existing_stock.kg_quantity - kg
                            
                            # Recalculate weighted average rates by REMOVING
                            if existing_stock.kg_quantity > 0 and kg > 0:
                                old_usd_per_kg = item.usd_rate_per_kg or Decimal(0)
                                old_usd_item = item.usd_rate_item or Decimal(0)
                                old_inr = item.usd_rate_item_to_inr or Decimal(0)
                                
                                # Current weighted total
                                current_usd_per_kg_total = existing_stock.kg_quantity * existing_stock.usd_rate_per_kg
                                current_usd_item_total = existing_stock.kg_quantity * existing_stock.usd_rate_item
                                current_inr_total = existing_stock.kg_quantity * existing_stock.usd_rate_item_to_inr
                                
                                # Remove the old contribution
                                remaining_usd_per_kg_total = current_usd_per_kg_total - (kg * old_usd_per_kg)
                                remaining_usd_item_total = current_usd_item_total - (kg * old_usd_item)
                                remaining_inr_total = current_inr_total - (kg * old_inr)
                                
                                if new_kg > 0:
                                    existing_stock.usd_rate_per_kg = remaining_usd_per_kg_total / new_kg
                                    existing_stock.usd_rate_item = remaining_usd_item_total / new_kg
                                    existing_stock.usd_rate_item_to_inr = remaining_inr_total / new_kg
                                    
                                    print(f"  Recalculated Rates:")
                                    print(f"    USD/kg: {existing_stock.usd_rate_per_kg:.2f}")
                                else:
                                    existing_stock.usd_rate_per_kg = Decimal(0)
                                    existing_stock.usd_rate_item = Decimal(0)
                                    existing_stock.usd_rate_item_to_inr = Decimal(0)
                            
                            # Subtract quantities
                            existing_stock.cs_quantity -= cs
                            existing_stock.kg_quantity -= kg
                            
                            print(f"  New Stock: CS={existing_stock.cs_quantity}, KG={existing_stock.kg_quantity}")
                            
                            # Delete if stock reaches zero
                            if existing_stock.cs_quantity == 0 and existing_stock.kg_quantity == 0:
                                print(f"  Stock depleted, deleting entry")
                                existing_stock.delete()
                            else:
                                existing_stock.save()
                                if existing_stock.cs_quantity < 0 or existing_stock.kg_quantity < 0:
                                    print(f"  ⚠ WARNING: Stock is NEGATIVE!")
                                    messages.warning(
                                        request,
                                        f"Warning: {item.item.name} stock is negative after deletion"
                                    )
                                else:
                                    print(f"  ✓ Stock updated successfully")
                        else:
                            print(f"\n⚠ WARNING: No stock found for {item.item.name}")
                            messages.warning(request, f"No stock record found for {item.item.name}")
                            
                    except Exception as e:
                        print(f"Error removing stock: {e}")
                        import traceback
                        traceback.print_exc()
                        messages.warning(request, f"Error removing stock for {item.item.name}: {str(e)}")
                
                # STEP 2: Delete associated StockMovement records
                print(f"\n=== STEP 2: DELETING STOCK MOVEMENTS ===")
                stock_movements = StockMovement.objects.filter(
                    reference_model='FreezingEntryLocal',
                    reference_id=str(entry.id)
                )
                movement_count = stock_movements.count()
                stock_movements.delete()
                print(f"  ✓ Deleted {movement_count} stock movement(s)")
                
                # STEP 3: Delete the entry itself
                print(f"\n=== STEP 3: DELETING ENTRY ===")
                entry.delete()
                print(f"  ✓ Entry deleted")
                
                print(f"\n=== DELETE COMPLETE ===")
                messages.success(request, 'Local freezing entry, stock, and stock movements deleted successfully! ✅')
                
        except Exception as e:
            print(f"Error deleting local freezing entry: {e}")
            import traceback
            print(f"Full traceback: {traceback.format_exc()}")
            messages.error(request, f'Error deleting entry: {str(e)}')
            
        return redirect('adminapp:freezing_entry_local_list')
    
    return render(request, 'adminapp/freezing/freezing_entry_local_confirm_delete.html', {'entry': entry})

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

class GetStockRateView(View):
    """
    AJAX endpoint to fetch stock rate based on workout and item filters
    """
    def get(self, request):
        try:
            # Get workout level filters
            workout_item_id = request.GET.get('workout_item')
            workout_unit_id = request.GET.get('workout_unit')
            workout_glaze_id = request.GET.get('workout_glaze')
            workout_category_id = request.GET.get('workout_category')
            workout_brand_id = request.GET.get('workout_brand')
            
            # Get item level filters
            item_quality_id = request.GET.get('item_quality')
            species_id = request.GET.get('species')
            peeling_type_id = request.GET.get('peeling_type')
            grade_id = request.GET.get('grade')
            
            # Build stock query filters - only include non-null filters
            filters = Q()
            
            if workout_item_id:
                filters &= Q(item_id=workout_item_id)
            if workout_unit_id:
                filters &= Q(unit_id=workout_unit_id)
            if workout_glaze_id:
                filters &= Q(glaze_id=workout_glaze_id)
            if workout_category_id:
                filters &= Q(freezing_category_id=workout_category_id)
            if workout_brand_id:
                filters &= Q(brand_id=workout_brand_id)
            if item_quality_id:
                filters &= Q(item_quality_id=item_quality_id)
            if species_id:
                filters &= Q(species_id=species_id)
            if peeling_type_id:
                filters &= Q(peeling_type_id=peeling_type_id)
            if grade_id:
                filters &= Q(item_grade_id=grade_id)
            
            # Try to find matching stock
            stock = Stock.objects.filter(filters).first()
            
            if stock:
                return JsonResponse({
                    'success': True,
                    'usd_rate_per_kg': float(stock.usd_rate_per_kg),
                    'usd_rate_item': float(stock.usd_rate_item),
                    'usd_rate_item_to_inr': float(stock.usd_rate_item_to_inr),
                    'cs_quantity': float(stock.cs_quantity),
                    'kg_quantity': float(stock.kg_quantity),
                })
            else:
                return JsonResponse({
                    'success': False,
                    'message': 'No matching stock found'
                })
                
        except Exception as e:
            logger.error(f"Error in GetStockRateView: {str(e)}")
            return JsonResponse({
                'success': False,
                'message': str(e)
            }, status=500)

class PreShipmentWorkOutView(CustomPermissionMixin, View):
    """
    Handle Pre-Shipment WorkOut creation with proper validation and calculations
    """
    permission_required = 'adminapp.shipping_view'
    template_name = "adminapp/create_preshipment_workout.html"

    def get(self, request):
        """Render the form with empty formset"""
        workout_form = PreShipmentWorkOutForm()
        formset = PreShipmentWorkOutItemFormSet(
            prefix="items",
            instance=PreShipmentWorkOut()
        )

        context = {
            "workout_form": workout_form,
            "formset": formset,
            "items": Item.objects.all(),
            "units": PackingUnit.objects.all(),
            "glazes": GlazePercentage.objects.all(),
            "categories": FreezingCategory.objects.all(),
            "brands": ItemBrand.objects.all(),
            "request": request
        }
        return render(request, self.template_name, context)

    def post(self, request):
        """Handle form submission with validation"""
        workout_form = PreShipmentWorkOutForm(request.POST)

        if workout_form.is_valid():
            try:
                with transaction.atomic():
                    # Save the main workout
                    workout = workout_form.save(commit=False)
                    selected_item = workout_form.cleaned_data.get("item")
                    
                    # Initialize formset with the unsaved workout instance
                    formset = PreShipmentWorkOutItemFormSet(
                        request.POST,
                        prefix="items",
                        instance=workout
                    )
                    
                    # Dynamically adjust species & peeling_type querysets for validation
                    if selected_item:
                        for form in formset.forms:
                            form.fields["species"].queryset = Species.objects.filter(
                                item=selected_item
                            )
                            form.fields["peeling_type"].queryset = ItemType.objects.filter(
                                item=selected_item
                            )
                    
                    # Validate formset
                    if formset.is_valid():
                        # Save main workout
                        workout.save()
                        
                        # Process each item in formset
                        for form in formset:
                            if form.cleaned_data and not form.cleaned_data.get('DELETE', False):
                                obj = form.save(commit=False)
                                
                                # Calculate profit/loss
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
                        
                        # Handle deleted forms if needed
                        formset.save_m2m() if hasattr(formset, 'save_m2m') else None
                        
                        messages.success(
                            request,
                            f"Pre-Shipment WorkOut created successfully with {formset.forms.__len__()} items."
                        )
                        return redirect(request.path)
                    else:
                        # Formset validation failed
                        logger.error(f"Formset errors: {formset.errors}")
                        messages.error(
                            request,
                            "Please correct the item form errors below."
                        )
            except Exception as e:
                logger.error(f"Error saving Pre-Shipment WorkOut: {str(e)}")
                messages.error(request, f"Error saving data: {str(e)}")
                transaction.set_rollback(True)
        else:
            # Main form validation failed
            logger.error(f"Workout form errors: {workout_form.errors}")
            messages.error(request, "Please correct the workout form errors below.")
            formset = PreShipmentWorkOutItemFormSet(
                request.POST,
                prefix="items",
                instance=PreShipmentWorkOut()
            )

        # Re-render form with errors
        context = {
            "workout_form": workout_form,
            "formset": formset,
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



# ajax functions

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

def get_item_grades(request):
    item_id = request.GET.get("item_id")

    # If item_id missing
    if not item_id:
        return JsonResponse([], safe=False)

    item_id = item_id.strip()
    if not item_id:
        return JsonResponse({"error": "Invalid item_id"}, status=400)

    try:
        grades = ItemGrade.objects.filter(item_id=item_id).values("id", "grade")
        return JsonResponse(list(grades), safe=False)
    except Exception as e:
        return JsonResponse({"error": "Database error occurred"}, status=500)




# SPOT PURCHASE REPORT - COMPLETE FIXED VERSION
@check_permission('reports_view')
def spot_purchase_report(request):
    items = Item.objects.all()
    spots = PurchasingSpot.objects.all()
    agents = PurchasingAgent.objects.all()
    categories = ItemCategory.objects.all()

    queryset = SpotPurchaseItem.objects.select_related(
        "purchase", "item", "purchase__spot", "purchase__agent", "item__category"
    )

    # Multi-select filters
    selected_items = request.GET.getlist("items")
    selected_spots = request.GET.getlist("spots")
    selected_agents = request.GET.getlist("agents")
    selected_categories = request.GET.getlist("categories")
    date_filter = request.GET.get("date_filter")

    # Date range filter
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

    # Quick date filter
    if date_filter == "week":
        queryset = queryset.filter(purchase__date__gte=now().date() - timedelta(days=7))
    elif date_filter == "month":
        queryset = queryset.filter(purchase__date__month=now().month)
    elif date_filter == "year":
        queryset = queryset.filter(purchase__date__year=now().year)

    # Custom date range
    if start_date and end_date:
        try:
            start = datetime.strptime(start_date, "%Y-%m-%d").date()
            end = datetime.strptime(end_date, "%Y-%m-%d").date()
            queryset = queryset.filter(purchase__date__range=[start, end])
        except:
            pass

    # Enhanced summary with ALL calculations including boxes and purchase amounts
    # NOTE: We need to calculate purchase amounts at the item level, not aggregate from purchase level
    summary = (
        queryset.values(
            "item__name",
            "item__category__name",
            "purchase__spot__location_name",
            "purchase__agent__name",
            "purchase__date",
            "purchase__voucher_number",
        )
        .annotate(
            total_quantity=Coalesce(Sum("quantity"), 0, output_field=DecimalField()),
            total_boxes=Coalesce(Sum("boxes"), 0, output_field=DecimalField()),
            total_amount=Coalesce(Sum("amount"), 0, output_field=DecimalField()),
            total_rate_sum=Coalesce(Sum("total_rate"), 0, output_field=DecimalField()),
            avg_rate=Coalesce(
                Sum(F("amount"), output_field=FloatField()) / 
                Sum(F("quantity"), output_field=FloatField()),
                0,
                output_field=FloatField()
            ),
            record_count=Count("id"),
        )
        .order_by("purchase__date", "item__name")
    )

    # Convert to list and calculate purchase amounts with expenses per item
    summary_list = list(summary)
    
    # Get all unique purchase IDs from the filtered data
    purchase_ids = queryset.values_list('purchase_id', flat=True).distinct()
    
    # Get expense data for these purchases
    from django.db.models import Case, When, Value
    expense_data = {}
    for purchase_id in purchase_ids:
        try:
            purchase = SpotPurchase.objects.get(id=purchase_id)
            # Get the total expense for this purchase
            try:
                total_expense = purchase.expense.total_expense
            except:
                total_expense = 0
            
            expense_data[purchase_id] = {
                'total_expense': total_expense,
                'total_quantity': purchase.total_quantity,
                'total_amount': purchase.total_amount,
            }
        except:
            pass
    
    # Now calculate purchase amounts for each summary row
    for row in summary_list:
        # Find the purchase for this row
        purchase_matches = SpotPurchase.objects.filter(
            date=row['purchase__date'],
            voucher_number=row['purchase__voucher_number']
        ).first()
        
        if purchase_matches and purchase_matches.id in expense_data:
            purchase_data = expense_data[purchase_matches.id]
            
            # Calculate this item's share of expenses proportionally
            if purchase_data['total_quantity'] > 0:
                item_quantity = float(row['total_quantity'])
                total_purchase_qty = float(purchase_data['total_quantity'])
                expense_share = float(purchase_data['total_expense']) * (item_quantity / total_purchase_qty)
                
                # Purchase amount = item amount + expense share
                row['purchase_amount'] = float(row['total_amount']) + expense_share
                
                # Purchase amount per kg
                if item_quantity > 0:
                    row['purchase_amount_per_kg'] = row['purchase_amount'] / item_quantity
                else:
                    row['purchase_amount_per_kg'] = 0
            else:
                row['purchase_amount'] = float(row['total_amount'])
                row['purchase_amount_per_kg'] = 0
        else:
            # No expenses found, purchase amount = total amount
            row['purchase_amount'] = float(row['total_amount'])
            if float(row['total_quantity']) > 0:
                row['purchase_amount_per_kg'] = row['purchase_amount'] / float(row['total_quantity'])
            else:
                row['purchase_amount_per_kg'] = 0

    # Calculate grand totals from the enhanced list
    grand_totals = {
        'grand_total_quantity': sum(float(row['total_quantity']) for row in summary_list),
        'grand_total_boxes': sum(float(row['total_boxes']) for row in summary_list),
        'grand_total_amount': sum(float(row['total_amount']) for row in summary_list),
        'grand_purchase_amount': sum(row['purchase_amount'] for row in summary_list),
        'total_records': len(summary_list),
    }

    # Calculate overall average rates
    if grand_totals['grand_total_quantity'] > 0:
        grand_totals['grand_avg_rate'] = float(grand_totals['grand_total_amount']) / float(grand_totals['grand_total_quantity'])
        grand_totals['grand_purchase_amount_per_kg'] = float(grand_totals['grand_purchase_amount']) / float(grand_totals['grand_total_quantity'])
    else:
        grand_totals['grand_avg_rate'] = 0
        grand_totals['grand_purchase_amount_per_kg'] = 0
    
    # Use summary_list instead of summary queryset
    summary = summary_list

    # Check if print/export requested
    action = request.GET.get("action")
    print_mode = request.GET.get("print")

    # Handle print request
    if action == "print" or print_mode == "1":
        return render(
            request,
            "adminapp/report/spot_purchase_report_print.html",
            {
                "summary": summary,
                "grand_totals": grand_totals,
                "start_date": start_date,
                "end_date": end_date,
            },
        )

    # Handle CSV export
    if action == "csv":
        response = HttpResponse(content_type="text/csv")
        response["Content-Disposition"] = 'attachment; filename="spot_purchase_report.csv"'
        writer = csv.writer(response)
        writer.writerow([
            "Date", "Voucher", "Item", "Category", "Spot", "Agent", 
            "Total Boxes", "Total Quantity", "Total Amount", "Avg Rate",
            "Purchase Amount (with Expenses)", "Purchase Amount Per Kg"
        ])
        for row in summary:
            writer.writerow([
                row["purchase__date"],
                row["purchase__voucher_number"],
                row["item__name"],
                row["item__category__name"],
                row["purchase__spot__location_name"],
                row["purchase__agent__name"],
                row["total_boxes"],
                row["total_quantity"],
                row["total_amount"],
                round(row["avg_rate"], 2) if row["avg_rate"] else 0,
                round(row["purchase_amount"], 2),
                round(row["purchase_amount_per_kg"], 2),
            ])
        # Add grand totals row
        writer.writerow([])
        writer.writerow([
            "GRAND TOTALS", "", "", "", "", "",
            grand_totals['grand_total_boxes'],
            grand_totals['grand_total_quantity'],
            grand_totals['grand_total_amount'],
            round(grand_totals['grand_avg_rate'], 2),
            grand_totals['grand_purchase_amount'],
            round(grand_totals['grand_purchase_amount_per_kg'], 2),
        ])
        return response

    # Handle Excel export
    if action == "excel":
        output = io.BytesIO()
        workbook = xlsxwriter.Workbook(output, {"in_memory": True})
        worksheet = workbook.add_worksheet("Report")

        # Add formats
        header_format = workbook.add_format({
            'bold': True,
            'bg_color': '#4f46e5',
            'font_color': 'white',
            'border': 1
        })
        total_format = workbook.add_format({
            'bold': True,
            'bg_color': '#f59e0b',
            'border': 1
        })
        number_format = workbook.add_format({'num_format': '#,##0.00'})

        headers = [
            "Date", "Voucher", "Item", "Category", "Spot", "Agent", 
            "Total Boxes", "Total Quantity", "Total Amount", "Avg Rate",
            "Purchase Amount (with Expenses)", "Purchase Amount Per Kg"
        ]
        for col, header in enumerate(headers):
            worksheet.write(0, col, header, header_format)

        for row_idx, row in enumerate(summary, start=1):
            worksheet.write(row_idx, 0, str(row["purchase__date"]))
            worksheet.write(row_idx, 1, row["purchase__voucher_number"])
            worksheet.write(row_idx, 2, row["item__name"])
            worksheet.write(row_idx, 3, row["item__category__name"])
            worksheet.write(row_idx, 4, row["purchase__spot__location_name"])
            worksheet.write(row_idx, 5, row["purchase__agent__name"])
            worksheet.write(row_idx, 6, float(row["total_boxes"]), number_format)
            worksheet.write(row_idx, 7, float(row["total_quantity"]), number_format)
            worksheet.write(row_idx, 8, float(row["total_amount"]), number_format)
            worksheet.write(row_idx, 9, round(row["avg_rate"], 2) if row["avg_rate"] else 0, number_format)
            worksheet.write(row_idx, 10, round(row["purchase_amount"], 2), number_format)
            worksheet.write(row_idx, 11, round(row["purchase_amount_per_kg"], 2), number_format)

        # Add grand totals
        last_row = len(summary) + 2
        worksheet.write(last_row, 0, "GRAND TOTALS", total_format)
        worksheet.write(last_row, 6, float(grand_totals['grand_total_boxes']), total_format)
        worksheet.write(last_row, 7, float(grand_totals['grand_total_quantity']), total_format)
        worksheet.write(last_row, 8, float(grand_totals['grand_total_amount']), total_format)
        worksheet.write(last_row, 9, round(grand_totals['grand_avg_rate'], 2), total_format)
        worksheet.write(last_row, 10, float(grand_totals['grand_purchase_amount']), total_format)
        worksheet.write(last_row, 11, round(grand_totals['grand_purchase_amount_per_kg'], 2), total_format)

        workbook.close()
        output.seek(0)

        response = HttpResponse(
            output.read(),
            content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
        response["Content-Disposition"] = 'attachment; filename="spot_purchase_report.xlsx"'
        return response

    return render(
        request,
        "adminapp/report/spot_purchase_report.html",
        {
            "summary": summary,
            "grand_totals": grand_totals,
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
    queryset = SpotPurchaseItem.objects.select_related(
        "purchase", "item", "purchase__spot", "purchase__agent", "item__category"
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

    # Enhanced summary with ALL calculations
    summary = (
        queryset.values(
            "item__name",
            "item__category__name",
            "purchase__spot__location_name",
            "purchase__agent__name",
            "purchase__date",
            "purchase__voucher_number",
        )
        .annotate(
            total_quantity=Coalesce(Sum("quantity"), 0, output_field=DecimalField()),
            total_boxes=Coalesce(Sum("boxes"), 0, output_field=DecimalField()),
            total_amount=Coalesce(Sum("amount"), 0, output_field=DecimalField()),
            # Get the purchase amount (amount + expenses) from the purchase model
            purchase_amount=Coalesce(Sum(F("purchase__total_purchase_amount")), 0, output_field=DecimalField()),
            purchase_amount_per_kg=Coalesce(Sum(F("purchase__total_purchase_amount_per_kg")), 0, output_field=DecimalField()),
            avg_rate=Coalesce(
                Sum(F("amount"), output_field=FloatField()) / 
                Sum(F("quantity"), output_field=FloatField()),
                0,
                output_field=FloatField()
            ),
        )
        .order_by("purchase__date", "item__name")
    )

    # Calculate grand totals
    grand_totals = summary.aggregate(
        grand_total_quantity=Coalesce(Sum("total_quantity"), 0, output_field=DecimalField()),
        grand_total_boxes=Coalesce(Sum("total_boxes"), 0, output_field=DecimalField()),
        grand_total_amount=Coalesce(Sum("total_amount"), 0, output_field=DecimalField()),
        grand_purchase_amount=Coalesce(Sum("purchase_amount"), 0, output_field=DecimalField()),
        grand_purchase_amount_per_kg=Coalesce(Sum("purchase_amount_per_kg"), 0, output_field=DecimalField()),
    )

    if grand_totals['grand_total_quantity'] > 0:
        grand_totals['grand_avg_rate'] = float(grand_totals['grand_total_amount']) / float(grand_totals['grand_total_quantity'])
        grand_totals['grand_purchase_amount_per_kg'] = float(grand_totals['grand_purchase_amount']) / float(grand_totals['grand_total_quantity'])
    else:
        grand_totals['grand_avg_rate'] = 0
        grand_totals['grand_purchase_amount_per_kg'] = 0

    return render(
        request,
        "adminapp/report/spot_purchase_report_print.html",
        {
            "summary": summary,
            "grand_totals": grand_totals,
            "start_date": start_date,
            "end_date": end_date,
        },
    )



# LOCAL PURCHASE REPORT - FIXED VERSION WITH ITEM_TYPE (PEELING TYPE)
@check_permission('report_view')
def local_purchase_report(request):
    # ✅ Only get items, grades, categories, and qualities that exist in LocalPurchaseItem
    items = Item.objects.filter(
        id__in=LocalPurchaseItem.objects.values_list('item_id', flat=True).distinct()
    ).distinct()
    
    grades = ItemGrade.objects.filter(
        id__in=LocalPurchaseItem.objects.values_list('grade_id', flat=True).distinct()
    ).distinct()
    
    categories = ItemCategory.objects.filter(
        id__in=LocalPurchaseItem.objects.values_list('item__category_id', flat=True).distinct()
    ).distinct()

    # ✅ Get qualities that exist in LocalPurchaseItem
    qualities = ItemQuality.objects.filter(
        id__in=LocalPurchaseItem.objects.values_list('item_quality_id', flat=True).distinct()
    ).distinct()

    # ✅ FIXED: Get ItemType (peeling types) that exist in LocalPurchaseItem
    peeling_types = ItemType.objects.filter(
        id__in=LocalPurchaseItem.objects.values_list('item_type_id', flat=True).distinct()
    ).distinct()

    # ✅ FIXED: Added item_quality and item_type to select_related
    queryset = LocalPurchaseItem.objects.select_related(
        "purchase", "item", "grade", "item__category", "item_quality", "item_type", "purchase__party_name"
    )

    # ✅ Multi-select filters
    selected_items = request.GET.getlist("items")
    selected_grades = request.GET.getlist("grades")
    selected_categories = request.GET.getlist("categories")
    selected_parties = request.GET.getlist("parties")
    selected_qualities = request.GET.getlist("qualities")
    selected_peeling_types = request.GET.getlist("peeling_types")  # ✅ Peeling type filter
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
    if selected_qualities:
        queryset = queryset.filter(item_quality__id__in=selected_qualities)
    if selected_peeling_types:  # ✅ FIXED: Filter by item_type
        queryset = queryset.filter(item_type__id__in=selected_peeling_types)
    if selected_parties:
        queryset = queryset.filter(purchase__party_name__id__in=selected_parties)
    if party_search:
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

    # ✅ FIXED: Group & summary - Using item_type__name for peeling type
    summary = (
        queryset.values(
            "item__name",
            "item__category__name",
            "grade__grade",
            "item_quality__quality",
            "item_type__name",  # ✅ FIXED: Using item_type instead of peeling_type
            "purchase__party_name__party",
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

    # ✅ Calculate statistics from queryset
    from django.db.models import DecimalField
    stats = queryset.aggregate(
        total_qty=Sum("quantity"),
        total_amt=Sum("amount")
    )
    
    total_records = summary.count()
    total_quantity = stats['total_qty'] or 0
    total_amount = stats['total_amt'] or 0
    avg_rate = (total_amount / total_quantity) if total_quantity > 0 else 0

    # ✅ Get unique parties for filter dropdown
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
        # ✅ FIXED: Peeling Type column in CSV header
        writer.writerow(["Date", "Voucher No", "Party", "District", "State", "Item", "Quality", "Grade", "Category", "Peeling Type", "Quantity", "Amount", "Avg Rate"])
        for row in summary:
            writer.writerow([
                row["purchase__date"],
                row["purchase__voucher_number"],
                row["purchase__party_name__party"],
                row["purchase__party_name__district"] or "N/A",
                row["purchase__party_name__state"] or "N/A",
                row["item__name"],
                row["item_quality__quality"] or "N/A",
                row["grade__grade"] or "N/A",
                row["item__category__name"],
                row["item_type__name"] or "N/A",  # ✅ FIXED: Using item_type__name
                row["total_quantity"],
                row["total_amount"],
                round(row["avg_rate"], 2) if row["avg_rate"] else 0,
            ])
        return response

    if action == "excel":
        output = io.BytesIO()
        workbook = xlsxwriter.Workbook(output, {"in_memory": True})
        worksheet = workbook.add_worksheet("Report")

        # ✅ FIXED: Peeling Type column in Excel header
        headers = ["Date", "Voucher No", "Party", "District", "State", "Item", "Quality", "Grade", "Category", "Peeling Type", "Quantity", "Amount", "Avg Rate"]
        for col, header in enumerate(headers):
            worksheet.write(0, col, header)

        for row_idx, row in enumerate(summary, start=1):
            worksheet.write(row_idx, 0, str(row["purchase__date"]))
            worksheet.write(row_idx, 1, row["purchase__voucher_number"])
            worksheet.write(row_idx, 2, row["purchase__party_name__party"])
            worksheet.write(row_idx, 3, row["purchase__party_name__district"] or "N/A")
            worksheet.write(row_idx, 4, row["purchase__party_name__state"] or "N/A")
            worksheet.write(row_idx, 5, row["item__name"])
            worksheet.write(row_idx, 6, row["item_quality__quality"] or "N/A")
            worksheet.write(row_idx, 7, row["grade__grade"] or "N/A")
            worksheet.write(row_idx, 8, row["item__category__name"])
            worksheet.write(row_idx, 9, row["item_type__name"] or "N/A")  # ✅ FIXED: Using item_type__name
            worksheet.write(row_idx, 10, row["total_quantity"])
            worksheet.write(row_idx, 11, row["total_amount"])
            worksheet.write(row_idx, 12, round(row["avg_rate"], 2) if row["avg_rate"] else 0)

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
            "parties": parties,
            "qualities": qualities,
            "peeling_types": peeling_types,  # ✅ Pass peeling types (ItemType) to template
            "selected_items": selected_items,
            "selected_grades": selected_grades,
            "selected_categories": selected_categories,
            "selected_parties": selected_parties,
            "selected_qualities": selected_qualities,
            "selected_peeling_types": selected_peeling_types,  # ✅ Pass selected peeling types
            "date_filter": date_filter,
            "start_date": start_date,
            "end_date": end_date,
            "party_search": party_search,
            # ✅ Add statistics to context
            "total_records": total_records,
            "total_quantity": total_quantity,
            "total_amount": total_amount,
            "avg_rate": avg_rate,
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
    
    # ✅ FIXED: Added item_quality and item_type to select_related
    queryset = LocalPurchaseItem.objects.select_related(
        "purchase", "item", "grade", "item__category", "item_quality", "item_type", "purchase__party_name"
    )

    # Apply the same filters as main view
    selected_items = request.GET.getlist("items")
    selected_grades = request.GET.getlist("grades")
    selected_categories = request.GET.getlist("categories")
    selected_parties = request.GET.getlist("parties")
    selected_qualities = request.GET.getlist("qualities")
    selected_peeling_types = request.GET.getlist("peeling_types")  # ✅ Peeling type filter
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
    if selected_qualities:
        queryset = queryset.filter(item_quality__id__in=selected_qualities)
    if selected_peeling_types:  # ✅ FIXED: Filter by item_type
        queryset = queryset.filter(item_type__id__in=selected_peeling_types)
    if selected_parties:
        queryset = queryset.filter(purchase__party_name__id__in=selected_parties)
    if party_search:
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

    # ✅ FIXED: Added item_type__name field to summary
    summary = (
        queryset.values(
            "item__name",
            "item__category__name",
            "grade__grade",
            "item_quality__quality",
            "item_type__name",  # ✅ FIXED: Using item_type instead of peeling_type
            "purchase__party_name__party",
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
            "selected_parties": selected_parties,
            "selected_qualities": selected_qualities,
            "selected_peeling_types": selected_peeling_types,  # ✅ Pass selected peeling types
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



# FREEZING REPORT - Fixed with proper grade order_code sorting
@check_permission('reports_view')
def freezing_report(request):
    # Get all master data with proper ordering
    items = Item.objects.all().order_by('name')
    grades = ItemGrade.objects.all().order_by(
        F('order_code').asc(nulls_last=True),
        'grade'
    )
    categories = ItemCategory.objects.all().order_by('name')
    peeling_types = ItemType.objects.all().order_by('name')
    brands = ItemBrand.objects.all().order_by('name')
    freezing_categories = FreezingCategory.objects.filter(is_active=True).order_by('name')
    processing_centers = ProcessingCenter.objects.all().order_by('name')
    stores = Store.objects.all().order_by('name')
    
    # Get units and glazes with ordering
    try:
        units = PackingUnit.objects.all().order_by('unit_code')
    except:
        units = []
    
    try:
        glazes = GlazePercentage.objects.all().order_by('percentage')
    except:
        glazes = []

    # Get filter parameters
    selected_items = request.GET.getlist("items")
    selected_grades = request.GET.getlist("grades")
    selected_categories = request.GET.getlist("categories")
    selected_peeling_types = request.GET.getlist("peeling_types")
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
    entry_type = request.GET.get("entry_type", "all")
    section_by = request.GET.get("section_by", "category")

    # Start with minimal select_related
    spot_queryset = FreezingEntrySpotItem.objects.select_related(
        "freezing_entry", "item", "item__category", "item_quality"
    )
    local_queryset = FreezingEntryLocalItem.objects.select_related(
        "freezing_entry", "item", "item__category", "item_quality"
    )

    # Add optional relationships
    try:
        test_spot = FreezingEntrySpotItem.objects.first()
        if test_spot:
            if hasattr(test_spot, 'grade'):
                spot_queryset = spot_queryset.select_related("grade")
                local_queryset = local_queryset.select_related("grade")
            if hasattr(test_spot, 'peeling_type'):
                spot_queryset = spot_queryset.select_related("peeling_type")
                local_queryset = local_queryset.select_related("peeling_type")
            if hasattr(test_spot, 'brand'):
                spot_queryset = spot_queryset.select_related("brand")
                local_queryset = local_queryset.select_related("brand")
            if hasattr(test_spot, 'freezing_category'):
                spot_queryset = spot_queryset.select_related("freezing_category")
                local_queryset = local_queryset.select_related("freezing_category")
            if hasattr(test_spot, 'processing_center'):
                spot_queryset = spot_queryset.select_related("processing_center")
                local_queryset = local_queryset.select_related("processing_center")
            if hasattr(test_spot, 'store'):
                spot_queryset = spot_queryset.select_related("store")
                local_queryset = local_queryset.select_related("store")
            if hasattr(test_spot, 'unit'):
                spot_queryset = spot_queryset.select_related("unit")
                local_queryset = local_queryset.select_related("unit")
            if hasattr(test_spot, 'glaze'):
                spot_queryset = spot_queryset.select_related("glaze")
                local_queryset = local_queryset.select_related("glaze")
    except:
        pass

    # Apply filters
    def apply_filters(queryset):
        if selected_items:
            queryset = queryset.filter(item__id__in=selected_items)
        
        test_item = queryset.first()
        if test_item:
            if hasattr(test_item, 'grade') and selected_grades:
                queryset = queryset.filter(grade__id__in=selected_grades)
            if hasattr(test_item, 'peeling_type') and selected_peeling_types:
                queryset = queryset.filter(peeling_type__id__in=selected_peeling_types)
            if hasattr(test_item, 'brand') and selected_brands:
                queryset = queryset.filter(brand__id__in=selected_brands)
            if hasattr(test_item, 'freezing_category') and selected_freezing_categories:
                queryset = queryset.filter(freezing_category__id__in=selected_freezing_categories)
            if hasattr(test_item, 'processing_center') and selected_processing_centers:
                queryset = queryset.filter(processing_center__id__in=selected_processing_centers)
            if hasattr(test_item, 'store') and selected_stores:
                queryset = queryset.filter(store__id__in=selected_stores)
            if hasattr(test_item, 'unit') and selected_units:
                queryset = queryset.filter(unit__id__in=selected_units)
            if hasattr(test_item, 'glaze') and selected_glazes:
                queryset = queryset.filter(glaze__id__in=selected_glazes)
        
        if selected_categories:
            queryset = queryset.filter(item__category__id__in=selected_categories)
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

    spot_queryset = apply_filters(spot_queryset)
    local_queryset = apply_filters(local_queryset)

    # CRITICAL: Order by grade order_code, then date (at database level)
    spot_queryset = spot_queryset.order_by(
        F('grade__order_code').asc(nulls_last=True),
        'freezing_entry__freezing_date',
        'id'
    )
    local_queryset = local_queryset.order_by(
        F('grade__order_code').asc(nulls_last=True),
        'freezing_entry__freezing_date',
        'id'
    )

    # Process data
    all_data = []

    if entry_type in ['all', 'spot']:
        for item in spot_queryset:
            data_row = {
                'id': item.id,
                'item__name': item.item.name if item.item else None,
                'item__category__name': item.item.category.name if item.item and item.item.category else None,
                'item_quality__quality': item.item_quality.quality if hasattr(item, 'item_quality') and item.item_quality else None,
                'freezing_entry__voucher_number': item.freezing_entry.voucher_number if item.freezing_entry else None,
                'freezing_entry__freezing_date': item.freezing_entry.freezing_date if item.freezing_entry else None,
                'freezing_entry__freezing_status': item.freezing_entry.freezing_status if item.freezing_entry else None,
                'entry_type': 'spot',
                'item_count': 1,
                'peeling_type__name': item.peeling_type.name if hasattr(item, 'peeling_type') and item.peeling_type else None,
                'grade__grade': item.grade.grade if hasattr(item, 'grade') and item.grade else None,
                'grade__order_code': item.grade.order_code if hasattr(item, 'grade') and item.grade else None,
                'brand__name': item.brand.name if hasattr(item, 'brand') and item.brand else None,
                'freezing_category__name': item.freezing_category.name if hasattr(item, 'freezing_category') and item.freezing_category else None,
                'processing_center__name': item.processing_center.name if hasattr(item, 'processing_center') and item.processing_center else None,
                'store__name': item.store.name if hasattr(item, 'store') and item.store else None,
                'unit__description': item.unit.description if hasattr(item, 'unit') and item.unit else None,
                'unit__unit_code': item.unit.unit_code if hasattr(item, 'unit') and item.unit else None,
                'glaze__percentage': item.glaze.percentage if hasattr(item, 'glaze') and item.glaze else None,
                'total_kg': float(getattr(item, 'kg', 0) or 0),
                'total_slab_quantity': float(getattr(item, 'slab_quantity', 0) or 0),
                'total_c_s_quantity': float(getattr(item, 'c_s_quantity', 0) or 0),
                'total_usd_amount': float(getattr(item, 'usd_rate_item', 0) or 0),
                'total_inr_amount': float(getattr(item, 'usd_rate_item_to_inr', 0) or 0),
                'avg_usd_rate_per_kg': float(getattr(item, 'usd_rate_per_kg', 0) or 0),
                'avg_yield_percentage': float(getattr(item, 'yield_percentage', 0) or 0),
            }
            all_data.append(data_row)

    if entry_type in ['all', 'local']:
        for item in local_queryset:
            data_row = {
                'id': item.id,
                'item__name': item.item.name if item.item else None,
                'item__category__name': item.item.category.name if item.item and item.item.category else None,
                'item_quality__quality': item.item_quality.quality if hasattr(item, 'item_quality') and item.item_quality else None,
                'freezing_entry__voucher_number': item.freezing_entry.voucher_number if item.freezing_entry else None,
                'freezing_entry__freezing_date': item.freezing_entry.freezing_date if item.freezing_entry else None,
                'freezing_entry__freezing_status': item.freezing_entry.freezing_status if item.freezing_entry else None,
                'entry_type': 'local',
                'item_count': 1,
                'peeling_type__name': item.peeling_type.name if hasattr(item, 'peeling_type') and item.peeling_type else None,
                'grade__grade': item.grade.grade if hasattr(item, 'grade') and item.grade else None,
                'grade__order_code': item.grade.order_code if hasattr(item, 'grade') and item.grade else None,
                'brand__name': item.brand.name if hasattr(item, 'brand') and item.brand else None,
                'freezing_category__name': item.freezing_category.name if hasattr(item, 'freezing_category') and item.freezing_category else None,
                'processing_center__name': item.processing_center.name if hasattr(item, 'processing_center') and item.processing_center else None,
                'store__name': item.store.name if hasattr(item, 'store') and item.store else None,
                'unit__description': item.unit.description if hasattr(item, 'unit') and item.unit else None,
                'unit__unit_code': item.unit.unit_code if hasattr(item, 'unit') and item.unit else None,
                'glaze__percentage': item.glaze.percentage if hasattr(item, 'glaze') and item.glaze else None,
                'total_kg': float(getattr(item, 'kg', 0) or 0),
                'total_slab_quantity': float(getattr(item, 'slab_quantity', 0) or 0),
                'total_c_s_quantity': float(getattr(item, 'c_s_quantity', 0) or 0),
                'total_usd_amount': float(getattr(item, 'usd_rate_item', 0) or 0),
                'total_inr_amount': float(getattr(item, 'usd_rate_item_to_inr', 0) or 0),
                'avg_usd_rate_per_kg': float(getattr(item, 'usd_rate_per_kg', 0) or 0),
                'avg_yield_percentage': None,
            }
            all_data.append(data_row)

    # Sectioning logic
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
            section_key = f"{date_obj.strftime('%B %Y')}" if date_obj else "No Date"
        elif section_by == "peeling_type":
            section_key = item.get("peeling_type__name") or "No Peeling Type"
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
        
        totals = sectioned_data[section_key]['totals']
        totals['total_kg'] += float(item.get('total_kg') or 0)
        totals['total_slab_quantity'] += float(item.get('total_slab_quantity') or 0)
        totals['total_c_s_quantity'] += float(item.get('total_c_s_quantity') or 0)
        totals['total_usd_amount'] += float(item.get('total_usd_amount') or 0)
        totals['total_inr_amount'] += float(item.get('total_inr_amount') or 0)
        totals['count'] += 1
        totals['item_count'] += int(item.get('item_count') or 0)

    # Sort sections and items by grade order_code
    if section_by == "grade":
        # Create grade order mapping from database
        grade_order_map = {g.grade: (g.order_code or 999999, g.grade) for g in grades}
        
        # Sort sections by order_code
        sectioned_data = dict(sorted(
            sectioned_data.items(),
            key=lambda x: grade_order_map.get(x[0], (999999, x[0]))
        ))
        
        # Items within sections are already sorted from database query
    else:
        # For non-grade sections, sort by section name
        sectioned_data = dict(sorted(sectioned_data.items()))
        
        # But still sort items within each section by grade order_code
        for section_key in sectioned_data:
            sectioned_data[section_key]['items'].sort(
                key=lambda x: (
                    x.get('grade__order_code') or 999999,
                    x.get('freezing_entry__freezing_date') or datetime.min.date(),
                    x.get('id') or 0
                )
            )

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
    except:
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
            "peeling_types": peeling_types,
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
            "selected_peeling_types": selected_peeling_types,
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

@check_permission('reports_export')
def freezing_report_print(request):
    """Separate view specifically for print format with grade order_code sorting"""
    
    # Get filter parameters
    selected_items = request.GET.getlist("items")
    selected_grades = request.GET.getlist("grades")
    selected_categories = request.GET.getlist("categories")
    selected_peeling_types = request.GET.getlist("peeling_types")
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
    entry_type = request.GET.get("entry_type", "all")
    section_by = request.GET.get("section_by", "category")

    # Get grades for sorting reference
    grades = ItemGrade.objects.all().order_by(
        F('order_code').asc(nulls_last=True),
        'grade'
    )

    # Start with minimal select_related
    spot_queryset = FreezingEntrySpotItem.objects.select_related(
        "freezing_entry", "item", "item__category", "item_quality"
    )
    local_queryset = FreezingEntryLocalItem.objects.select_related(
        "freezing_entry", "item", "item__category", "item_quality"
    )

    # Add optional relationships
    try:
        test_spot = FreezingEntrySpotItem.objects.first()
        if test_spot:
            if hasattr(test_spot, 'grade'):
                spot_queryset = spot_queryset.select_related("grade")
                local_queryset = local_queryset.select_related("grade")
            if hasattr(test_spot, 'peeling_type'):
                spot_queryset = spot_queryset.select_related("peeling_type")
                local_queryset = local_queryset.select_related("peeling_type")
            if hasattr(test_spot, 'brand'):
                spot_queryset = spot_queryset.select_related("brand")
                local_queryset = local_queryset.select_related("brand")
            if hasattr(test_spot, 'freezing_category'):
                spot_queryset = spot_queryset.select_related("freezing_category")
                local_queryset = local_queryset.select_related("freezing_category")
            if hasattr(test_spot, 'processing_center'):
                spot_queryset = spot_queryset.select_related("processing_center")
                local_queryset = local_queryset.select_related("processing_center")
            if hasattr(test_spot, 'store'):
                spot_queryset = spot_queryset.select_related("store")
                local_queryset = local_queryset.select_related("store")
            if hasattr(test_spot, 'unit'):
                spot_queryset = spot_queryset.select_related("unit")
                local_queryset = local_queryset.select_related("unit")
            if hasattr(test_spot, 'glaze'):
                spot_queryset = spot_queryset.select_related("glaze")
                local_queryset = local_queryset.select_related("glaze")
    except:
        pass

    # Apply filters
    def apply_filters(queryset):
        if selected_items:
            queryset = queryset.filter(item__id__in=selected_items)
        
        test_item = queryset.first()
        if test_item:
            if hasattr(test_item, 'grade') and selected_grades:
                queryset = queryset.filter(grade__id__in=selected_grades)
            if hasattr(test_item, 'peeling_type') and selected_peeling_types:
                queryset = queryset.filter(peeling_type__id__in=selected_peeling_types)
            if hasattr(test_item, 'brand') and selected_brands:
                queryset = queryset.filter(brand__id__in=selected_brands)
            if hasattr(test_item, 'freezing_category') and selected_freezing_categories:
                queryset = queryset.filter(freezing_category__id__in=selected_freezing_categories)
            if hasattr(test_item, 'processing_center') and selected_processing_centers:
                queryset = queryset.filter(processing_center__id__in=selected_processing_centers)
            if hasattr(test_item, 'store') and selected_stores:
                queryset = queryset.filter(store__id__in=selected_stores)
            if hasattr(test_item, 'unit') and selected_units:
                queryset = queryset.filter(unit__id__in=selected_units)
            if hasattr(test_item, 'glaze') and selected_glazes:
                queryset = queryset.filter(glaze__id__in=selected_glazes)
        
        if selected_categories:
            queryset = queryset.filter(item__category__id__in=selected_categories)
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

    spot_queryset = apply_filters(spot_queryset)
    local_queryset = apply_filters(local_queryset)

    # CRITICAL: Order by grade order_code at database level
    spot_queryset = spot_queryset.order_by(
        F('grade__order_code').asc(nulls_last=True),
        'freezing_entry__freezing_date',
        'id'
    )
    local_queryset = local_queryset.order_by(
        F('grade__order_code').asc(nulls_last=True),
        'freezing_entry__freezing_date',
        'id'
    )

    # Process data
    all_data = []

    if entry_type in ['all', 'spot']:
        for item in spot_queryset:
            data_row = {
                'id': item.id,
                'item__name': item.item.name if item.item else None,
                'item__category__name': item.item.category.name if item.item and item.item.category else None,
                'item_quality__quality': item.item_quality.quality if hasattr(item, 'item_quality') and item.item_quality else None,
                'freezing_entry__voucher_number': item.freezing_entry.voucher_number if item.freezing_entry else None,
                'freezing_entry__freezing_date': item.freezing_entry.freezing_date if item.freezing_entry else None,
                'freezing_entry__freezing_status': item.freezing_entry.freezing_status if item.freezing_entry else None,
                'entry_type': 'spot',
                'item_count': 1,
                'peeling_type__name': item.peeling_type.name if hasattr(item, 'peeling_type') and item.peeling_type else None,
                'grade__grade': item.grade.grade if hasattr(item, 'grade') and item.grade else None,
                'grade__order_code': item.grade.order_code if hasattr(item, 'grade') and item.grade else None,
                'brand__name': item.brand.name if hasattr(item, 'brand') and item.brand else None,
                'freezing_category__name': item.freezing_category.name if hasattr(item, 'freezing_category') and item.freezing_category else None,
                'processing_center__name': item.processing_center.name if hasattr(item, 'processing_center') and item.processing_center else None,
                'store__name': item.store.name if hasattr(item, 'store') and item.store else None,
                'unit__description': item.unit.description if hasattr(item, 'unit') and item.unit else None,
                'unit__unit_code': item.unit.unit_code if hasattr(item, 'unit') and item.unit else None,
                'glaze__percentage': item.glaze.percentage if hasattr(item, 'glaze') and item.glaze else None,
                'total_kg': float(getattr(item, 'kg', 0) or 0),
                'total_slab_quantity': float(getattr(item, 'slab_quantity', 0) or 0),
                'total_c_s_quantity': float(getattr(item, 'c_s_quantity', 0) or 0),
                'total_usd_amount': float(getattr(item, 'usd_rate_item', 0) or 0),
                'total_inr_amount': float(getattr(item, 'usd_rate_item_to_inr', 0) or 0),
                'avg_usd_rate_per_kg': float(getattr(item, 'usd_rate_per_kg', 0) or 0),
                'avg_yield_percentage': float(getattr(item, 'yield_percentage', 0) or 0),
            }
            all_data.append(data_row)

    if entry_type in ['all', 'local']:
        for item in local_queryset:
            data_row = {
                'id': item.id,
                'item__name': item.item.name if item.item else None,
                'item__category__name': item.item.category.name if item.item and item.item.category else None,
                'item_quality__quality': item.item_quality.quality if hasattr(item, 'item_quality') and item.item_quality else None,
                'freezing_entry__voucher_number': item.freezing_entry.voucher_number if item.freezing_entry else None,
                'freezing_entry__freezing_date': item.freezing_entry.freezing_date if item.freezing_entry else None,
                'freezing_entry__freezing_status': item.freezing_entry.freezing_status if item.freezing_entry else None,
                'entry_type': 'local',
                'item_count': 1,
                'peeling_type__name': item.peeling_type.name if hasattr(item, 'peeling_type') and item.peeling_type else None,
                'grade__grade': item.grade.grade if hasattr(item, 'grade') and item.grade else None,
                'grade__order_code': item.grade.order_code if hasattr(item, 'grade') and item.grade else None,
                'brand__name': item.brand.name if hasattr(item, 'brand') and item.brand else None,
                'freezing_category__name': item.freezing_category.name if hasattr(item, 'freezing_category') and item.freezing_category else None,
                'processing_center__name': item.processing_center.name if hasattr(item, 'processing_center') and item.processing_center else None,
                'store__name': item.store.name if hasattr(item, 'store') and item.store else None,
                'unit__description': item.unit.description if hasattr(item, 'unit') and item.unit else None,
                'unit__unit_code': item.unit.unit_code if hasattr(item, 'unit') and item.unit else None,
                'glaze__percentage': item.glaze.percentage if hasattr(item, 'glaze') and item.glaze else None,
                'total_kg': float(getattr(item, 'kg', 0) or 0),
                'total_slab_quantity': float(getattr(item, 'slab_quantity', 0) or 0),
                'total_c_s_quantity': float(getattr(item, 'c_s_quantity', 0) or 0),
                'total_usd_amount': float(getattr(item, 'usd_rate_item', 0) or 0),
                'total_inr_amount': float(getattr(item, 'usd_rate_item_to_inr', 0) or 0),
                'avg_usd_rate_per_kg': float(getattr(item, 'usd_rate_per_kg', 0) or 0),
                'avg_yield_percentage': None,
            }
            all_data.append(data_row)

    # Sectioning logic
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
            section_key = f"{date_obj.strftime('%B %Y')}" if date_obj else "No Date"
        elif section_by == "peeling_type":
            section_key = item.get("peeling_type__name") or "No Peeling Type"
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
        
        totals = sectioned_data[section_key]['totals']
        totals['total_kg'] += float(item.get('total_kg') or 0)
        totals['total_slab_quantity'] += float(item.get('total_slab_quantity') or 0)
        totals['total_c_s_quantity'] += float(item.get('total_c_s_quantity') or 0)
        totals['total_usd_amount'] += float(item.get('total_usd_amount') or 0)
        totals['total_inr_amount'] += float(item.get('total_inr_amount') or 0)
        totals['count'] += 1
        totals['item_count'] += int(item.get('item_count') or 0)

    # Sort sections and items by grade order_code
    if section_by == "grade":
        # Create grade order mapping
        grade_order_map = {g.grade: (g.order_code or 999999, g.grade) for g in grades}
        
        # Sort sections by order_code
        sectioned_data = dict(sorted(
            sectioned_data.items(),
            key=lambda x: grade_order_map.get(x[0], (999999, x[0]))
        ))
    else:
        # Sort sections alphabetically
        sectioned_data = dict(sorted(sectioned_data.items()))
        
        # Sort items within each section by grade order_code
        for section_key in sectioned_data:
            sectioned_data[section_key]['items'].sort(
                key=lambda x: (
                    x.get('grade__order_code') or 999999,
                    x.get('freezing_entry__freezing_date') or datetime.min.date(),
                    x.get('id') or 0
                )
            )

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

    return render(
        request,
        "adminapp/report/freezing_report_print.html",
        {
            "sectioned_data": sectioned_data,
            "grand_totals": grand_totals,
            "start_date": start_date,
            "end_date": end_date,
            "entry_type": entry_type,
            "section_by": section_by,
            "date_filter": date_filter,
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
            try:
                # Calculate totals first
                total_kg = Decimal(0)
                total_slab = Decimal(0)
                total_c_s = Decimal(0)

                # Process formset to calculate totals
                for f in formset:
                    if f.cleaned_data and not f.cleaned_data.get('DELETE', False):
                        slab = f.cleaned_data.get('slab_quantity') or Decimal(0)
                        cs = f.cleaned_data.get('c_s_quantity') or Decimal(0)
                        kg = f.cleaned_data.get('kg') or Decimal(0)

                        total_slab += slab
                        total_c_s += cs
                        total_kg += kg

                # Save the main entry first
                entry = form.save(commit=False)
                entry.total_slab = total_slab
                entry.total_c_s = total_c_s
                entry.total_kg = total_kg
                entry.total_amount = 0
                entry.save()
                
                print(f"Main entry saved with ID: {entry.id}")
                print(f"Tenant: {entry.tenant_company_name}")
                
                # Set the instance and save the formset
                formset.instance = entry
                saved_items = formset.save()
                print(f"Saved {len(saved_items)} items from formset")
                
                # Debug: Check what was actually saved
                for i, item in enumerate(saved_items):
                    print(f"Item {i+1}: {item.item} - Slab: {item.slab_quantity} - CS: {item.c_s_quantity} - KG: {item.kg}")

                # Now CREATE/UPDATE tenant stock
                stock_errors = []
                for freezing_item in saved_items:
                    try:
                        # Prepare tenant stock filter criteria
                        stock_filters = {
                            'tenant_company_name': entry.tenant_company_name,
                            'item': freezing_item.item,
                            'brand': freezing_item.brand,
                            'freezing_category': freezing_item.freezing_category,
                            'unit': freezing_item.unit,
                            'glaze': freezing_item.glaze,
                            'species': freezing_item.species,
                            'grade': freezing_item.grade,
                        }
                        
                        # Add nullable fields for filtering
                        if freezing_item.processing_center:
                            stock_filters['processing_center'] = freezing_item.processing_center
                        else:
                            stock_filters['processing_center__isnull'] = True
                            
                        if freezing_item.store:
                            stock_filters['store'] = freezing_item.store
                        else:
                            stock_filters['store__isnull'] = True
                            
                        if freezing_item.item_quality:
                            stock_filters['item_quality'] = freezing_item.item_quality
                        else:
                            stock_filters['item_quality__isnull'] = True
                            
                        if freezing_item.peeling_type:
                            stock_filters['peeling_type'] = freezing_item.peeling_type
                        else:
                            stock_filters['peeling_type__isnull'] = True
                        
                        print(f"\nLooking for tenant stock with filters: {stock_filters}")

                        # Get quantities
                        slab = freezing_item.slab_quantity or Decimal(0)
                        cs = freezing_item.c_s_quantity or Decimal(0)
                        kg = freezing_item.kg or Decimal(0)

                        # Try to find existing tenant stock with row-level lock
                        existing_stock = TenantStock.objects.select_for_update().filter(**stock_filters).first()
                        
                        if existing_stock:
                            # Update existing stock (ADD quantities for freezing entry)
                            print(f"\n✚ ADDING to existing tenant stock for {freezing_item.item.name}:")
                            print(f"  Tenant: {entry.tenant_company_name}")
                            print(f"  Current: Slab={existing_stock.available_slab}, CS={existing_stock.available_c_s}, KG={existing_stock.available_kg}")
                            print(f"  Adding: Slab={slab}, CS={cs}, KG={kg}")
                            
                            # ADD quantities (freezing creates new stock for tenant)
                            existing_stock.available_slab += slab
                            existing_stock.available_c_s += cs
                            existing_stock.available_kg += kg
                            
                            existing_stock.original_slab += slab
                            existing_stock.original_c_s += cs
                            existing_stock.original_kg += kg
                            
                            existing_stock.save()
                            
                            print(f"  New Total: Slab={existing_stock.available_slab}, CS={existing_stock.available_c_s}, KG={existing_stock.available_kg}")
                            print(f"  ✓ Tenant stock UPDATED successfully")
                            
                        else:
                            # CREATE new tenant stock entry
                            new_stock = TenantStock.objects.create(
                                tenant_company_name=entry.tenant_company_name,
                                processing_center=freezing_item.processing_center,
                                store=freezing_item.store,
                                item=freezing_item.item,
                                item_quality=freezing_item.item_quality,
                                unit=freezing_item.unit,
                                glaze=freezing_item.glaze,
                                freezing_category=freezing_item.freezing_category,
                                brand=freezing_item.brand,
                                species=freezing_item.species,
                                grade=freezing_item.grade,
                                peeling_type=freezing_item.peeling_type,
                                available_slab=slab,
                                available_c_s=cs,
                                available_kg=kg,
                                original_slab=slab,
                                original_c_s=cs,
                                original_kg=kg,
                            )
                            
                            print(f"\n✓ NEW tenant stock CREATED for {freezing_item.item.name}:")
                            print(f"  Tenant: {entry.tenant_company_name}")
                            print(f"  Slab={new_stock.available_slab}, CS={new_stock.available_c_s}, KG={new_stock.available_kg}")

                    except Exception as stock_error:
                        error_msg = f"Error with tenant stock for {freezing_item.item.name}: {str(stock_error)}"
                        print(error_msg)
                        import traceback
                        print(f"Stock error traceback: {traceback.format_exc()}")
                        stock_errors.append(error_msg)
                        continue

                # Add any stock errors as warning messages
                for error in stock_errors:
                    messages.warning(request, error)

                if stock_errors:
                    messages.success(request, 'Freezing entry created successfully, but some tenant stock updates failed.')
                else:
                    messages.success(request, 'Freezing entry created successfully and tenant stock updated!')
                    
                return redirect(reverse('adminapp:list_freezing_entry_tenant'))
                
            except Exception as e:
                print(f"Error in transaction: {e}")
                import traceback
                print(f"Full traceback: {traceback.format_exc()}")
                messages.error(request, f'Error creating freezing entry: {str(e)}')
        else:
            # Debug form and formset errors
            print("=== VALIDATION ERRORS ===")
            if not form.is_valid():
                print(f"Form errors: {form.errors}")
            if not formset.is_valid():
                print(f"Formset errors: {formset.errors}")
                print(f"Formset non_form_errors: {formset.non_form_errors()}")
                
                # Debug individual form errors
                for i, form_instance in enumerate(formset):
                    if form_instance.errors:
                        print(f"Form {i} errors: {form_instance.errors}")
                        print(f"Form {i} cleaned_data: {form_instance.cleaned_data if form_instance.is_valid() else 'Invalid'}")
                
    else:
        form = FreezingEntryTenantForm()
        formset = FreezingEntryTenantItemFormSet()
        
    return render(request, 'adminapp/tenant/create.html', {'form': form, 'formset': formset})

@check_permission('freezing_edit')
def tenant_freezing_update(request, pk):
    freezing_entry = get_object_or_404(FreezingEntryTenant, pk=pk)

    if request.method == "POST":
        form = FreezingEntryTenantForm(request.POST, instance=freezing_entry)
        formset = FreezingEntryTenantItemFormSet(request.POST, instance=freezing_entry)

        if form.is_valid() and formset.is_valid():
            try:
                with transaction.atomic():
                    # Track tenant change
                    old_tenant = freezing_entry.tenant_company_name
                    new_tenant = form.cleaned_data.get('tenant_company_name')
                    tenant_changed = old_tenant != new_tenant
                    
                    if tenant_changed:
                        print(f"\n⚠️ TENANT CHANGED: {old_tenant} → {new_tenant}")

                    # STEP 1: REMOVE old stock quantities
                    print(f"\n=== STEP 1: REMOVING OLD TENANT STOCK QUANTITIES ===")
                    old_items = freezing_entry.items.all()
                    
                    for old_item in old_items:
                        try:
                            # Build stock filters
                            stock_filters = {
                                'tenant_company_name': old_tenant,
                                'item': old_item.item,
                                'brand': old_item.brand,
                                'freezing_category': old_item.freezing_category,
                                'unit': old_item.unit,
                                'glaze': old_item.glaze,
                                'species': old_item.species,
                                'grade': old_item.grade,
                                'processing_center': old_item.processing_center,
                                'store': old_item.store,
                                'item_quality': old_item.item_quality,
                                'peeling_type': old_item.peeling_type,
                            }
                            # Remove None values
                            stock_filters = {k: v for k, v in stock_filters.items() if v is not None}
                            
                            # Find matching tenant stock with row-level lock
                            existing_stock = TenantStock.objects.select_for_update().filter(**stock_filters).first()
                            
                            if existing_stock:
                                old_slab = old_item.slab_quantity or Decimal(0)
                                old_cs = old_item.c_s_quantity or Decimal(0)
                                old_kg = old_item.kg or Decimal(0)
                                
                                print(f"\nRemoving from {old_item.item.name} (Tenant: {old_tenant}):")
                                print(f"  Current Stock: Slab={existing_stock.available_slab}, CS={existing_stock.available_c_s}, KG={existing_stock.available_kg}")
                                print(f"  Removing: Slab={old_slab}, CS={old_cs}, KG={old_kg}")
                                
                                # Subtract quantities
                                existing_stock.available_slab -= old_slab
                                existing_stock.available_c_s -= old_cs
                                existing_stock.available_kg -= old_kg
                                
                                existing_stock.original_slab -= old_slab
                                existing_stock.original_c_s -= old_cs
                                existing_stock.original_kg -= old_kg
                                
                                print(f"  New Stock: Slab={existing_stock.available_slab}, CS={existing_stock.available_c_s}, KG={existing_stock.available_kg}")
                                
                                # Delete if all are zero or negative
                                if (existing_stock.available_slab <= 0 and 
                                    existing_stock.available_c_s <= 0 and 
                                    existing_stock.available_kg <= 0):
                                    print(f"  Stock depleted to zero/negative, deleting entry")
                                    existing_stock.delete()
                                else:
                                    existing_stock.save()
                                    if (existing_stock.available_slab < 0 or 
                                        existing_stock.available_c_s < 0 or 
                                        existing_stock.available_kg < 0):
                                        print(f"  ⚠ WARNING: Tenant stock is now NEGATIVE!")
                                        messages.warning(
                                            request,
                                            f"Warning: {old_item.item.name} tenant stock is negative "
                                            f"(Slab: {existing_stock.available_slab}, CS: {existing_stock.available_c_s}, KG: {existing_stock.available_kg})"
                                        )
                                    else:
                                        print(f"  ✓ Tenant stock updated successfully")
                            else:
                                # Stock not found - this shouldn't happen but handle it
                                print(f"\n⚠ WARNING: No tenant stock found for {old_item.item.name} (Tenant: {old_tenant})")
                                messages.warning(request, f"No tenant stock record found for {old_item.item.name}")
                                
                        except Exception as e:
                            print(f"Error removing old tenant stock: {e}")
                            import traceback
                            traceback.print_exc()
                            messages.warning(request, f"Error removing tenant stock for {old_item.item.name}: {str(e)}")

                    # STEP 2: Process new data and calculate totals
                    print(f"\n=== STEP 2: PROCESSING NEW DATA ===")
                    total_kg = Decimal(0)
                    total_slab = Decimal(0)
                    total_c_s = Decimal(0)
                    
                    stock_updates = []

                    # Process formset
                    for f in formset:
                        if f.cleaned_data and not f.cleaned_data.get("DELETE", False):
                            slab = f.cleaned_data.get("slab_quantity") or Decimal(0)
                            cs = f.cleaned_data.get("c_s_quantity") or Decimal(0)
                            kg = f.cleaned_data.get("kg") or Decimal(0)

                            # Extract data for stock
                            stock_data = {
                                'processing_center': f.cleaned_data.get('processing_center'),
                                'store': f.cleaned_data.get('store'),
                                'item': f.cleaned_data.get('item'),
                                'item_quality': f.cleaned_data.get('item_quality'),
                                'unit': f.cleaned_data.get('unit'),
                                'glaze': f.cleaned_data.get('glaze'),
                                'brand': f.cleaned_data.get('brand'),
                                'species': f.cleaned_data.get('species'),
                                'grade': f.cleaned_data.get('grade'),
                                'peeling_type': f.cleaned_data.get('peeling_type'),
                                'freezing_category': f.cleaned_data.get('freezing_category'),
                                'slab': slab,
                                'cs': cs,
                                'kg': kg,
                            }

                            if stock_data['item'] and stock_data['brand']:
                                stock_updates.append(stock_data)
                                print(f"\nItem to add: {stock_data['item'].name}")
                                print(f"  Slab={slab}, CS={cs}, KG={kg}")

                            # Calculate totals
                            total_slab += slab
                            total_c_s += cs
                            total_kg += kg

                    # Assign totals
                    entry = form.save(commit=False)
                    entry.total_slab = total_slab
                    entry.total_c_s = total_c_s
                    entry.total_kg = total_kg
                    entry.total_amount = 0

                    entry.save()
                    formset.instance = entry
                    formset.save()

                    # STEP 3: ADD new stock quantities
                    print(f"\n=== STEP 3: ADDING NEW TENANT STOCK QUANTITIES ===")
                    for stock_data in stock_updates:
                        try:
                            # Build stock filters (use NEW tenant from entry)
                            stock_filters = {
                                'tenant_company_name': entry.tenant_company_name,
                                'item': stock_data['item'],
                                'brand': stock_data['brand'],
                                'freezing_category': stock_data['freezing_category'],
                                'unit': stock_data['unit'],
                                'glaze': stock_data['glaze'],
                                'species': stock_data['species'],
                                'grade': stock_data['grade'],
                                'processing_center': stock_data['processing_center'],
                                'store': stock_data['store'],
                                'item_quality': stock_data['item_quality'],
                                'peeling_type': stock_data['peeling_type'],
                            }
                            # Remove None values
                            stock_filters = {k: v for k, v in stock_filters.items() if v is not None}

                            # Find existing tenant stock with row-level lock
                            existing_stock = TenantStock.objects.select_for_update().filter(**stock_filters).first()
                            
                            if existing_stock:
                                print(f"\nAdding to {stock_data['item'].name} (Tenant: {entry.tenant_company_name}):")
                                print(f"  Current Stock: Slab={existing_stock.available_slab}, CS={existing_stock.available_c_s}, KG={existing_stock.available_kg}")
                                print(f"  Adding: Slab={stock_data['slab']}, CS={stock_data['cs']}, KG={stock_data['kg']}")
                                
                                # Add new quantities
                                existing_stock.available_slab += stock_data['slab']
                                existing_stock.available_c_s += stock_data['cs']
                                existing_stock.available_kg += stock_data['kg']
                                
                                existing_stock.original_slab += stock_data['slab']
                                existing_stock.original_c_s += stock_data['cs']
                                existing_stock.original_kg += stock_data['kg']
                                
                                existing_stock.save()
                                
                                print(f"  New Stock: Slab={existing_stock.available_slab}, CS={existing_stock.available_c_s}, KG={existing_stock.available_kg}")
                                print(f"  ✓ Tenant stock updated successfully")
                                
                            else:
                                # Create new tenant stock entry
                                new_stock_data = {
                                    **stock_filters,
                                    'available_slab': stock_data['slab'],
                                    'available_c_s': stock_data['cs'],
                                    'available_kg': stock_data['kg'],
                                    'original_slab': stock_data['slab'],
                                    'original_c_s': stock_data['cs'],
                                    'original_kg': stock_data['kg'],
                                }
                                
                                stock = TenantStock.objects.create(**new_stock_data)
                                print(f"\n✓ Tenant stock CREATED for {stock_data['item'].name} (Tenant: {entry.tenant_company_name}):")
                                print(f"  Slab={stock.available_slab}, CS={stock.available_c_s}, KG={stock.available_kg}")

                        except Exception as e:
                            print(f"\n✗ Error updating tenant stock for {stock_data['item'].name}: {e}")
                            import traceback
                            traceback.print_exc()
                            messages.warning(request, f"Error updating tenant stock for {stock_data['item'].name}: {str(e)}")

                    print(f"\n=== UPDATE COMPLETE ===")
                    
                    if tenant_changed:
                        messages.success(
                            request, 
                            f'Freezing entry updated successfully! Tenant changed from {old_tenant} to {entry.tenant_company_name}. Stock synchronized for both tenants.'
                        )
                    else:
                        messages.success(request, 'Freezing entry updated successfully and tenant stock synchronized!')
                        
                    return redirect(reverse('adminapp:list_freezing_entry_tenant'))
                    
            except ValueError as e:
                # Validation error
                print(f"\n✗ Validation Error: {e}")
                messages.error(request, str(e))
            except Exception as e:
                # Other errors
                print(f"\n✗ Transaction failed: {e}")
                import traceback
                traceback.print_exc()
                messages.error(request, f'Error updating freezing entry: {str(e)}')
        else:
            print("Form Errors:", form.errors)
            print("Formset Errors:", formset.errors)
            messages.error(request, 'Please correct the errors below.')

    else:
        form = FreezingEntryTenantForm(instance=freezing_entry)
        formset = FreezingEntryTenantItemFormSet(instance=freezing_entry)

    return render(
        request,
        'adminapp/tenant/update.html',
        {'form': form, 'formset': formset, 'entry': freezing_entry}
    )

@transaction.atomic
@check_permission('freezing_delete')
def tenant_freezing_delete(request, pk):
    entry = get_object_or_404(FreezingEntryTenant, pk=pk)
    
    if request.method == "POST":
        try:
            print(f"\n=== DELETING TENANT FREEZING ENTRY ===")
            print(f"Entry: {entry.voucher_number} - Tenant: {entry.tenant_company_name}")
            
            # Get all items before deletion
            items = list(entry.items.all())
            
            # STEP 1: Remove quantities from tenant stock
            print(f"\n=== REMOVING QUANTITIES FROM TENANT STOCK ===")
            for item in items:
                try:
                    # Build stock filters
                    stock_filters = {
                        'tenant_company_name': entry.tenant_company_name,
                        'item': item.item,
                        'brand': item.brand,
                        'freezing_category': item.freezing_category,
                        'unit': item.unit,
                        'glaze': item.glaze,
                        'species': item.species,
                        'grade': item.grade,
                        'processing_center': item.processing_center,
                        'store': item.store,
                        'item_quality': item.item_quality,
                        'peeling_type': item.peeling_type,
                    }
                    # Remove None values
                    stock_filters = {k: v for k, v in stock_filters.items() if v is not None}
                    
                    # Find matching tenant stock with row-level lock
                    existing_stock = TenantStock.objects.select_for_update().filter(**stock_filters).first()
                    
                    if existing_stock:
                        item_slab = item.slab_quantity or Decimal(0)
                        item_cs = item.c_s_quantity or Decimal(0)
                        item_kg = item.kg or Decimal(0)
                        
                        print(f"\nRemoving from {item.item.name}:")
                        print(f"  Current Stock: Slab={existing_stock.available_slab}, CS={existing_stock.available_c_s}, KG={existing_stock.available_kg}")
                        print(f"  Removing: Slab={item_slab}, CS={item_cs}, KG={item_kg}")
                        
                        # Subtract quantities
                        existing_stock.available_slab -= item_slab
                        existing_stock.available_c_s -= item_cs
                        existing_stock.available_kg -= item_kg
                        
                        existing_stock.original_slab -= item_slab
                        existing_stock.original_c_s -= item_cs
                        existing_stock.original_kg -= item_kg
                        
                        print(f"  New Stock: Slab={existing_stock.available_slab}, CS={existing_stock.available_c_s}, KG={existing_stock.available_kg}")
                        
                        # Delete if all are zero or negative
                        if (existing_stock.available_slab <= 0 and 
                            existing_stock.available_c_s <= 0 and 
                            existing_stock.available_kg <= 0):
                            print(f"  Stock depleted to zero/negative, deleting tenant stock entry")
                            existing_stock.delete()
                        else:
                            existing_stock.save()
                            if (existing_stock.available_slab < 0 or 
                                existing_stock.available_c_s < 0 or 
                                existing_stock.available_kg < 0):
                                print(f"  ⚠ WARNING: Tenant stock is now NEGATIVE!")
                                messages.warning(
                                    request,
                                    f"Warning: {item.item.name} tenant stock is negative "
                                    f"(Slab: {existing_stock.available_slab}, CS: {existing_stock.available_c_s}, KG: {existing_stock.available_kg})"
                                )
                            else:
                                print(f"  ✓ Tenant stock updated successfully")
                    else:
                        print(f"\n⚠ WARNING: No tenant stock found for {item.item.name}")
                        messages.warning(request, f"No tenant stock record found for {item.item.name}")
                        
                except Exception as e:
                    print(f"Error removing tenant stock for {item.item.name}: {e}")
                    import traceback
                    traceback.print_exc()
                    messages.warning(request, f"Error removing tenant stock for {item.item.name}: {str(e)}")
            
            # STEP 2: Delete the entry (cascade will delete items)
            print(f"\n=== DELETING FREEZING ENTRY ===")
            entry.delete()
            print(f"✓ Entry deleted successfully")
            
            messages.success(request, f'Freezing entry {entry.voucher_number} deleted successfully and tenant stock updated!')
            return redirect('adminapp:list_freezing_entry_tenant')
            
        except Exception as e:
            print(f"\n✗ Deletion failed: {e}")
            import traceback
            traceback.print_exc()
            messages.error(request, f'Error deleting freezing entry: {str(e)}')
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





@transaction.atomic
@check_permission('freezing_add')
def return_tenant_create(request):
    if request.method == "POST":
        form = ReturnTenantForm(request.POST)
        formset = ReturnTenantItemFormSet(request.POST)
        
        if form.is_valid() and formset.is_valid():
            # Validate stock availability BEFORE saving anything
            tenant_id = form.cleaned_data['tenant_company_name'].id
            errors = []
            
            # Pre-validate all items for stock availability
            for form_item in formset.cleaned_data:
                if form_item and not form_item.get('DELETE', False):
                    try:
                        stock = TenantStock.objects.get(
                            tenant_company_name_id=tenant_id,
                            processing_center=form_item.get('processing_center'),
                            store=form_item.get('store'),
                            item=form_item.get('item'),
                            item_quality=form_item.get('item_quality'),
                            unit=form_item.get('unit'),
                            glaze=form_item.get('glaze'),
                            freezing_category=form_item.get('freezing_category'),
                            brand=form_item.get('brand'),
                            species=form_item.get('species'),
                            grade=form_item.get('grade'),
                            peeling_type=form_item.get('peeling_type'),
                        )
                        
                        slab_qty = form_item.get('slab_quantity', 0)
                        cs_qty = form_item.get('c_s_quantity', 0)
                        kg_qty = form_item.get('kg', 0)
                        
                        # Check if sufficient stock is available
                        if (stock.available_slab < slab_qty or 
                            stock.available_c_s < cs_qty or 
                            stock.available_kg < kg_qty):
                            item_name = form_item.get('item')
                            species_name = form_item.get('species')
                            grade_name = form_item.get('grade')
                            errors.append(
                                f"Insufficient stock for {item_name} - {species_name} - {grade_name}. "
                                f"Available: {stock.available_kg} KG, Requested: {kg_qty} KG"
                            )
                    except TenantStock.DoesNotExist:
                        # Stock doesn't exist - will create with negative values
                        pass
            
            # If validation errors, don't proceed with save
            if errors:
                for error in errors:
                    messages.error(request, error)
                return render(request, 'adminapp/ReturnTenant/create.html', {
                    'form': form,
                    'formset': formset,
                })
            
            # No errors - proceed with saving
            entry = form.save()
            formset.instance = entry
            saved_items = formset.save(commit=False)
            
            total_amount = Decimal("0.00")
            processed_items = []
            
            # Process each returned item
            for item in saved_items:
                item.save()
                processed_items.append(item)
                
                # Try to find existing TenantStock
                try:
                    stock = TenantStock.objects.get(
                        tenant_company_name=entry.tenant_company_name,
                        processing_center=item.processing_center,
                        store=item.store,
                        item=item.item,
                        item_quality=item.item_quality,
                        unit=item.unit,
                        glaze=item.glaze,
                        freezing_category=item.freezing_category,
                        brand=item.brand,
                        species=item.species,
                        grade=item.grade,
                        peeling_type=item.peeling_type,
                    )
                    
                    # Subtract returned quantities from available stock
                    stock.available_slab -= item.slab_quantity
                    stock.available_c_s -= item.c_s_quantity
                    stock.available_kg -= item.kg
                    stock.save()
                    
                except TenantStock.DoesNotExist:
                    # Stock doesn't exist - create with negative values
                    stock = TenantStock.objects.create(
                        tenant_company_name=entry.tenant_company_name,
                        processing_center=item.processing_center,
                        store=item.store,
                        item=item.item,
                        item_quality=item.item_quality,
                        unit=item.unit,
                        glaze=item.glaze,
                        freezing_category=item.freezing_category,
                        brand=item.brand,
                        species=item.species,
                        grade=item.grade,
                        peeling_type=item.peeling_type,
                        available_slab=-item.slab_quantity,
                        available_c_s=-item.c_s_quantity,
                        available_kg=-item.kg,
                        original_slab=-item.slab_quantity,
                        original_c_s=-item.c_s_quantity,
                        original_kg=-item.kg,
                    )
                    
                    # Add warning message
                    messages.warning(request, 
                        f"⚠️ No existing stock found for {item.item} - {item.species}. "
                        f"Created with negative balance: {item.kg} KG")
            
            # Handle deleted items from formset
            for deleted_item in formset.deleted_objects:
                deleted_item.delete()
            
            # Update entry totals
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
            
            messages.success(request, 
                f'✅ Return entry {entry.voucher_number} created successfully! '
                f'{len(processed_items)} items returned. Total: ₹{entry.total_amount}')
            return redirect(reverse('adminapp:list_return_tenant'))
        else:
            if not form.is_valid():
                messages.error(request, f'Form errors: {form.errors}')
            if not formset.is_valid():
                messages.error(request, f'Formset errors: {formset.errors}')
    else:
        form = ReturnTenantForm()
        formset = ReturnTenantItemFormSet()
    
    return render(request, 'adminapp/ReturnTenant/create.html', {
        'form': form,
        'formset': formset,
    })

# AJAX endpoint to get tenant stock details
def get_tenant_stock_ajax(request):
    """
    Returns available stock for a specific tenant
    """
    import traceback
    
    tenant_id = request.GET.get('tenant_id')
    
    if not tenant_id:
        return JsonResponse({'error': 'No tenant selected'}, status=400)
    
    try:
        # Verify tenant exists
        from django.core.exceptions import ObjectDoesNotExist
        try:
            tenant = Tenant.objects.get(id=tenant_id)
        except ObjectDoesNotExist:
            return JsonResponse({'error': f'Tenant with ID {tenant_id} not found'}, status=404)
        
        # Get all available stock for this tenant
        stock_items = TenantStock.objects.filter(
            tenant_company_name_id=tenant_id,
            available_kg__gt=0
        ).select_related(
            'item', 'species', 'grade', 'unit', 'freezing_category',
            'brand', 'glaze', 'item_quality', 'peeling_type', 
            'processing_center', 'store'
        ).order_by('item__name', 'species__name')
        
        stock_data = []
        for stock in stock_items:
            try:
                # Safely get optional fields with proper attribute access
                item_quality_id = stock.item_quality.id if stock.item_quality else None
                item_quality_name = str(stock.item_quality) if stock.item_quality else ''
                
                peeling_type_id = stock.peeling_type.id if stock.peeling_type else None
                peeling_type_name = str(stock.peeling_type) if stock.peeling_type else ''
                
                processing_center_id = stock.processing_center.id if stock.processing_center else None
                processing_center_name = str(stock.processing_center) if stock.processing_center else ''
                
                store_id = stock.store.id if stock.store else None
                store_name = str(stock.store) if stock.store else ''
                
                stock_data.append({
                    'id': stock.id,
                    'item_id': stock.item.id if stock.item else None,
                    'item_name': str(stock.item) if stock.item else 'N/A',
                    'species_id': stock.species.id if stock.species else None,
                    'species_name': str(stock.species) if stock.species else 'N/A',
                    'grade_id': stock.grade.id if stock.grade else None,
                    'grade_name': str(stock.grade) if stock.grade else 'N/A',
                    'unit_id': stock.unit.id if stock.unit else None,
                    'unit_name': str(stock.unit) if stock.unit else 'N/A',
                    'freezing_category_id': stock.freezing_category.id if stock.freezing_category else None,
                    'freezing_category_name': str(stock.freezing_category) if stock.freezing_category else 'N/A',
                    'brand_id': stock.brand.id if stock.brand else None,
                    'brand_name': str(stock.brand) if stock.brand else 'N/A',
                    'glaze_id': stock.glaze.id if stock.glaze else None,
                    'glaze_name': str(stock.glaze) if stock.glaze else 'N/A',
                    'item_quality_id': item_quality_id,
                    'item_quality_name': item_quality_name,
                    'peeling_type_id': peeling_type_id,
                    'peeling_type_name': peeling_type_name,
                    'processing_center_id': processing_center_id,
                    'processing_center_name': processing_center_name,
                    'store_id': store_id,
                    'store_name': store_name,
                    'available_slab': float(stock.available_slab),
                    'available_c_s': float(stock.available_c_s),
                    'available_kg': float(stock.available_kg),
                    'display_text': (
                        f"{str(stock.item) if stock.item else 'N/A'} - "
                        f"{str(stock.species) if stock.species else 'N/A'} - "
                        f"{str(stock.grade) if stock.grade else 'N/A'} | "
                        f"Available: {stock.available_kg} KG ({stock.available_slab} Slab, {stock.available_c_s} C/S)"
                    )
                })
            except AttributeError as attr_error:
                # Log specific attribute error
                print(f"AttributeError for stock item {stock.id}: {str(attr_error)}")
                print(f"Item Quality object: {stock.item_quality}")
                print(f"Item Quality type: {type(stock.item_quality)}")
                continue
            except Exception as item_error:
                print(f"Error processing stock item {stock.id}: {str(item_error)}")
                print(f"Error type: {type(item_error).__name__}")
                continue
        
        return JsonResponse({
            'success': True,
            'stock_count': len(stock_data),
            'stock_items': stock_data,
            'tenant_name': tenant.name if hasattr(tenant, 'name') else 'Unknown'
        })
        
    except Exception as e:
        # Log the full error for debugging
        error_trace = traceback.format_exc()
        print(f"Error in get_tenant_stock_ajax: {error_trace}")
        
        return JsonResponse({
            'success': False,
            'error': str(e),
            'error_type': type(e).__name__
        }, status=500)

@check_permission('freezing_edit')
def return_tenant_update(request, pk):
    return_entry = get_object_or_404(ReturnTenant, pk=pk)

    if request.method == "POST":
        form = ReturnTenantForm(request.POST, instance=return_entry)
        formset = ReturnTenantItemFormSet(request.POST, instance=return_entry)

        if form.is_valid() and formset.is_valid():
            try:
                with transaction.atomic():
                    # Track tenant change
                    old_tenant = return_entry.tenant_company_name
                    new_tenant = form.cleaned_data.get('tenant_company_name')
                    tenant_changed = old_tenant != new_tenant
                    
                    if tenant_changed:
                        print(f"\n⚠️ TENANT CHANGED: {old_tenant} → {new_tenant}")

                    # STEP 1: RESTORE old stock quantities (reverse the return)
                    print(f"\n=== STEP 1: RESTORING OLD TENANT STOCK QUANTITIES ===")
                    old_items = return_entry.items.all()
                    
                    for old_item in old_items:
                        try:
                            # Build stock filters
                            stock_filters = {
                                'tenant_company_name': old_tenant,
                                'item': old_item.item,
                                'brand': old_item.brand,
                                'freezing_category': old_item.freezing_category,
                                'unit': old_item.unit,
                                'glaze': old_item.glaze,
                                'species': old_item.species,
                                'grade': old_item.grade,
                                'processing_center': old_item.processing_center,
                                'store': old_item.store,
                                'item_quality': old_item.item_quality,
                                'peeling_type': old_item.peeling_type,
                            }
                            # Remove None values
                            stock_filters = {k: v for k, v in stock_filters.items() if v is not None}
                            
                            # Find matching tenant stock with row-level lock
                            existing_stock = TenantStock.objects.select_for_update().filter(**stock_filters).first()
                            
                            if existing_stock:
                                old_slab = old_item.slab_quantity or Decimal(0)
                                old_cs = old_item.c_s_quantity or Decimal(0)
                                old_kg = old_item.kg or Decimal(0)
                                
                                print(f"\nRestoring {old_item.item.name} (Tenant: {old_tenant}):")
                                print(f"  Current Stock: Slab={existing_stock.available_slab}, CS={existing_stock.available_c_s}, KG={existing_stock.available_kg}")
                                print(f"  Restoring (Adding back): Slab={old_slab}, CS={old_cs}, KG={old_kg}")
                                
                                # Add back the returned quantities
                                existing_stock.available_slab += old_slab
                                existing_stock.available_c_s += old_cs
                                existing_stock.available_kg += old_kg
                                
                                existing_stock.original_slab += old_slab
                                existing_stock.original_c_s += old_cs
                                existing_stock.original_kg += old_kg
                                
                                existing_stock.save()
                                
                                print(f"  New Stock: Slab={existing_stock.available_slab}, CS={existing_stock.available_c_s}, KG={existing_stock.available_kg}")
                                print(f"  ✓ Tenant stock restored successfully")
                            else:
                                # Create new stock entry with positive values
                                old_slab = old_item.slab_quantity or Decimal(0)
                                old_cs = old_item.c_s_quantity or Decimal(0)
                                old_kg = old_item.kg or Decimal(0)
                                
                                new_stock_data = {
                                    **stock_filters,
                                    'available_slab': old_slab,
                                    'available_c_s': old_cs,
                                    'available_kg': old_kg,
                                    'original_slab': old_slab,
                                    'original_c_s': old_cs,
                                    'original_kg': old_kg,
                                }
                                
                                TenantStock.objects.create(**new_stock_data)
                                print(f"\n✓ Tenant stock CREATED for {old_item.item.name} (Tenant: {old_tenant}):")
                                print(f"  Slab={old_slab}, CS={old_cs}, KG={old_kg}")
                                
                        except Exception as e:
                            print(f"Error restoring old tenant stock: {e}")
                            import traceback
                            traceback.print_exc()
                            messages.warning(request, f"Error restoring tenant stock for {old_item.item.name}: {str(e)}")

                    # STEP 2: Validate new data for stock availability
                    print(f"\n=== STEP 2: VALIDATING NEW DATA ===")
                    errors = []
                    
                    for f in formset:
                        if f.cleaned_data and not f.cleaned_data.get("DELETE", False):
                            slab = f.cleaned_data.get("slab_quantity") or Decimal(0)
                            cs = f.cleaned_data.get("c_s_quantity") or Decimal(0)
                            kg = f.cleaned_data.get("kg") or Decimal(0)
                            
                            stock_filters = {
                                'tenant_company_name': new_tenant,
                                'item': f.cleaned_data.get('item'),
                                'brand': f.cleaned_data.get('brand'),
                                'freezing_category': f.cleaned_data.get('freezing_category'),
                                'unit': f.cleaned_data.get('unit'),
                                'glaze': f.cleaned_data.get('glaze'),
                                'species': f.cleaned_data.get('species'),
                                'grade': f.cleaned_data.get('grade'),
                                'processing_center': f.cleaned_data.get('processing_center'),
                                'store': f.cleaned_data.get('store'),
                                'item_quality': f.cleaned_data.get('item_quality'),
                                'peeling_type': f.cleaned_data.get('peeling_type'),
                            }
                            stock_filters = {k: v for k, v in stock_filters.items() if v is not None}
                            
                            try:
                                existing_stock = TenantStock.objects.filter(**stock_filters).first()
                                
                                if existing_stock:
                                    if (existing_stock.available_slab < slab or 
                                        existing_stock.available_c_s < cs or 
                                        existing_stock.available_kg < kg):
                                        item_name = f.cleaned_data.get('item')
                                        species_name = f.cleaned_data.get('species')
                                        grade_name = f.cleaned_data.get('grade')
                                        errors.append(
                                            f"Insufficient stock for {item_name} - {species_name} - {grade_name}. "
                                            f"Available: {existing_stock.available_kg} KG, Requested: {kg} KG"
                                        )
                            except Exception as e:
                                print(f"Error validating stock: {e}")
                    
                    if errors:
                        for error in errors:
                            messages.error(request, error)
                        # Re-render form with errors
                        form = ReturnTenantForm(request.POST, instance=return_entry)
                        formset = ReturnTenantItemFormSet(request.POST, instance=return_entry)
                        return render(request, 'adminapp/ReturnTenant/update.html', {
                            'form': form,
                            'formset': formset,
                            'entry': return_entry
                        })

                    # STEP 3: Process new data and calculate totals
                    print(f"\n=== STEP 3: PROCESSING NEW DATA ===")
                    total_kg = Decimal(0)
                    total_slab = Decimal(0)
                    total_c_s = Decimal(0)
                    
                    stock_updates = []

                    # Process formset
                    for f in formset:
                        if f.cleaned_data and not f.cleaned_data.get("DELETE", False):
                            slab = f.cleaned_data.get("slab_quantity") or Decimal(0)
                            cs = f.cleaned_data.get("c_s_quantity") or Decimal(0)
                            kg = f.cleaned_data.get("kg") or Decimal(0)

                            # Extract data for stock
                            stock_data = {
                                'processing_center': f.cleaned_data.get('processing_center'),
                                'store': f.cleaned_data.get('store'),
                                'item': f.cleaned_data.get('item'),
                                'item_quality': f.cleaned_data.get('item_quality'),
                                'unit': f.cleaned_data.get('unit'),
                                'glaze': f.cleaned_data.get('glaze'),
                                'brand': f.cleaned_data.get('brand'),
                                'species': f.cleaned_data.get('species'),
                                'grade': f.cleaned_data.get('grade'),
                                'peeling_type': f.cleaned_data.get('peeling_type'),
                                'freezing_category': f.cleaned_data.get('freezing_category'),
                                'slab': slab,
                                'cs': cs,
                                'kg': kg,
                            }

                            if stock_data['item'] and stock_data['brand']:
                                stock_updates.append(stock_data)
                                print(f"\nItem to return: {stock_data['item'].name}")
                                print(f"  Slab={slab}, CS={cs}, KG={kg}")

                            # Calculate totals
                            total_slab += slab
                            total_c_s += cs
                            total_kg += kg

                    # Assign totals
                    entry = form.save(commit=False)
                    entry.total_slab = total_slab
                    entry.total_c_s = total_c_s
                    entry.total_kg = total_kg
                    entry.total_amount = Decimal(0)

                    entry.save()
                    formset.instance = entry
                    formset.save()

                    # STEP 4: SUBTRACT new stock quantities (process the return)
                    print(f"\n=== STEP 4: SUBTRACTING NEW TENANT STOCK QUANTITIES ===")
                    for stock_data in stock_updates:
                        try:
                            # Build stock filters (use NEW tenant from entry)
                            stock_filters = {
                                'tenant_company_name': entry.tenant_company_name,
                                'item': stock_data['item'],
                                'brand': stock_data['brand'],
                                'freezing_category': stock_data['freezing_category'],
                                'unit': stock_data['unit'],
                                'glaze': stock_data['glaze'],
                                'species': stock_data['species'],
                                'grade': stock_data['grade'],
                                'processing_center': stock_data['processing_center'],
                                'store': stock_data['store'],
                                'item_quality': stock_data['item_quality'],
                                'peeling_type': stock_data['peeling_type'],
                            }
                            # Remove None values
                            stock_filters = {k: v for k, v in stock_filters.items() if v is not None}

                            # Find existing tenant stock with row-level lock
                            existing_stock = TenantStock.objects.select_for_update().filter(**stock_filters).first()
                            
                            if existing_stock:
                                print(f"\nSubtracting from {stock_data['item'].name} (Tenant: {entry.tenant_company_name}):")
                                print(f"  Current Stock: Slab={existing_stock.available_slab}, CS={existing_stock.available_c_s}, KG={existing_stock.available_kg}")
                                print(f"  Subtracting: Slab={stock_data['slab']}, CS={stock_data['cs']}, KG={stock_data['kg']}")
                                
                                # Subtract returned quantities
                                existing_stock.available_slab -= stock_data['slab']
                                existing_stock.available_c_s -= stock_data['cs']
                                existing_stock.available_kg -= stock_data['kg']
                                
                                existing_stock.original_slab -= stock_data['slab']
                                existing_stock.original_c_s -= stock_data['cs']
                                existing_stock.original_kg -= stock_data['kg']
                                
                                print(f"  New Stock: Slab={existing_stock.available_slab}, CS={existing_stock.available_c_s}, KG={existing_stock.available_kg}")
                                
                                # Delete if all are zero or negative
                                if (existing_stock.available_slab <= 0 and 
                                    existing_stock.available_c_s <= 0 and 
                                    existing_stock.available_kg <= 0):
                                    print(f"  Stock depleted to zero/negative, deleting entry")
                                    existing_stock.delete()
                                else:
                                    existing_stock.save()
                                    if (existing_stock.available_slab < 0 or 
                                        existing_stock.available_c_s < 0 or 
                                        existing_stock.available_kg < 0):
                                        print(f"  ⚠ WARNING: Tenant stock is now NEGATIVE!")
                                        messages.warning(
                                            request,
                                            f"Warning: {stock_data['item'].name} tenant stock is negative "
                                            f"(Slab: {existing_stock.available_slab}, CS: {existing_stock.available_c_s}, KG: {existing_stock.available_kg})"
                                        )
                                    else:
                                        print(f"  ✓ Tenant stock updated successfully")
                                
                            else:
                                # Create new tenant stock entry with negative values
                                new_stock_data = {
                                    **stock_filters,
                                    'available_slab': -stock_data['slab'],
                                    'available_c_s': -stock_data['cs'],
                                    'available_kg': -stock_data['kg'],
                                    'original_slab': -stock_data['slab'],
                                    'original_c_s': -stock_data['cs'],
                                    'original_kg': -stock_data['kg'],
                                }
                                
                                stock = TenantStock.objects.create(**new_stock_data)
                                print(f"\n⚠️ Tenant stock CREATED with NEGATIVE values for {stock_data['item'].name} (Tenant: {entry.tenant_company_name}):")
                                print(f"  Slab={stock.available_slab}, CS={stock.available_c_s}, KG={stock.available_kg}")
                                messages.warning(
                                    request,
                                    f"⚠️ No existing stock found for {stock_data['item'].name}. "
                                    f"Created with negative balance: {stock_data['kg']} KG"
                                )

                        except Exception as e:
                            print(f"\n✗ Error updating tenant stock for {stock_data['item'].name}: {e}")
                            import traceback
                            traceback.print_exc()
                            messages.warning(request, f"Error updating tenant stock for {stock_data['item'].name}: {str(e)}")

                    print(f"\n=== UPDATE COMPLETE ===")
                    
                    if tenant_changed:
                        messages.success(
                            request, 
                            f'Return entry updated successfully! Tenant changed from {old_tenant} to {entry.tenant_company_name}. Stock synchronized for both tenants.'
                        )
                    else:
                        messages.success(request, 'Return entry updated successfully and tenant stock synchronized!')
                        
                    return redirect(reverse('adminapp:list_return_tenant'))
                    
            except ValueError as e:
                # Validation error
                print(f"\n✗ Validation Error: {e}")
                messages.error(request, str(e))
            except Exception as e:
                # Other errors
                print(f"\n✗ Transaction failed: {e}")
                import traceback
                traceback.print_exc()
                messages.error(request, f'Error updating return entry: {str(e)}')
        else:
            print("Form Errors:", form.errors)
            print("Formset Errors:", formset.errors)
            messages.error(request, 'Please correct the errors below.')

    else:
        form = ReturnTenantForm(instance=return_entry)
        formset = ReturnTenantItemFormSet(instance=return_entry)

    return render(
        request,
        'adminapp/ReturnTenant/update.html',
        {'form': form, 'formset': formset, 'entry': return_entry}
    )

@transaction.atomic
@check_permission('freezing_delete')
def return_tenant_delete(request, pk):
    entry = get_object_or_404(ReturnTenant, pk=pk)
    
    if request.method == "POST":
        try:
            print(f"\n=== DELETING RETURN TENANT ENTRY ===")
            print(f"Entry: {entry.voucher_number} - Tenant: {entry.tenant_company_name}")
            
            # Get all items before deletion
            items = list(entry.items.all())
            
            # STEP 1: Restore quantities to tenant stock (reverse the return)
            print(f"\n=== RESTORING QUANTITIES TO TENANT STOCK ===")
            for item in items:
                try:
                    # Build stock filters
                    stock_filters = {
                        'tenant_company_name': entry.tenant_company_name,
                        'item': item.item,
                        'brand': item.brand,
                        'freezing_category': item.freezing_category,
                        'unit': item.unit,
                        'glaze': item.glaze,
                        'species': item.species,
                        'grade': item.grade,
                        'processing_center': item.processing_center,
                        'store': item.store,
                        'item_quality': item.item_quality,
                        'peeling_type': item.peeling_type,
                    }
                    # Remove None values
                    stock_filters = {k: v for k, v in stock_filters.items() if v is not None}
                    
                    # Find matching tenant stock with row-level lock
                    existing_stock = TenantStock.objects.select_for_update().filter(**stock_filters).first()
                    
                    if existing_stock:
                        item_slab = item.slab_quantity or Decimal(0)
                        item_cs = item.c_s_quantity or Decimal(0)
                        item_kg = item.kg or Decimal(0)
                        
                        print(f"\nRestoring to {item.item.name}:")
                        print(f"  Current Available: Slab={existing_stock.available_slab}, CS={existing_stock.available_c_s}, KG={existing_stock.available_kg}")
                        print(f"  Current Original: Slab={existing_stock.original_slab}, CS={existing_stock.original_c_s}, KG={existing_stock.original_kg}")
                        print(f"  Restoring (Adding): Slab={item_slab}, CS={item_cs}, KG={item_kg}")
                        
                        # ✅ ONLY restore to AVAILABLE quantities (not original)
                        existing_stock.available_slab += item_slab
                        existing_stock.available_c_s += item_cs
                        existing_stock.available_kg += item_kg
                        
                        # ❌ DO NOT modify original quantities
                        # original_kg stays unchanged - it represents the original frozen amount
                        
                        existing_stock.save()
                        
                        print(f"  New Available: Slab={existing_stock.available_slab}, CS={existing_stock.available_c_s}, KG={existing_stock.available_kg}")
                        print(f"  Original (unchanged): Slab={existing_stock.original_slab}, CS={existing_stock.original_c_s}, KG={existing_stock.original_kg}")
                        print(f"  ✓ Tenant stock restored successfully")
                    else:
                        # ⚠️ This shouldn't happen when deleting a return
                        # Returns should only modify existing stock, not create new entries
                        print(f"⚠️ WARNING: No existing stock found for {item.item.name}")
                        messages.warning(
                            request, 
                            f"No existing stock found for {item.item.name}. "
                            f"Cannot restore return quantities."
                        )
                        
                except Exception as e:
                    print(f"Error restoring tenant stock for {item.item.name}: {e}")
                    import traceback
                    traceback.print_exc()
                    messages.warning(request, f"Error restoring tenant stock for {item.item.name}: {str(e)}")
            
            # STEP 2: Delete the entry (cascade will delete items)
            print(f"\n=== DELETING RETURN ENTRY ===")
            entry.delete()
            print(f"✓ Entry deleted successfully")
            
            messages.success(request, f'Return entry {entry.voucher_number} deleted successfully and tenant stock restored!')
            return redirect('adminapp:list_return_tenant')
            
        except Exception as e:
            print(f"\n✗ Deletion failed: {e}")
            import traceback
            traceback.print_exc()
            messages.error(request, f'Error deleting return entry: {str(e)}')
            return redirect('adminapp:list_return_tenant')
    
    return render(request, 'adminapp/ReturnTenant/confirm_delete.html', {'entry': entry})

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


@transaction.atomic
def create_tenant_bill(tenant, from_date, to_date):
    """
    Create a TenantBill using ONLY TenantStock data with proper amount tracking.
    
    IMPORTANT: This uses original_kg from TenantStock.
    If original_kg is 0, it will use available_kg as fallback.
    """
    
    # Avoid duplicates for exact period
    existing = TenantBill.objects.filter(
        tenant=tenant, from_date=from_date, to_date=to_date
    ).first()
    if existing:
        logger.info(f"Bill already exists for {tenant} {from_date} to {to_date}")
        return existing

    # ✅ Get data ONLY from TenantStock
    tenant_stocks = TenantStock.objects.filter(
        tenant_company_name=tenant,
    ).select_related(
        'item', 'brand', 'unit', 'glaze', 'species', 
        'grade', 'freezing_category', 'processing_center', 
        'store', 'item_quality', 'peeling_type'
    )

    if not tenant_stocks.exists():
        logger.info(f"No tenant stock found for {tenant}")
        return None

    bill = TenantBill.objects.create(
        tenant=tenant,
        from_date=from_date,
        to_date=to_date,
    )

    totals = {"amount": Decimal("0.00"), "slabs": 0, "cs": 0, "kg": Decimal("0.00")}
    items_created = 0
    items_skipped = 0

    # ✅ Process each TenantStock entry
    for stock in tenant_stocks:
        # ✅ Use ORIGINAL_KG, fallback to AVAILABLE_KG if original is 0
        if stock.original_kg > 0:
            billing_kg = stock.original_kg
            billing_slab = stock.original_slab
            billing_cs = stock.original_c_s
            logger.info(f"Using ORIGINAL quantities for {stock.item.name}: {billing_kg} KG")
        elif stock.available_kg > 0:
            # Fallback: Use available if original not set
            billing_kg = stock.available_kg
            billing_slab = stock.available_slab
            billing_cs = stock.available_c_s
            logger.warning(
                f"ORIGINAL_KG is 0 for {stock.item.name}, "
                f"using AVAILABLE_KG as fallback: {billing_kg} KG"
            )
        else:
            # Skip items with no stock
            logger.info(f"Skipping {stock.item.name} - no stock available")
            items_skipped += 1
            continue

        # Get tariff for this freezing category
        try:
            tariff_obj = TenantFreezingTariff.objects.get(
                tenant=tenant, 
                category=stock.freezing_category
            )
            tariff = Decimal(str(tariff_obj.tariff))
        except TenantFreezingTariff.DoesNotExist:
            logger.warning(
                f"No tariff for {tenant} - {stock.freezing_category}; using 0.00"
            )
            tariff = Decimal("0.00")

        # ✅ Calculate line total: tariff * kg (no days multiplier)
        line_total = (tariff * billing_kg).quantize(
            Decimal('0.01'), rounding=ROUND_HALF_UP
        )
        
        logger.info(
            f"Billing {stock.item.name}: "
            f"KG={billing_kg}, Tariff={tariff}, Total={line_total}"
        )

        # Find matching FreezingEntryTenant for this tenant and stock
        freezing_entry = FreezingEntryTenant.objects.filter(
            tenant_company_name=tenant,
            freezing_status="complete",
            freezing_date__lte=to_date  # Only entries up to billing period
        ).order_by('-freezing_date').first()
        
        if not freezing_entry:
            logger.error(f"No FreezingEntryTenant found for {tenant}, cannot create bill item")
            continue
        
        # Find matching FreezingEntryTenantItem
        freezing_item = FreezingEntryTenantItem.objects.filter(
            freezing_entry=freezing_entry,
            item=stock.item,
            brand=stock.brand,
            freezing_category=stock.freezing_category,
            grade=stock.grade
        ).first()
        
        # If no exact match, use any item from this entry with same item
        if not freezing_item:
            freezing_item = FreezingEntryTenantItem.objects.filter(
                freezing_entry=freezing_entry,
                item=stock.item
            ).first()
        
        if not freezing_item:
            logger.error(f"No FreezingEntryTenantItem found, skipping {stock.item.name}")
            items_skipped += 1
            continue

        # Create bill item with TenantStock quantities
        TenantBillItem.objects.create(
            bill=bill,
            freezing_entry=freezing_entry,
            freezing_entry_item=freezing_item,
            slab_quantity=billing_slab,  # ✅ From TenantStock
            c_s_quantity=billing_cs,     # ✅ From TenantStock
            kg_quantity=billing_kg,      # ✅ From TenantStock
            days_stored=0,               # ✅ Not used in calculation
            tariff_per_day=tariff,
            line_total=line_total,
        )

        totals["amount"] += line_total
        totals["slabs"] += billing_slab or 0
        totals["cs"] += billing_cs or 0
        totals["kg"] += billing_kg
        items_created += 1

    # Update totals on bill
    bill.total_amount = totals["amount"]
    bill.total_slabs = totals["slabs"]
    bill.total_c_s = totals["cs"]
    bill.total_kg = totals["kg"]
    bill.save()

    logger.info(
        f"Created bill {bill.pk} for {tenant}: "
        f"{items_created} items billed, {items_skipped} items skipped, "
        f"Total: ₹{totals['amount']}"
    )
    
    return bill



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
                messages.success(
                    request, 
                    f"Bill {getattr(bill, 'bill_number', bill.id)} created successfully. "
                    f"Total Amount: ₹{bill.total_amount}, Total KG: {bill.total_kg}"
                )
                return redirect('adminapp:view_bill', bill_id=bill.id)
            else:
                messages.warning(request, "No tenant stock found for billing.")
    else:
        tenant_id = request.GET.get("tenant_id")
        initial = {}
        if tenant_id:
            from adminapp.models import TenantBill
            try:
                last_bill = TenantBill.objects.filter(
                    tenant_id=tenant_id
                ).order_by('-to_date').first()
                
                if last_bill:
                    initial['from_date'] = last_bill.to_date + timedelta(days=1)
                    initial['tenant'] = tenant_id
            except TenantBill.DoesNotExist:
                pass

        form = BillGenerationForm(initial=initial)

    return render(request, 'adminapp/billing/generate_manual_bill.html', {'form': form})


def populate_original_quantities():
    """
    One-time script to populate original_kg from available_kg
    Run this in Django shell: python manage.py shell
    >>> from adminapp.views import populate_original_quantities
    >>> populate_original_quantities()
    """
    from adminapp.models import TenantStock
    
    updated = 0
    for stock in TenantStock.objects.all():
        if stock.original_kg == 0 and stock.available_kg > 0:
            stock.original_kg = stock.available_kg
            stock.original_slab = stock.available_slab
            stock.original_c_s = stock.available_c_s
            stock.save()
            updated += 1
            print(f"Updated {stock.item.name}: original_kg = {stock.original_kg}")
    
    print(f"\nTotal updated: {updated} records")
    return updated






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
                            brand = item_form.cleaned_data.get('brand')
                            cs_quantity = item_form.cleaned_data.get('cs_quantity', 0) or 0
                            kg_quantity = item_form.cleaned_data.get('kg_quantity', 0) or 0
                            
                            print(f"Processing item form {i}: Item={item}, CS={cs_quantity}, KG={kg_quantity}")
                            
                            if item and brand and (cs_quantity > 0 or kg_quantity > 0):
                                # Create transfer item manually since this isn't an inline formset
                                transfer_item = StoreTransferItem(
                                    transfer=transfer,
                                    item=item,
                                    brand=brand,
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
                                
                                # Process stock transfer using tracking system
                                process_stock_transfer(transfer, transfer_item, request.user)
                            else:
                                print(f"Skipping item form {i}: no item/brand or no quantity")
                    
                    if items_saved > 0:
                        messages.success(request, f"Transfer created successfully with {items_saved} items!")
                        return redirect('adminapp:store_transfer_list')
                    else:
                        transfer.delete()
                        messages.error(request, "No valid items were added to the transfer.")
                        
            except Exception as e:
                print(f"Error creating transfer: {str(e)}")
                import traceback
                traceback.print_exc()
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

def process_stock_transfer(transfer, transfer_item, user):
    """
    Process stock transfer between stores using tracking system
    - Deduct from source store (transfer_out)
    - Add to destination store (transfer_in)
    """
    print(f"\n=== PROCESSING STOCK TRANSFER ===")
    print(f"From: {transfer.from_store.name} → To: {transfer.to_store.name}")
    print(f"Item: {transfer_item.item.name}")
    print(f"Quantities: CS={transfer_item.cs_quantity}, KG={transfer_item.kg_quantity}")
    
    # STEP 1: TRANSFER OUT from source store
    print(f"\n--- Step 1: Transferring OUT from {transfer.from_store.name} ---")
    try:
        # Get peeling_type if it exists on the model
        peeling_type = getattr(transfer_item, 'peeling_type', None)
        
        update_stock_with_tracking(
            store=transfer.from_store,
            item=transfer_item.item,
            brand=transfer_item.brand,
            cs_change=-transfer_item.cs_quantity,  # Negative = subtract
            kg_change=-transfer_item.kg_quantity,  # Negative = subtract
            movement_type='transfer_out',
            item_quality=transfer_item.item_quality,
            freezing_category=transfer_item.freezing_category,
            peeling_type=peeling_type,
            unit=transfer_item.unit,
            glaze=transfer_item.glaze,
            species=transfer_item.species,
            item_grade=transfer_item.item_grade,
            voucher_number=transfer.voucher_no,
            movement_date=transfer.date,
            user=user,
            notes=f"Transfer OUT to {transfer.to_store.name} - {transfer.voucher_no}"
        )
        print(f"✓ Stock transferred OUT from {transfer.from_store.name}")
        
    except Exception as e:
        print(f"✗ Error transferring OUT: {e}")
        raise ValueError(f"Error removing stock from {transfer.from_store.name}: {str(e)}")
    
    # STEP 2: TRANSFER IN to destination store
    print(f"\n--- Step 2: Transferring IN to {transfer.to_store.name} ---")
    try:
        # Get peeling_type if it exists on the model
        peeling_type = getattr(transfer_item, 'peeling_type', None)
        
        update_stock_with_tracking(
            store=transfer.to_store,
            item=transfer_item.item,
            brand=transfer_item.brand,
            cs_change=transfer_item.cs_quantity,  # Positive = add
            kg_change=transfer_item.kg_quantity,  # Positive = add
            movement_type='transfer_in',
            item_quality=transfer_item.item_quality,
            freezing_category=transfer_item.freezing_category,
            peeling_type=peeling_type,
            unit=transfer_item.unit,
            glaze=transfer_item.glaze,
            species=transfer_item.species,
            item_grade=transfer_item.item_grade,
            voucher_number=transfer.voucher_no,
            movement_date=transfer.date,
            user=user,
            notes=f"Transfer IN from {transfer.from_store.name} - {transfer.voucher_no}"
        )
        print(f"✓ Stock transferred IN to {transfer.to_store.name}")
        
    except Exception as e:
        print(f"✗ Error transferring IN: {e}")
        raise ValueError(f"Error adding stock to {transfer.to_store.name}: {str(e)}")
    
    print(f"\n✓ Stock transfer completed successfully\n")

def reverse_stock_transfer(transfer, transfer_item, user):
    """
    Reverse stock transfer between stores using tracking system
    - Add back to source store (original from_store)
    - Deduct from destination store (original to_store)
    """
    print(f"\n=== REVERSING STOCK TRANSFER ===")
    print(f"Reversing: {transfer.to_store.name} → {transfer.from_store.name}")
    print(f"Item: {transfer_item.item.name}")
    print(f"Quantities: CS={transfer_item.cs_quantity}, KG={transfer_item.kg_quantity}")
    
    # STEP 1: ADD BACK to source store (reverse the transfer_out)
    print(f"\n--- Step 1: Adding back to {transfer.from_store.name} ---")
    try:
        # Get peeling_type if it exists on the model
        peeling_type = getattr(transfer_item, 'peeling_type', None)
        
        update_stock_with_tracking(
            store=transfer.from_store,
            item=transfer_item.item,
            brand=transfer_item.brand,
            cs_change=transfer_item.cs_quantity,  # Positive = add back
            kg_change=transfer_item.kg_quantity,  # Positive = add back
            movement_type='transfer_in',  # Adding back = transfer_in
            item_quality=transfer_item.item_quality,
            freezing_category=transfer_item.freezing_category,
            peeling_type=peeling_type,
            unit=transfer_item.unit,
            glaze=transfer_item.glaze,
            species=transfer_item.species,
            item_grade=transfer_item.item_grade,
            voucher_number=f"{transfer.voucher_no}-REVERSE",
            movement_date=timezone.now().date(),
            user=user,
            notes=f"REVERSAL: Adding back to {transfer.from_store.name} - {transfer.voucher_no}"
        )
        print(f"✓ Stock added back to {transfer.from_store.name}")
        
    except Exception as e:
        print(f"✗ Error adding back to source: {e}")
        raise ValueError(f"Error returning stock to {transfer.from_store.name}: {str(e)}")
    
    # STEP 2: DEDUCT from destination store (reverse the transfer_in)
    print(f"\n--- Step 2: Removing from {transfer.to_store.name} ---")
    try:
        # Get peeling_type if it exists on the model
        peeling_type = getattr(transfer_item, 'peeling_type', None)
        
        update_stock_with_tracking(
            store=transfer.to_store,
            item=transfer_item.item,
            brand=transfer_item.brand,
            cs_change=-transfer_item.cs_quantity,  # Negative = remove
            kg_change=-transfer_item.kg_quantity,  # Negative = remove
            movement_type='transfer_out',  # Removing = transfer_out
            item_quality=transfer_item.item_quality,
            freezing_category=transfer_item.freezing_category,
            peeling_type=peeling_type,
            unit=transfer_item.unit,
            glaze=transfer_item.glaze,
            species=transfer_item.species,
            item_grade=transfer_item.item_grade,
            voucher_number=f"{transfer.voucher_no}-REVERSE",
            movement_date=timezone.now().date(),
            user=user,
            notes=f"REVERSAL: Removing from {transfer.to_store.name} - {transfer.voucher_no}"
        )
        print(f"✓ Stock removed from {transfer.to_store.name}")
        
    except Exception as e:
        print(f"✗ Error removing from destination: {e}")
        raise ValueError(
            f"Cannot reverse transfer: Error removing stock from {transfer.to_store.name}. "
            f"Stock may have been used or transferred elsewhere. Error: {str(e)}"
        )
    
    print(f"\n✓ Stock transfer reversal completed successfully\n")


@login_required
@check_permission('shipping_view')
def transfer_detail(request, pk):
    """View transfer details"""
    transfer = get_object_or_404(StoreTransfer, pk=pk)
    items = StoreTransferItem.objects.filter(transfer=transfer).select_related(
        'item', 'brand', 'item_quality', 'item_grade', 'freezing_category'
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
    """Delete a store transfer and reverse stock changes"""
    transfer = get_object_or_404(StoreTransfer, pk=pk)
    transfer_no = transfer.voucher_no

    try:
        with transaction.atomic():
            # Get all transfer items BEFORE deleting
            transfer_items = list(transfer.items.all())
            
            # Reverse stock transfer for each item BEFORE deleting
            for transfer_item in transfer_items:
                reverse_stock_transfer(transfer, transfer_item, request.user)
            
            # Now delete the transfer (and its items via CASCADE)
            transfer.delete()

        if request.headers.get("Content-Type") == "application/json":
            return JsonResponse({
                "success": True,
                "message": f'Transfer "{transfer_no}" deleted successfully and stock reversed.'
            })
        else:
            messages.success(request, f'Transfer "{transfer_no}" deleted successfully and stock reversed.')
            return redirect("adminapp:store_transfer_list")

    except Exception as e:
        print(f"Error deleting transfer: {str(e)}")
        import traceback
        traceback.print_exc()
        
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



# STOCK REPORT VIEW

@check_permission('reports_view')
def stock_report(request):
    """Stock report with same grades combined and quantities summed"""
    
    # Import required aggregation functions
    from django.db.models import Max
    
    # Get all master data
    items = Item.objects.all()
    categories = ItemCategory.objects.all()
    stores = Store.objects.all()
    brands = ItemBrand.objects.all()
    processing_centers = ProcessingCenter.objects.all()
    
    # Get optional models
    try:
        units = PackingUnit.objects.all()
    except:
        units = []
    
    try:
        glazes = GlazePercentage.objects.all()
    except:
        glazes = []
        
    try:
        peeling_types = ItemType.objects.all()
    except:
        peeling_types = []
        
    try:
        grades = ItemGrade.objects.all().order_by(
            F('order_code').asc(nulls_last=True),
            'grade'
        )
    except:
        grades = []
        
    try:
        item_qualities = ItemQuality.objects.all()
    except:
        item_qualities = []
        
    try:
        freezing_categories = FreezingCategory.objects.filter(is_active=True)
    except:
        freezing_categories = []
        
    try:
        species_list = Species.objects.all()
    except:
        species_list = []

    # Get filter parameters
    selected_items = request.GET.getlist("items")
    selected_categories = request.GET.getlist("categories")
    selected_stores = request.GET.getlist("stores")
    selected_brands = request.GET.getlist("brands")
    selected_units = request.GET.getlist("units")
    selected_glazes = request.GET.getlist("glazes")
    selected_peeling_types = request.GET.getlist("peeling_types")
    selected_grades = request.GET.getlist("grades")
    selected_item_qualities = request.GET.getlist("item_qualities")
    selected_freezing_categories = request.GET.getlist("freezing_categories")
    selected_species = request.GET.getlist("species")
    
    # Date filters
    date_filter = request.GET.get("date_filter", "")
    start_date = request.GET.get("start_date", "")
    end_date = request.GET.get("end_date", "")
    
    # Calculate date range
    today = timezone.now().date()
    if date_filter == "today":
        start_date = end_date = today
    elif date_filter == "week":
        start_date = today - timedelta(days=today.weekday())
        end_date = today
    elif date_filter == "month":
        start_date = today.replace(day=1)
        end_date = today
    elif date_filter == "quarter":
        quarter_month = ((today.month - 1) // 3) * 3 + 1
        start_date = today.replace(month=quarter_month, day=1)
        end_date = today
    elif date_filter == "year":
        start_date = today.replace(month=1, day=1)
        end_date = today
    elif date_filter == "custom" and start_date and end_date:
        try:
            start_date = datetime.strptime(start_date, "%Y-%m-%d").date()
            end_date = datetime.strptime(end_date, "%Y-%m-%d").date()
        except:
            start_date = None
            end_date = None
    else:
        start_date = None
        end_date = None

    # Build base movement query
    movement_query = StockMovement.objects.select_related(
        'store', 'item', 'item__category', 'brand', 'unit', 'glaze',
        'freezing_category', 'item_quality', 'peeling_type', 'item_grade', 'species'
    )

    # Apply filters to movements
    if selected_items:
        movement_query = movement_query.filter(item__id__in=selected_items)
    if selected_categories:
        movement_query = movement_query.filter(item__category__id__in=selected_categories)
    if selected_stores:
        movement_query = movement_query.filter(store__id__in=selected_stores)
    if selected_brands:
        movement_query = movement_query.filter(brand__id__in=selected_brands)
    if selected_units:
        movement_query = movement_query.filter(unit__id__in=selected_units)
    if selected_glazes:
        movement_query = movement_query.filter(glaze__id__in=selected_glazes)
    if selected_peeling_types:
        movement_query = movement_query.filter(peeling_type__id__in=selected_peeling_types)
    if selected_grades:
        movement_query = movement_query.filter(item_grade__id__in=selected_grades)
    if selected_item_qualities:
        movement_query = movement_query.filter(item_quality__id__in=selected_item_qualities)
    if selected_freezing_categories:
        movement_query = movement_query.filter(freezing_category__id__in=selected_freezing_categories)
    if selected_species:
        movement_query = movement_query.filter(species__id__in=selected_species)

    # Get unique stock combinations - Aggregate to get unique combinations
    stock_combinations = movement_query.values(
        'store', 'item', 'brand', 'item_quality', 'freezing_category',
        'peeling_type', 'unit', 'glaze', 'species', 'item_grade'
    ).annotate(
        store_name=Max('store__name'),
        item_name=Max('item__name'),
        brand_name=Max('brand__name'),
        category_name=Max('item__category__name'),
        unit_code=Max('unit__unit_code'),
        glaze_percentage=Max('glaze__percentage'),
        freezing_category_name=Max('freezing_category__name'),
        item_quality_quality=Max('item_quality__quality'),
        peeling_type_name=Max('peeling_type__name'),
        species_name=Max('species__name'),
        item_grade_grade=Max('item_grade__grade'),
        item_grade_order_code=Max('item_grade__order_code')
    )

    # Build sectioned data structure
    sectioned_data = {}
    
    for combo in stock_combinations:
        # Create section key using item_quality instead of item
        item_quality = combo['item_quality_quality'] or "Unknown"
        unit_code = combo['unit_code'] or "N/A"
        glaze_pct = combo['glaze_percentage'] or "N/A"
        category_name = combo['freezing_category_name'] or "N/A"
        brand_name = combo['brand_name'] or "N/A"
        
        section_key = f"{item_quality}|{unit_code}|{glaze_pct}|{category_name}|{brand_name}"
        
        # Initialize section if not exists
        if section_key not in sectioned_data:
            sectioned_data[section_key] = {
                'item_quality': item_quality,  # Changed from item_name
                'unit_code': unit_code,
                'glaze': glaze_pct,
                'category': category_name,
                'brand': brand_name,
                'store_name': combo['store_name'],
                'items': [],
                'totals': {
                    'opening': Decimal('0'),
                    'freezing': Decimal('0'),
                    'shipment': Decimal('0'),
                    'transfer_in': Decimal('0'),
                    'transfer_out': Decimal('0'),
                    'adjustment_plus': Decimal('0'),
                    'adjustment_minus': Decimal('0'),
                    'total_slab': Decimal('0'),
                    'total_case': Decimal('0'),
                }
            }
        
        # Build grade display
        grade_parts = []
        if combo['species_name']:
            grade_parts.append(combo['species_name'])
        if combo['peeling_type_name']:
            grade_parts.append(combo['peeling_type_name'])
        if combo['item_grade_grade']:
            grade_parts.append(combo['item_grade_grade'])
        grade_display = " / ".join(grade_parts) if grade_parts else "NIL"
        
        # Build filter for this specific grade (NO VOUCHER - combines all entries)
        movement_filters = {
            'store_id': combo['store'],
            'item_id': combo['item'],
            'brand_id': combo['brand'],
        }
        
        # Add optional filters
        if combo['item_quality'] is not None:
            movement_filters['item_quality_id'] = combo['item_quality']
        if combo['freezing_category'] is not None:
            movement_filters['freezing_category_id'] = combo['freezing_category']
        if combo['peeling_type'] is not None:
            movement_filters['peeling_type_id'] = combo['peeling_type']
        if combo['unit'] is not None:
            movement_filters['unit_id'] = combo['unit']
        if combo['glaze'] is not None:
            movement_filters['glaze_id'] = combo['glaze']
        if combo['species'] is not None:
            movement_filters['species_id'] = combo['species']
        if combo['item_grade'] is not None:
            movement_filters['item_grade_id'] = combo['item_grade']
        
        # Filter movements for this grade (combines ALL entries with same grade)
        item_movements = movement_query.filter(**movement_filters)
        
        # Initialize quantities
        opening = Decimal('0')
        freezing = Decimal('0')
        shipment = Decimal('0')
        transfer_in = Decimal('0')
        transfer_out = Decimal('0')
        adjustment_plus = Decimal('0')
        adjustment_minus = Decimal('0')
        total_case = Decimal('0')
        
        # Calculate opening balance (all movements before start_date)
        if start_date:
            opening_movements = item_movements.filter(
                movement_date__lt=start_date
            ).aggregate(
                total_kg=Coalesce(Sum('kg_quantity'), Decimal('0'), output_field=DecimalField())
            )
            opening = opening_movements['total_kg']
            
            # Get movements within date range
            period_movements = item_movements.filter(
                movement_date__gte=start_date,
                movement_date__lte=end_date
            )
        else:
            # If no date filter, opening is 0
            period_movements = item_movements
        
        if start_date and end_date:
            # Freezing entries (SUM of all freezing movements for this grade)
            freezing_data = period_movements.filter(
                movement_type__in=['freezing_spot', 'freezing_local', 'freezing_tenant', 'return_tenant']
            ).aggregate(
                total=Coalesce(Sum('kg_quantity'), Decimal('0'), output_field=DecimalField())
            )
            freezing = freezing_data['total']
            
            # Shipments (SUM of all shipment movements)
            shipment_data = period_movements.filter(
                movement_type='shipment'
            ).aggregate(
                total=Coalesce(Sum('kg_quantity'), Decimal('0'), output_field=DecimalField())
            )
            shipment = abs(shipment_data['total'])
            
            # Transfers IN (SUM)
            transfer_in_data = period_movements.filter(
                movement_type='transfer_in'
            ).aggregate(
                total=Coalesce(Sum('kg_quantity'), Decimal('0'), output_field=DecimalField())
            )
            transfer_in = transfer_in_data['total']
            
            # Transfers OUT (SUM)
            transfer_out_data = period_movements.filter(
                movement_type='transfer_out'
            ).aggregate(
                total=Coalesce(Sum('kg_quantity'), Decimal('0'), output_field=DecimalField())
            )
            transfer_out = abs(transfer_out_data['total'])
            
            # Adjustments Plus (SUM)
            adj_plus_data = period_movements.filter(
                movement_type='adjustment_plus'
            ).aggregate(
                total=Coalesce(Sum('kg_quantity'), Decimal('0'), output_field=DecimalField())
            )
            adjustment_plus = adj_plus_data['total']
            
            # Adjustments Minus (SUM)
            adj_minus_data = period_movements.filter(
                movement_type='adjustment_minus'
            ).aggregate(
                total=Coalesce(Sum('kg_quantity'), Decimal('0'), output_field=DecimalField())
            )
            adjustment_minus = abs(adj_minus_data['total'])
            
            # Calculate cumulative CS (SUM)
            cumulative_cs = item_movements.filter(
                movement_date__lte=end_date
            ).aggregate(
                total=Coalesce(Sum('cs_quantity'), Decimal('0'), output_field=DecimalField())
            )
            total_case = cumulative_cs['total']
            
            # Calculate total slab
            total_slab = (opening + freezing + transfer_in + adjustment_plus) - (shipment + transfer_out + adjustment_minus)
        else:
            # No date filter - show current total stock
            all_movements = item_movements.aggregate(
                total_kg=Coalesce(Sum('kg_quantity'), Decimal('0'), output_field=DecimalField()),
                total_cs=Coalesce(Sum('cs_quantity'), Decimal('0'), output_field=DecimalField())
            )
            total_slab = all_movements['total_kg']
            total_case = all_movements['total_cs']
        
        # Only add rows with non-zero quantities
        if opening != 0 or freezing != 0 or shipment != 0 or transfer_in != 0 or transfer_out != 0 or adjustment_plus != 0 or adjustment_minus != 0 or total_slab != 0:
            item_data = {
                'grade': grade_display,
                'grade_order': combo['item_grade_order_code'] if combo['item_grade_order_code'] else 999999,
                'opening': opening,
                'freezing': freezing,
                'shipment': shipment,
                'transfer_in': transfer_in,
                'transfer_out': transfer_out,
                'adjustment_plus': adjustment_plus,
                'adjustment_minus': adjustment_minus,
                'total_slab': total_slab,
                'total_case': total_case,
            }
            
            sectioned_data[section_key]['items'].append(item_data)
            
            # Add to section totals
            for key in ['opening', 'freezing', 'shipment', 'transfer_in', 'transfer_out', 
                        'adjustment_plus', 'adjustment_minus', 'total_slab', 'total_case']:
                sectioned_data[section_key]['totals'][key] += item_data[key]

    # Remove empty sections
    sectioned_data = {k: v for k, v in sectioned_data.items() if v['items']}

    # Sort items within each section by grade order
    for section in sectioned_data.values():
        section['items'].sort(key=lambda x: (x['grade_order'], x['grade']))

    # Calculate grand totals
    grand_totals = {
        'opening': Decimal('0'),
        'freezing': Decimal('0'),
        'shipment': Decimal('0'),
        'transfer_in': Decimal('0'),
        'transfer_out': Decimal('0'),
        'adjustment_plus': Decimal('0'),
        'adjustment_minus': Decimal('0'),
        'total_slab': Decimal('0'),
        'total_case': Decimal('0'),
        'section_count': len(sectioned_data),
    }
    
    for section in sectioned_data.values():
        for key in grand_totals:
            if key != 'section_count':
                grand_totals[key] += section['totals'][key]

    context = {
        "sectioned_data": sectioned_data,
        "grand_totals": grand_totals,
        "items": items,
        "categories": categories,
        "stores": stores,
        "brands": brands,
        "processing_centers": processing_centers,
        "units": units,
        "glazes": glazes,
        "peeling_types": peeling_types,
        "grades": grades,
        "item_qualities": item_qualities,
        "freezing_categories": freezing_categories,
        "species_list": species_list,
        "selected_items": selected_items,
        "selected_categories": selected_categories,
        "selected_stores": selected_stores,
        "selected_brands": selected_brands,
        "selected_units": selected_units,
        "selected_glazes": selected_glazes,
        "selected_peeling_types": selected_peeling_types,
        "selected_grades": selected_grades,
        "selected_item_qualities": selected_item_qualities,
        "selected_freezing_categories": selected_freezing_categories,
        "selected_species": selected_species,
        "date_filter": date_filter,
        "start_date": start_date.strftime("%Y-%m-%d") if start_date else "",
        "end_date": end_date.strftime("%Y-%m-%d") if end_date else "",
    }
    
    return render(request, "adminapp/report/stock_report.html", context)

@check_permission('reports_export')
def stock_report_print(request):
    """Print view matching the main stock report structure"""
    
    # Import required aggregation functions
    from django.db.models import Max
    
    # Get filter parameters
    selected_items = request.GET.getlist("items")
    selected_categories = request.GET.getlist("categories")
    selected_stores = request.GET.getlist("stores")
    selected_brands = request.GET.getlist("brands")
    selected_units = request.GET.getlist("units")
    selected_glazes = request.GET.getlist("glazes")
    selected_peeling_types = request.GET.getlist("peeling_types")
    selected_grades = request.GET.getlist("grades")
    selected_item_qualities = request.GET.getlist("item_qualities")
    selected_freezing_categories = request.GET.getlist("freezing_categories")
    selected_species = request.GET.getlist("species")
    
    # Date filters
    date_filter = request.GET.get("date_filter", "")
    start_date = request.GET.get("start_date", "")
    end_date = request.GET.get("end_date", "")
    
    # Calculate date range
    today = timezone.now().date()
    if date_filter == "today":
        start_date = end_date = today
    elif date_filter == "week":
        start_date = today - timedelta(days=today.weekday())
        end_date = today
    elif date_filter == "month":
        start_date = today.replace(day=1)
        end_date = today
    elif date_filter == "quarter":
        quarter_month = ((today.month - 1) // 3) * 3 + 1
        start_date = today.replace(month=quarter_month, day=1)
        end_date = today
    elif date_filter == "year":
        start_date = today.replace(month=1, day=1)
        end_date = today
    elif date_filter == "custom" and start_date and end_date:
        try:
            start_date = datetime.strptime(start_date, "%Y-%m-%d").date()
            end_date = datetime.strptime(end_date, "%Y-%m-%d").date()
        except:
            start_date = None
            end_date = None
    else:
        start_date = None
        end_date = None

    # Build base movement query
    movement_query = StockMovement.objects.select_related(
        'store', 'item', 'item__category', 'brand', 'unit', 'glaze',
        'freezing_category', 'item_quality', 'peeling_type', 'item_grade', 'species'
    )

    # Apply filters to movements
    if selected_items:
        movement_query = movement_query.filter(item__id__in=selected_items)
    if selected_categories:
        movement_query = movement_query.filter(item__category__id__in=selected_categories)
    if selected_stores:
        movement_query = movement_query.filter(store__id__in=selected_stores)
    if selected_brands:
        movement_query = movement_query.filter(brand__id__in=selected_brands)
    if selected_units:
        movement_query = movement_query.filter(unit__id__in=selected_units)
    if selected_glazes:
        movement_query = movement_query.filter(glaze__id__in=selected_glazes)
    if selected_peeling_types:
        movement_query = movement_query.filter(peeling_type__id__in=selected_peeling_types)
    if selected_grades:
        movement_query = movement_query.filter(item_grade__id__in=selected_grades)
    if selected_item_qualities:
        movement_query = movement_query.filter(item_quality__id__in=selected_item_qualities)
    if selected_freezing_categories:
        movement_query = movement_query.filter(freezing_category__id__in=selected_freezing_categories)
    if selected_species:
        movement_query = movement_query.filter(species__id__in=selected_species)

    # Get unique stock combinations - Aggregate to get unique combinations
    stock_combinations = movement_query.values(
        'store', 'item', 'brand', 'item_quality', 'freezing_category',
        'peeling_type', 'unit', 'glaze', 'species', 'item_grade'
    ).annotate(
        store_name=Max('store__name'),
        item_name=Max('item__name'),
        brand_name=Max('brand__name'),
        category_name=Max('item__category__name'),
        unit_code=Max('unit__unit_code'),
        glaze_percentage=Max('glaze__percentage'),
        freezing_category_name=Max('freezing_category__name'),
        item_quality_quality=Max('item_quality__quality'),
        peeling_type_name=Max('peeling_type__name'),
        species_name=Max('species__name'),
        item_grade_grade=Max('item_grade__grade'),
        item_grade_order_code=Max('item_grade__order_code')
    )

    # Build sectioned data structure
    sectioned_data = {}
    
    for combo in stock_combinations:
        # Create section key using item_quality
        item_quality = combo['item_quality_quality'] or "Unknown"
        unit_code = combo['unit_code'] or "N/A"
        glaze_pct = combo['glaze_percentage'] or "N/A"
        category_name = combo['freezing_category_name'] or "N/A"
        brand_name = combo['brand_name'] or "N/A"
        
        section_key = f"{item_quality}|{unit_code}|{glaze_pct}|{category_name}|{brand_name}"
        
        # Initialize section if not exists
        if section_key not in sectioned_data:
            sectioned_data[section_key] = {
                'item_quality': item_quality,
                'unit_code': unit_code,
                'glaze': glaze_pct,
                'category': category_name,
                'brand': brand_name,
                'store_name': combo['store_name'],
                'items': [],
                'totals': {
                    'opening': Decimal('0'),
                    'freezing': Decimal('0'),
                    'shipment': Decimal('0'),
                    'transfer_in': Decimal('0'),
                    'transfer_out': Decimal('0'),
                    'adjustment_plus': Decimal('0'),
                    'adjustment_minus': Decimal('0'),
                    'total_slab': Decimal('0'),
                    'total_case': Decimal('0'),
                }
            }
        
        # Build grade display
        grade_parts = []
        if combo['species_name']:
            grade_parts.append(combo['species_name'])
        if combo['peeling_type_name']:
            grade_parts.append(combo['peeling_type_name'])
        if combo['item_grade_grade']:
            grade_parts.append(combo['item_grade_grade'])
        grade_display = " / ".join(grade_parts) if grade_parts else "NIL"
        
        # Build filter for this specific grade
        movement_filters = {
            'store_id': combo['store'],
            'item_id': combo['item'],
            'brand_id': combo['brand'],
        }
        
        # Add optional filters
        if combo['item_quality'] is not None:
            movement_filters['item_quality_id'] = combo['item_quality']
        if combo['freezing_category'] is not None:
            movement_filters['freezing_category_id'] = combo['freezing_category']
        if combo['peeling_type'] is not None:
            movement_filters['peeling_type_id'] = combo['peeling_type']
        if combo['unit'] is not None:
            movement_filters['unit_id'] = combo['unit']
        if combo['glaze'] is not None:
            movement_filters['glaze_id'] = combo['glaze']
        if combo['species'] is not None:
            movement_filters['species_id'] = combo['species']
        if combo['item_grade'] is not None:
            movement_filters['item_grade_id'] = combo['item_grade']
        
        # Filter movements for this grade
        item_movements = movement_query.filter(**movement_filters)
        
        # Initialize quantities
        opening = Decimal('0')
        freezing = Decimal('0')
        shipment = Decimal('0')
        transfer_in = Decimal('0')
        transfer_out = Decimal('0')
        adjustment_plus = Decimal('0')
        adjustment_minus = Decimal('0')
        total_case = Decimal('0')
        
        # Calculate opening balance
        if start_date:
            opening_movements = item_movements.filter(
                movement_date__lt=start_date
            ).aggregate(
                total_kg=Coalesce(Sum('kg_quantity'), Decimal('0'), output_field=DecimalField())
            )
            opening = opening_movements['total_kg']
            
            period_movements = item_movements.filter(
                movement_date__gte=start_date,
                movement_date__lte=end_date
            )
        else:
            period_movements = item_movements
        
        if start_date and end_date:
            # Freezing entries
            freezing_data = period_movements.filter(
                movement_type__in=['freezing_spot', 'freezing_local', 'freezing_tenant', 'return_tenant']
            ).aggregate(
                total=Coalesce(Sum('kg_quantity'), Decimal('0'), output_field=DecimalField())
            )
            freezing = freezing_data['total']
            
            # Shipments
            shipment_data = period_movements.filter(
                movement_type='shipment'
            ).aggregate(
                total=Coalesce(Sum('kg_quantity'), Decimal('0'), output_field=DecimalField())
            )
            shipment = abs(shipment_data['total'])
            
            # Transfers IN
            transfer_in_data = period_movements.filter(
                movement_type='transfer_in'
            ).aggregate(
                total=Coalesce(Sum('kg_quantity'), Decimal('0'), output_field=DecimalField())
            )
            transfer_in = transfer_in_data['total']
            
            # Transfers OUT
            transfer_out_data = period_movements.filter(
                movement_type='transfer_out'
            ).aggregate(
                total=Coalesce(Sum('kg_quantity'), Decimal('0'), output_field=DecimalField())
            )
            transfer_out = abs(transfer_out_data['total'])
            
            # Adjustments Plus
            adj_plus_data = period_movements.filter(
                movement_type='adjustment_plus'
            ).aggregate(
                total=Coalesce(Sum('kg_quantity'), Decimal('0'), output_field=DecimalField())
            )
            adjustment_plus = adj_plus_data['total']
            
            # Adjustments Minus
            adj_minus_data = period_movements.filter(
                movement_type='adjustment_minus'
            ).aggregate(
                total=Coalesce(Sum('kg_quantity'), Decimal('0'), output_field=DecimalField())
            )
            adjustment_minus = abs(adj_minus_data['total'])
            
            # Calculate cumulative CS
            cumulative_cs = item_movements.filter(
                movement_date__lte=end_date
            ).aggregate(
                total=Coalesce(Sum('cs_quantity'), Decimal('0'), output_field=DecimalField())
            )
            total_case = cumulative_cs['total']
            
            # Calculate total slab
            total_slab = (opening + freezing + transfer_in + adjustment_plus) - (shipment + transfer_out + adjustment_minus)
        else:
            # No date filter - show current total stock
            all_movements = item_movements.aggregate(
                total_kg=Coalesce(Sum('kg_quantity'), Decimal('0'), output_field=DecimalField()),
                total_cs=Coalesce(Sum('cs_quantity'), Decimal('0'), output_field=DecimalField())
            )
            total_slab = all_movements['total_kg']
            total_case = all_movements['total_cs']
        
        # Only add rows with non-zero quantities
        if opening != 0 or freezing != 0 or shipment != 0 or transfer_in != 0 or transfer_out != 0 or adjustment_plus != 0 or adjustment_minus != 0 or total_slab != 0:
            item_data = {
                'grade': grade_display,
                'grade_order': combo['item_grade_order_code'] if combo['item_grade_order_code'] else 999999,
                'opening': opening,
                'freezing': freezing,
                'shipment': shipment,
                'transfer_in': transfer_in,
                'transfer_out': transfer_out,
                'adjustment_plus': adjustment_plus,
                'adjustment_minus': adjustment_minus,
                'total_slab': total_slab,
                'total_case': total_case,
            }
            
            sectioned_data[section_key]['items'].append(item_data)
            
            # Add to section totals
            for key in ['opening', 'freezing', 'shipment', 'transfer_in', 'transfer_out', 
                        'adjustment_plus', 'adjustment_minus', 'total_slab', 'total_case']:
                sectioned_data[section_key]['totals'][key] += item_data[key]

    # Remove empty sections
    sectioned_data = {k: v for k, v in sectioned_data.items() if v['items']}

    # Sort items within each section by grade order
    for section in sectioned_data.values():
        section['items'].sort(key=lambda x: (x['grade_order'], x['grade']))

    # Calculate grand totals
    grand_totals = {
        'opening': Decimal('0'),
        'freezing': Decimal('0'),
        'shipment': Decimal('0'),
        'transfer_in': Decimal('0'),
        'transfer_out': Decimal('0'),
        'adjustment_plus': Decimal('0'),
        'adjustment_minus': Decimal('0'),
        'total_slab': Decimal('0'),
        'total_case': Decimal('0'),
        'section_count': len(sectioned_data),
    }
    
    for section in sectioned_data.values():
        for key in grand_totals:
            if key != 'section_count':
                grand_totals[key] += section['totals'][key]

    return render(
        request,
        "adminapp/report/stock_report_print.html",
        {
            "sectioned_data": sectioned_data,
            "grand_totals": grand_totals,
            "date_filter": date_filter,
            "start_date": start_date.strftime("%Y-%m-%d") if start_date else "",
            "end_date": end_date.strftime("%Y-%m-%d") if end_date else "",
        },
    )


# STOCK REPORT with amount - FIXED VERSION
@check_permission('reports_view')
def stock_report_amt(request):
    """Stock report with amount calculations matching stock_report structure"""
    
    from django.db.models import Max
    
    # Get all master data
    items = Item.objects.all()
    categories = ItemCategory.objects.all()
    stores = Store.objects.all()
    brands = ItemBrand.objects.all()
    processing_centers = ProcessingCenter.objects.all()
    
    # Get optional models
    try:
        units = PackingUnit.objects.all()
    except:
        units = []
    
    try:
        glazes = GlazePercentage.objects.all()
    except:
        glazes = []
        
    try:
        peeling_types = ItemType.objects.all()
    except:
        peeling_types = []
        
    try:
        grades = ItemGrade.objects.all().order_by(
            F('order_code').asc(nulls_last=True),
            'grade'
        )
    except:
        grades = []
        
    try:
        item_qualities = ItemQuality.objects.all()
    except:
        item_qualities = []
        
    try:
        freezing_categories = FreezingCategory.objects.filter(is_active=True)
    except:
        freezing_categories = []
        
    try:
        species_list = Species.objects.all()
    except:
        species_list = []

    # Get filter parameters
    selected_items = request.GET.getlist("items")
    selected_categories = request.GET.getlist("categories")
    selected_stores = request.GET.getlist("stores")
    selected_brands = request.GET.getlist("brands")
    selected_units = request.GET.getlist("units")
    selected_glazes = request.GET.getlist("glazes")
    selected_peeling_types = request.GET.getlist("peeling_types")
    selected_grades = request.GET.getlist("grades")
    selected_item_qualities = request.GET.getlist("item_qualities")
    selected_freezing_categories = request.GET.getlist("freezing_categories")
    selected_species = request.GET.getlist("species")
    
    # Date filters
    date_filter = request.GET.get("date_filter", "")
    start_date = request.GET.get("start_date", "")
    end_date = request.GET.get("end_date", "")
    
    # Calculate date range
    today = timezone.now().date()
    if date_filter == "today":
        start_date = end_date = today
    elif date_filter == "week":
        start_date = today - timedelta(days=today.weekday())
        end_date = today
    elif date_filter == "month":
        start_date = today.replace(day=1)
        end_date = today
    elif date_filter == "quarter":
        quarter_month = ((today.month - 1) // 3) * 3 + 1
        start_date = today.replace(month=quarter_month, day=1)
        end_date = today
    elif date_filter == "year":
        start_date = today.replace(month=1, day=1)
        end_date = today
    elif date_filter == "custom" and start_date and end_date:
        try:
            start_date = datetime.strptime(start_date, "%Y-%m-%d").date()
            end_date = datetime.strptime(end_date, "%Y-%m-%d").date()
        except:
            start_date = None
            end_date = None
    else:
        start_date = None
        end_date = None

    # Build base movement query
    movement_query = StockMovement.objects.select_related(
        'store', 'item', 'item__category', 'brand', 'unit', 'glaze',
        'freezing_category', 'item_quality', 'peeling_type', 'item_grade', 'species'
    )

    # Apply filters to movements
    if selected_items:
        movement_query = movement_query.filter(item__id__in=selected_items)
    if selected_categories:
        movement_query = movement_query.filter(item__category__id__in=selected_categories)
    if selected_stores:
        movement_query = movement_query.filter(store__id__in=selected_stores)
    if selected_brands:
        movement_query = movement_query.filter(brand__id__in=selected_brands)
    if selected_units:
        movement_query = movement_query.filter(unit__id__in=selected_units)
    if selected_glazes:
        movement_query = movement_query.filter(glaze__id__in=selected_glazes)
    if selected_peeling_types:
        movement_query = movement_query.filter(peeling_type__id__in=selected_peeling_types)
    if selected_grades:
        movement_query = movement_query.filter(item_grade__id__in=selected_grades)
    if selected_item_qualities:
        movement_query = movement_query.filter(item_quality__id__in=selected_item_qualities)
    if selected_freezing_categories:
        movement_query = movement_query.filter(freezing_category__id__in=selected_freezing_categories)
    if selected_species:
        movement_query = movement_query.filter(species__id__in=selected_species)

    # Get unique stock combinations
    stock_combinations = movement_query.values(
        'store', 'item', 'brand', 'item_quality', 'freezing_category',
        'peeling_type', 'unit', 'glaze', 'species', 'item_grade'
    ).annotate(
        store_name=Max('store__name'),
        item_name=Max('item__name'),
        brand_name=Max('brand__name'),
        category_name=Max('item__category__name'),
        unit_code=Max('unit__unit_code'),
        glaze_percentage=Max('glaze__percentage'),
        freezing_category_name=Max('freezing_category__name'),
        item_quality_quality=Max('item_quality__quality'),
        peeling_type_name=Max('peeling_type__name'),
        species_name=Max('species__name'),
        item_grade_grade=Max('item_grade__grade'),
        item_grade_order_code=Max('item_grade__order_code')
    )

    # Build sectioned data structure
    sectioned_data = {}
    
    for combo in stock_combinations:
        # Create section key
        item_quality = combo['item_quality_quality'] or "Unknown"
        unit_code = combo['unit_code'] or "N/A"
        glaze_pct = combo['glaze_percentage'] or "N/A"
        category_name = combo['freezing_category_name'] or "N/A"
        brand_name = combo['brand_name'] or "N/A"
        
        section_key = f"{item_quality}|{unit_code}|{glaze_pct}|{category_name}|{brand_name}"
        
        # Initialize section if not exists
        if section_key not in sectioned_data:
            sectioned_data[section_key] = {
                'item_quality': item_quality,
                'unit_code': unit_code,
                'glaze': glaze_pct,
                'category': category_name,
                'brand': brand_name,
                'store_name': combo['store_name'],
                'items': [],
                'totals': {
                    'opening': Decimal('0'),
                    'freezing': Decimal('0'),
                    'shipment': Decimal('0'),
                    'transfer_in': Decimal('0'),
                    'transfer_out': Decimal('0'),
                    'adjustment_plus': Decimal('0'),
                    'adjustment_minus': Decimal('0'),
                    'total_slab': Decimal('0'),
                    'total_case': Decimal('0'),
                    'total_usd_amount': Decimal('0'),
                    'total_inr_amount': Decimal('0'),
                }
            }
        
        # Build grade display
        grade_parts = []
        if combo['species_name']:
            grade_parts.append(combo['species_name'])
        if combo['peeling_type_name']:
            grade_parts.append(combo['peeling_type_name'])
        if combo['item_grade_grade']:
            grade_parts.append(combo['item_grade_grade'])
        grade_display = " / ".join(grade_parts) if grade_parts else "NIL"
        
        # Build filter for this specific grade
        movement_filters = {
            'store_id': combo['store'],
            'item_id': combo['item'],
            'brand_id': combo['brand'],
        }
        
        # Add optional filters
        if combo['item_quality'] is not None:
            movement_filters['item_quality_id'] = combo['item_quality']
        if combo['freezing_category'] is not None:
            movement_filters['freezing_category_id'] = combo['freezing_category']
        if combo['peeling_type'] is not None:
            movement_filters['peeling_type_id'] = combo['peeling_type']
        if combo['unit'] is not None:
            movement_filters['unit_id'] = combo['unit']
        if combo['glaze'] is not None:
            movement_filters['glaze_id'] = combo['glaze']
        if combo['species'] is not None:
            movement_filters['species_id'] = combo['species']
        if combo['item_grade'] is not None:
            movement_filters['item_grade_id'] = combo['item_grade']
        
        # Filter movements for this grade
        item_movements = movement_query.filter(**movement_filters)
        
        # Initialize quantities
        opening = Decimal('0')
        freezing = Decimal('0')
        shipment = Decimal('0')
        transfer_in = Decimal('0')
        transfer_out = Decimal('0')
        adjustment_plus = Decimal('0')
        adjustment_minus = Decimal('0')
        total_case = Decimal('0')
        
        # Calculate opening balance
        if start_date:
            opening_movements = item_movements.filter(
                movement_date__lt=start_date
            ).aggregate(
                total_kg=Coalesce(Sum('kg_quantity'), Decimal('0'), output_field=DecimalField())
            )
            opening = opening_movements['total_kg']
            
            period_movements = item_movements.filter(
                movement_date__gte=start_date,
                movement_date__lte=end_date
            )
        else:
            period_movements = item_movements
        
        if start_date and end_date:
            # Freezing entries
            freezing_data = period_movements.filter(
                movement_type__in=['freezing_spot', 'freezing_local', 'freezing_tenant', 'return_tenant']
            ).aggregate(
                total=Coalesce(Sum('kg_quantity'), Decimal('0'), output_field=DecimalField())
            )
            freezing = freezing_data['total']
            
            # Shipments
            shipment_data = period_movements.filter(
                movement_type='shipment'
            ).aggregate(
                total=Coalesce(Sum('kg_quantity'), Decimal('0'), output_field=DecimalField())
            )
            shipment = abs(shipment_data['total'])
            
            # Transfers IN
            transfer_in_data = period_movements.filter(
                movement_type='transfer_in'
            ).aggregate(
                total=Coalesce(Sum('kg_quantity'), Decimal('0'), output_field=DecimalField())
            )
            transfer_in = transfer_in_data['total']
            
            # Transfers OUT
            transfer_out_data = period_movements.filter(
                movement_type='transfer_out'
            ).aggregate(
                total=Coalesce(Sum('kg_quantity'), Decimal('0'), output_field=DecimalField())
            )
            transfer_out = abs(transfer_out_data['total'])
            
            # Adjustments Plus
            adj_plus_data = period_movements.filter(
                movement_type='adjustment_plus'
            ).aggregate(
                total=Coalesce(Sum('kg_quantity'), Decimal('0'), output_field=DecimalField())
            )
            adjustment_plus = adj_plus_data['total']
            
            # Adjustments Minus
            adj_minus_data = period_movements.filter(
                movement_type='adjustment_minus'
            ).aggregate(
                total=Coalesce(Sum('kg_quantity'), Decimal('0'), output_field=DecimalField())
            )
            adjustment_minus = abs(adj_minus_data['total'])
            
            # Calculate cumulative CS
            cumulative_cs = item_movements.filter(
                movement_date__lte=end_date
            ).aggregate(
                total=Coalesce(Sum('cs_quantity'), Decimal('0'), output_field=DecimalField())
            )
            total_case = cumulative_cs['total']
            
            # Calculate total slab
            total_slab = (opening + freezing + transfer_in + adjustment_plus) - (shipment + transfer_out + adjustment_minus)
        else:
            # No date filter - show current total stock
            all_movements = item_movements.aggregate(
                total_kg=Coalesce(Sum('kg_quantity'), Decimal('0'), output_field=DecimalField()),
                total_cs=Coalesce(Sum('cs_quantity'), Decimal('0'), output_field=DecimalField())
            )
            total_slab = all_movements['total_kg']
            total_case = all_movements['total_cs']
        
        # Calculate USD and INR amounts for current stock
        # Get the latest rate for this combination
        latest_movement = item_movements.order_by('-movement_date', '-id').first()
        usd_rate_per_kg = Decimal('0')
        inr_rate_per_kg = Decimal('0')
        
        if latest_movement:
            usd_rate_per_kg = latest_movement.usd_rate_per_kg or Decimal('0')
            # For INR, calculate from usd_rate_item_to_inr divided by kg
            if latest_movement.usd_rate_item_to_inr and latest_movement.kg_quantity:
                inr_rate_per_kg = latest_movement.usd_rate_item_to_inr / latest_movement.kg_quantity
        
        usd_amount = total_slab * usd_rate_per_kg
        inr_amount = total_slab * inr_rate_per_kg
        
        # Only add rows with non-zero quantities
        if opening != 0 or freezing != 0 or shipment != 0 or transfer_in != 0 or transfer_out != 0 or adjustment_plus != 0 or adjustment_minus != 0 or total_slab != 0:
            item_data = {
                'grade': grade_display,
                'grade_order': combo['item_grade_order_code'] if combo['item_grade_order_code'] else 999999,
                'opening': opening,
                'freezing': freezing,
                'shipment': shipment,
                'transfer_in': transfer_in,
                'transfer_out': transfer_out,
                'adjustment_plus': adjustment_plus,
                'adjustment_minus': adjustment_minus,
                'total_slab': total_slab,
                'total_case': total_case,
                'usd_rate_per_kg': usd_rate_per_kg,
                'inr_rate_per_kg': inr_rate_per_kg,
                'usd_amount': usd_amount,
                'inr_amount': inr_amount,
                # Add section-level info for template access
                'item__name': combo['item_name'],
                'item__category__name': combo['category_name'],
                'store__name': combo['store_name'],
                'brand__name': combo['brand_name'],
                'unit__unit_code': combo['unit_code'],
                'unit__description': combo['unit_code'],  # Using unit_code as description
                'glaze__percentage': combo['glaze_percentage'],
                'freezing_category__name': combo['freezing_category_name'],
                'item_quality__quality': combo['item_quality_quality'],
                'species__name': combo['species_name'],
                'peeling_type__name': combo['peeling_type_name'],
                'item_grade__grade': combo['item_grade_grade'],
            }
            
            sectioned_data[section_key]['items'].append(item_data)
            
            # Add to section totals
            for key in ['opening', 'freezing', 'shipment', 'transfer_in', 'transfer_out', 
                        'adjustment_plus', 'adjustment_minus', 'total_slab', 'total_case']:
                sectioned_data[section_key]['totals'][key] += item_data[key]
            
            sectioned_data[section_key]['totals']['total_usd_amount'] += usd_amount
            sectioned_data[section_key]['totals']['total_inr_amount'] += inr_amount

    # Remove empty sections
    sectioned_data = {k: v for k, v in sectioned_data.items() if v['items']}

    # Sort items within each section by grade order
    for section in sectioned_data.values():
        section['items'].sort(key=lambda x: (x['grade_order'], x['grade']))

    # Calculate grand totals
    grand_totals = {
        'opening': Decimal('0'),
        'freezing': Decimal('0'),
        'shipment': Decimal('0'),
        'transfer_in': Decimal('0'),
        'transfer_out': Decimal('0'),
        'adjustment_plus': Decimal('0'),
        'adjustment_minus': Decimal('0'),
        'total_slab': Decimal('0'),
        'total_case': Decimal('0'),
        'total_usd_amount': Decimal('0'),
        'total_inr_amount': Decimal('0'),
        'section_count': len(sectioned_data),
    }
    
    for section in sectioned_data.values():
        for key in grand_totals:
            if key != 'section_count':
                grand_totals[key] += section['totals'][key]

    context = {
        "sectioned_data": sectioned_data,
        "grand_totals": grand_totals,
        "items": items,
        "categories": categories,
        "stores": stores,
        "brands": brands,
        "processing_centers": processing_centers,
        "units": units,
        "glazes": glazes,
        "peeling_types": peeling_types,
        "grades": grades,
        "item_qualities": item_qualities,
        "freezing_categories": freezing_categories,
        "species_list": species_list,
        "selected_items": selected_items,
        "selected_categories": selected_categories,
        "selected_stores": selected_stores,
        "selected_brands": selected_brands,
        "selected_units": selected_units,
        "selected_glazes": selected_glazes,
        "selected_peeling_types": selected_peeling_types,
        "selected_grades": selected_grades,
        "selected_item_qualities": selected_item_qualities,
        "selected_freezing_categories": selected_freezing_categories,
        "selected_species": selected_species,
        "date_filter": date_filter,
        "start_date": start_date.strftime("%Y-%m-%d") if start_date else "",
        "end_date": end_date.strftime("%Y-%m-%d") if end_date else "",
    }
    
    return render(request, "adminapp/report/stock_report_amt.html", context)

@check_permission('reports_export')
def stock_report_print_amt(request):
    """Print view for stock report with amounts"""
    
    from django.db.models import Max
    
    # Get filter parameters (same as main view)
    selected_items = request.GET.getlist("items")
    selected_categories = request.GET.getlist("categories")
    selected_stores = request.GET.getlist("stores")
    selected_brands = request.GET.getlist("brands")
    selected_units = request.GET.getlist("units")
    selected_glazes = request.GET.getlist("glazes")
    selected_peeling_types = request.GET.getlist("peeling_types")
    selected_grades = request.GET.getlist("grades")
    selected_item_qualities = request.GET.getlist("item_qualities")
    selected_freezing_categories = request.GET.getlist("freezing_categories")
    selected_species = request.GET.getlist("species")
    
    # Date filters
    date_filter = request.GET.get("date_filter", "")
    start_date = request.GET.get("start_date", "")
    end_date = request.GET.get("end_date", "")
    
    # Calculate date range (same logic as main view)
    today = timezone.now().date()
    if date_filter == "today":
        start_date = end_date = today
    elif date_filter == "week":
        start_date = today - timedelta(days=today.weekday())
        end_date = today
    elif date_filter == "month":
        start_date = today.replace(day=1)
        end_date = today
    elif date_filter == "quarter":
        quarter_month = ((today.month - 1) // 3) * 3 + 1
        start_date = today.replace(month=quarter_month, day=1)
        end_date = today
    elif date_filter == "year":
        start_date = today.replace(month=1, day=1)
        end_date = today
    elif date_filter == "custom" and start_date and end_date:
        try:
            start_date = datetime.strptime(start_date, "%Y-%m-%d").date()
            end_date = datetime.strptime(end_date, "%Y-%m-%d").date()
        except:
            start_date = None
            end_date = None
    else:
        start_date = None
        end_date = None

    # Build query (same as main view - copy the entire logic)
    movement_query = StockMovement.objects.select_related(
        'store', 'item', 'item__category', 'brand', 'unit', 'glaze',
        'freezing_category', 'item_quality', 'peeling_type', 'item_grade', 'species'
    )

    # Apply filters
    if selected_items:
        movement_query = movement_query.filter(item__id__in=selected_items)
    if selected_categories:
        movement_query = movement_query.filter(item__category__id__in=selected_categories)
    if selected_stores:
        movement_query = movement_query.filter(store__id__in=selected_stores)
    if selected_brands:
        movement_query = movement_query.filter(brand__id__in=selected_brands)
    if selected_units:
        movement_query = movement_query.filter(unit__id__in=selected_units)
    if selected_glazes:
        movement_query = movement_query.filter(glaze__id__in=selected_glazes)
    if selected_peeling_types:
        movement_query = movement_query.filter(peeling_type__id__in=selected_peeling_types)
    if selected_grades:
        movement_query = movement_query.filter(item_grade__id__in=selected_grades)
    if selected_item_qualities:
        movement_query = movement_query.filter(item_quality__id__in=selected_item_qualities)
    if selected_freezing_categories:
        movement_query = movement_query.filter(freezing_category__id__in=selected_freezing_categories)
    if selected_species:
        movement_query = movement_query.filter(species__id__in=selected_species)

    # Get combinations and process (exact same logic as main view)
    stock_combinations = movement_query.values(
        'store', 'item', 'brand', 'item_quality', 'freezing_category',
        'peeling_type', 'unit', 'glaze', 'species', 'item_grade'
    ).annotate(
        store_name=Max('store__name'),
        item_name=Max('item__name'),
        brand_name=Max('brand__name'),
        category_name=Max('item__category__name'),
        unit_code=Max('unit__unit_code'),
        glaze_percentage=Max('glaze__percentage'),
        freezing_category_name=Max('freezing_category__name'),
        item_quality_quality=Max('item_quality__quality'),
        peeling_type_name=Max('peeling_type__name'),
        species_name=Max('species__name'),
        item_grade_grade=Max('item_grade__grade'),
        item_grade_order_code=Max('item_grade__order_code')
    )

    # Build sectioned data structure (same as main view)
    sectioned_data = {}
    
    for combo in stock_combinations:
        # Create section key
        item_quality = combo['item_quality_quality'] or "Unknown"
        unit_code = combo['unit_code'] or "N/A"
        glaze_pct = combo['glaze_percentage'] or "N/A"
        category_name = combo['freezing_category_name'] or "N/A"
        brand_name = combo['brand_name'] or "N/A"
        
        section_key = f"{item_quality}|{unit_code}|{glaze_pct}|{category_name}|{brand_name}"
        
        # Initialize section if not exists
        if section_key not in sectioned_data:
            sectioned_data[section_key] = {
                'item_quality': item_quality,
                'unit_code': unit_code,
                'glaze': glaze_pct,
                'category': category_name,
                'brand': brand_name,
                'store_name': combo['store_name'],
                'items': [],
                'totals': {
                    'opening': Decimal('0'),
                    'freezing': Decimal('0'),
                    'shipment': Decimal('0'),
                    'transfer_in': Decimal('0'),
                    'transfer_out': Decimal('0'),
                    'adjustment_plus': Decimal('0'),
                    'adjustment_minus': Decimal('0'),
                    'total_slab': Decimal('0'),
                    'total_case': Decimal('0'),
                    'total_usd_amount': Decimal('0'),
                    'total_inr_amount': Decimal('0'),
                }
            }
        
        # Build grade display
        grade_parts = []
        if combo['species_name']:
            grade_parts.append(combo['species_name'])
        if combo['peeling_type_name']:
            grade_parts.append(combo['peeling_type_name'])
        if combo['item_grade_grade']:
            grade_parts.append(combo['item_grade_grade'])
        grade_display = " / ".join(grade_parts) if grade_parts else "NIL"
        
        # Build filter for this specific grade
        movement_filters = {
            'store_id': combo['store'],
            'item_id': combo['item'],
            'brand_id': combo['brand'],
        }
        
        # Add optional filters
        if combo['item_quality'] is not None:
            movement_filters['item_quality_id'] = combo['item_quality']
        if combo['freezing_category'] is not None:
            movement_filters['freezing_category_id'] = combo['freezing_category']
        if combo['peeling_type'] is not None:
            movement_filters['peeling_type_id'] = combo['peeling_type']
        if combo['unit'] is not None:
            movement_filters['unit_id'] = combo['unit']
        if combo['glaze'] is not None:
            movement_filters['glaze_id'] = combo['glaze']
        if combo['species'] is not None:
            movement_filters['species_id'] = combo['species']
        if combo['item_grade'] is not None:
            movement_filters['item_grade_id'] = combo['item_grade']
        
        # Filter movements for this grade
        item_movements = movement_query.filter(**movement_filters)
        
        # Initialize quantities
        opening = Decimal('0')
        freezing = Decimal('0')
        shipment = Decimal('0')
        transfer_in = Decimal('0')
        transfer_out = Decimal('0')
        adjustment_plus = Decimal('0')
        adjustment_minus = Decimal('0')
        total_case = Decimal('0')
        
        # Calculate opening balance
        if start_date:
            opening_movements = item_movements.filter(
                movement_date__lt=start_date
            ).aggregate(
                total_kg=Coalesce(Sum('kg_quantity'), Decimal('0'), output_field=DecimalField())
            )
            opening = opening_movements['total_kg']
            
            period_movements = item_movements.filter(
                movement_date__gte=start_date,
                movement_date__lte=end_date
            )
        else:
            period_movements = item_movements
        
        if start_date and end_date:
            # Freezing entries
            freezing_data = period_movements.filter(
                movement_type__in=['freezing_spot', 'freezing_local', 'freezing_tenant', 'return_tenant']
            ).aggregate(
                total=Coalesce(Sum('kg_quantity'), Decimal('0'), output_field=DecimalField())
            )
            freezing = freezing_data['total']
            
            # Shipments
            shipment_data = period_movements.filter(
                movement_type='shipment'
            ).aggregate(
                total=Coalesce(Sum('kg_quantity'), Decimal('0'), output_field=DecimalField())
            )
            shipment = abs(shipment_data['total'])
            
            # Transfers IN
            transfer_in_data = period_movements.filter(
                movement_type='transfer_in'
            ).aggregate(
                total=Coalesce(Sum('kg_quantity'), Decimal('0'), output_field=DecimalField())
            )
            transfer_in = transfer_in_data['total']
            
            # Transfers OUT
            transfer_out_data = period_movements.filter(
                movement_type='transfer_out'
            ).aggregate(
                total=Coalesce(Sum('kg_quantity'), Decimal('0'), output_field=DecimalField())
            )
            transfer_out = abs(transfer_out_data['total'])
            
            # Adjustments Plus
            adj_plus_data = period_movements.filter(
                movement_type='adjustment_plus'
            ).aggregate(
                total=Coalesce(Sum('kg_quantity'), Decimal('0'), output_field=DecimalField())
            )
            adjustment_plus = adj_plus_data['total']
            
            # Adjustments Minus
            adj_minus_data = period_movements.filter(
                movement_type='adjustment_minus'
            ).aggregate(
                total=Coalesce(Sum('kg_quantity'), Decimal('0'), output_field=DecimalField())
            )
            adjustment_minus = abs(adj_minus_data['total'])
            
            # Calculate cumulative CS
            cumulative_cs = item_movements.filter(
                movement_date__lte=end_date
            ).aggregate(
                total=Coalesce(Sum('cs_quantity'), Decimal('0'), output_field=DecimalField())
            )
            total_case = cumulative_cs['total']
            
            # Calculate total slab
            total_slab = (opening + freezing + transfer_in + adjustment_plus) - (shipment + transfer_out + adjustment_minus)
        else:
            # No date filter - show current total stock
            all_movements = item_movements.aggregate(
                total_kg=Coalesce(Sum('kg_quantity'), Decimal('0'), output_field=DecimalField()),
                total_cs=Coalesce(Sum('cs_quantity'), Decimal('0'), output_field=DecimalField())
            )
            total_slab = all_movements['total_kg']
            total_case = all_movements['total_cs']
        
        # Calculate USD and INR amounts
        latest_movement = item_movements.order_by('-movement_date', '-id').first()
        usd_rate_per_kg = Decimal('0')
        inr_rate_per_kg = Decimal('0')
        
        if latest_movement:
            usd_rate_per_kg = latest_movement.usd_rate_per_kg or Decimal('0')
            if latest_movement.usd_rate_item_to_inr and latest_movement.kg_quantity:
                inr_rate_per_kg = latest_movement.usd_rate_item_to_inr / latest_movement.kg_quantity
        
        usd_amount = total_slab * usd_rate_per_kg
        inr_amount = total_slab * inr_rate_per_kg
        
        # Only add rows with non-zero quantities
        if opening != 0 or freezing != 0 or shipment != 0 or transfer_in != 0 or transfer_out != 0 or adjustment_plus != 0 or adjustment_minus != 0 or total_slab != 0:
            item_data = {
                'grade': grade_display,
                'grade_order': combo['item_grade_order_code'] if combo['item_grade_order_code'] else 999999,
                'opening': opening,
                'freezing': freezing,
                'shipment': shipment,
                'transfer_in': transfer_in,
                'transfer_out': transfer_out,
                'adjustment_plus': adjustment_plus,
                'adjustment_minus': adjustment_minus,
                'total_slab': total_slab,
                'total_case': total_case,
                'usd_rate_per_kg': usd_rate_per_kg,
                'inr_rate_per_kg': inr_rate_per_kg,
                'usd_amount': usd_amount,
                'inr_amount': inr_amount,
                # Add section-level info for template access
                'item__name': combo['item_name'],
                'item__category__name': combo['category_name'],
                'store__name': combo['store_name'],
                'brand__name': combo['brand_name'],
                'unit__unit_code': combo['unit_code'],
                'unit__description': combo['unit_code'],  # Using unit_code as description
                'glaze__percentage': combo['glaze_percentage'],
                'freezing_category__name': combo['freezing_category_name'],
                'item_quality__quality': combo['item_quality_quality'],
                'species__name': combo['species_name'],
                'peeling_type__name': combo['peeling_type_name'],
                'item_grade__grade': combo['item_grade_grade'],
            }
            
            sectioned_data[section_key]['items'].append(item_data)
            
            # Add to section totals
            for key in ['opening', 'freezing', 'shipment', 'transfer_in', 'transfer_out', 
                        'adjustment_plus', 'adjustment_minus', 'total_slab', 'total_case']:
                sectioned_data[section_key]['totals'][key] += item_data[key]
            
            sectioned_data[section_key]['totals']['total_usd_amount'] += usd_amount
            sectioned_data[section_key]['totals']['total_inr_amount'] += inr_amount

    # Remove empty sections
    sectioned_data = {k: v for k, v in sectioned_data.items() if v['items']}

    # Sort items within each section by grade order
    for section in sectioned_data.values():
        section['items'].sort(key=lambda x: (x['grade_order'], x['grade']))

    # Calculate grand totals
    grand_totals = {
        'opening': Decimal('0'),
        'freezing': Decimal('0'),
        'shipment': Decimal('0'),
        'transfer_in': Decimal('0'),
        'transfer_out': Decimal('0'),
        'adjustment_plus': Decimal('0'),
        'adjustment_minus': Decimal('0'),
        'total_slab': Decimal('0'),
        'total_case': Decimal('0'),
        'total_usd_amount': Decimal('0'),
        'total_inr_amount': Decimal('0'),
        'section_count': len(sectioned_data),
    }
    
    for section in sectioned_data.values():
        for key in grand_totals:
            if key != 'section_count':
                grand_totals[key] += section['totals'][key]

    return render(
        request,
        "adminapp/report/stock_report_print_amt.html",
        {
            "sectioned_data": sectioned_data,
            "grand_totals": grand_totals,
            "date_filter": date_filter,
            "start_date": start_date.strftime("%Y-%m-%d") if start_date else "",
            "end_date": end_date.strftime("%Y-%m-%d") if end_date else "",
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
def delete_spot_agent_voucher(request, pk):
    voucher = get_object_or_404(SpotAgentVoucher, pk=pk)
    
    if request.method == 'POST':
        agent = voucher.agent
        voucher_date = voucher.date
        voucher_no = voucher.voucher_no
        
        try:
            voucher.delete()
            
            
            messages.success(
                request,
                f'Spot agent voucher "{voucher_no}" has been deleted successfully!'
            )
        except Exception as e:
            messages.error(
                request,
                f'Error deleting voucher: {str(e)}'
            )
        
        return redirect('adminapp:spotagentvoucher_list')
    
    # If GET request, redirect back to detail page
    return redirect('adminapp:spot_agent_voucher_detail', pk=pk)

@check_permission('voucher_view')
def delete_spot_agent_voucher_list(request, pk):
    voucher = get_object_or_404(SpotAgentVoucher, pk=pk)

    try:
        voucher_no = voucher.voucher_no
        voucher.delete()
        messages.success(request, f'Spot agent voucher "{voucher_no}" deleted successfully!')
    except Exception as e:
        messages.error(request, f"Error deleting voucher: {str(e)}")

    return redirect('adminapp:spotagentvoucher_list')


@login_required
def spot_agent_voucher_detail(request, pk):
    """
    Display detailed information about a specific spot agent voucher.
    
    Args:
        request: HTTP request object
        pk: Primary key of the SpotAgentVoucher
        
    Returns:
        Rendered template with voucher details
    """
    voucher = get_object_or_404(SpotAgentVoucher, pk=pk)
    
    context = {
        'voucher': voucher,
    }
    
    return render(request, 'adminapp/vouchers/spot_agent_voucher_detail.html', context)




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

@check_permission('voucher_add')
def create_supervisor_voucher(request):
    if request.method == "POST":
        form = SupervisorVoucherForm(request.POST)
        if form.is_valid():
            voucher = form.save(commit=False)

            # Get previous voucher totals for this supervisor
            voucher_sums = SupervisorVoucher.objects.filter(
                supervisor=voucher.supervisor
            ).aggregate(
                total_receipt=Sum('receipt'),
                total_payment=Sum('payment')
            )
            
            total_receipt = voucher_sums['total_receipt'] or 0
            total_payment = voucher_sums['total_payment'] or 0
            
            # Calculate previous balance: Payments - Receipts
            # (Payments = what we paid supervisor, Receipts = what supervisor paid us)
            last_total = total_payment - total_receipt

            # Remain amount before this entry
            voucher.remain_amount = last_total

            # Compute new total after receipt/payment
            voucher.total_amount = last_total + (voucher.payment or 0) - (voucher.receipt or 0)

            voucher.save()
            messages.success(request, "Supervisor Voucher created successfully ✅")
            return redirect("adminapp:supervisorvoucher_list")
    else:
        form = SupervisorVoucherForm()

    return render(request, "adminapp/vouchers/supervisorvoucher_form.html", {"form": form})


@check_permission('voucher_view')
@login_required
def supervisor_voucher_detail(request, pk):
    """
    Display detailed information about a specific supervisor voucher.
    
    Args:
        request: HTTP request object
        pk: Primary key of the SupervisorVoucher
        
    Returns:
        Rendered template with voucher details
    """
    voucher = get_object_or_404(SupervisorVoucher, pk=pk)
    
    context = {
        'voucher': voucher,
    }
    
    return render(request, 'adminapp/vouchers/supervisor_voucher_detail.html', context)

@check_permission('voucher_view')
def get_supervisor_balance(request):
    supervisor_id = request.GET.get("supervisor_id")
    if not supervisor_id:
        return JsonResponse({"error": "No supervisor_id provided"}, status=400)

    try:
        supervisor = PurchasingSupervisor.objects.get(pk=supervisor_id)

        # Sum of receipts & payments in vouchers
        voucher_sums = SupervisorVoucher.objects.filter(
            supervisor=supervisor
        ).aggregate(
            total_receipt=Sum("receipt"),
            total_payment=Sum("payment"),
        )

        total_receipt = voucher_sums["total_receipt"] or 0
        total_payment = voucher_sums["total_payment"] or 0

        # Calculate total commission from spot purchases
        # Get all spot purchases for this supervisor
        spot_purchases = SpotPurchase.objects.filter(supervisor=supervisor)
        
        # Debug: Print spot purchases
        print(f"=== Debug Supervisor Balance for {supervisor.name} ===")
        print(f"Supervisor ID: {supervisor.id}")
        print(f"Total Spot Purchases: {spot_purchases.count()}")
        
        # Calculate total quantity (kg) from all purchases
        total_quantity = spot_purchases.aggregate(
            total_kg=Sum('total_quantity')
        )['total_kg'] or 0
        
        print(f"Total Quantity (kg): {total_quantity}")
        
        # Get commission rate
        commission_rate = supervisor.commission or 0
        print(f"Commission Rate (₹/kg): {commission_rate}")
        
        # Calculate total commission: total_kg * commission_rate
        total_commission = float(total_quantity) * float(commission_rate)
        print(f"Total Commission: {total_quantity} × {commission_rate} = {total_commission}")
        
        # Calculate remaining balance: Payments - Receipts
        remain_amount = total_payment - total_receipt
        
        print(f"Total Payments: {total_payment}")
        print(f"Total Receipts: {total_receipt}")
        print(f"Remaining Balance: {remain_amount}")
        print("=" * 50)

        return JsonResponse({
            "total_receipt": float(total_receipt),
            "total_payment": float(total_payment),
            "remain_amount": float(remain_amount),
            "supervisor_name": supervisor.name,
            "supervisor_mobile": supervisor.mobile or "N/A",
            "supervisor_email": supervisor.email or "N/A",
            "commission_rate": float(commission_rate),
            "total_quantity": float(total_quantity),
            "total_commission": float(total_commission),
            "total_purchases": spot_purchases.count(),
        })

    except PurchasingSupervisor.DoesNotExist:
        return JsonResponse({"error": "Supervisor not found"}, status=404)
    except Exception as e:
        print(f"Error in get_supervisor_balance: {str(e)}")
        import traceback
        traceback.print_exc()
        return JsonResponse({"error": f"Server error: {str(e)}"}, status=500)

@check_permission('voucher_view')
def supervisorvoucher_list_with_summary(request):
    """Enhanced list view with transaction summary and filtering"""
    
    # Get filter parameters
    date_filter = request.GET.get('date_filter', 'all')
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    supervisor_filter = request.GET.get('supervisor')
    search_query = request.GET.get('search', '')
    
    # Base queryset
    vouchers = SupervisorVoucher.objects.select_related('supervisor').order_by('-date', '-id')
    
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
    
    # Apply supervisor filtering
    if supervisor_filter:
        vouchers = vouchers.filter(supervisor_id=supervisor_filter)
    
    # Apply search filtering
    if search_query:
        vouchers = vouchers.filter(
            Q(voucher_no__icontains=search_query) |
            Q(supervisor__name__icontains=search_query) |
            Q(supervisor__mobile__icontains=search_query) |
            Q(description__icontains=search_query)
        )
    
    # Calculate summary statistics
    summary = vouchers.aggregate(
        total_vouchers=Count('id'),
        total_receipts=Sum('receipt'),
        total_payments=Sum('payment'),
        net_amount=Sum('payment') - Sum('receipt')
    )
    
    # Convert None to 0 for display
    for key, value in summary.items():
        if value is None:
            summary[key] = Decimal('0.00')
    
    # Get supervisor-wise summary
    supervisor_summary = vouchers.values(
        'supervisor__id', 
        'supervisor__name',
        'supervisor__mobile'
    ).annotate(
        voucher_count=Count('id'),
        total_receipts=Sum('receipt'),
        total_payments=Sum('payment'),
        net_amount=Sum('payment') - Sum('receipt')
    ).order_by('-net_amount')
    
    # Pagination
    paginator = Paginator(vouchers, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    # Get all active supervisors for filter dropdown
    all_supervisors = PurchasingSupervisor.objects.filter(is_active=True).order_by('name')
    
    context = {
        'vouchers': page_obj,
        'summary': summary,
        'supervisor_summary': supervisor_summary,
        'all_supervisors': all_supervisors,
        'search_query': search_query,
        'date_filter': date_filter,
        'start_date': start_date,
        'end_date': end_date,
        'supervisor_filter': supervisor_filter,
        'period_name': period_name,
        'total_count': paginator.count,
        'today': today,
    }
    
    return render(request, "adminapp/vouchers/supervisorvoucher_list.html", context)

@check_permission('voucher_view')
def supervisor_voucher_summary_pdf(request):
    """Generate PDF summary report"""
    
    # Get same filter parameters as list view
    date_filter = request.GET.get('date_filter', 'all')
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    supervisor_filter = request.GET.get('supervisor')
    
    # Apply same filtering logic
    vouchers = SupervisorVoucher.objects.select_related('supervisor').order_by('-date', '-id')
    
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
    
    if supervisor_filter:
        vouchers = vouchers.filter(supervisor_id=supervisor_filter)
    
    # Calculate summary
    summary = vouchers.aggregate(
        total_vouchers=Count('id'),
        total_receipts=Sum('receipt'),
        total_payments=Sum('payment'),
        net_amount=Sum('payment') - Sum('receipt')
    )
    
    for key, value in summary.items():
        if value is None:
            summary[key] = Decimal('0.00')
    
    # Get supervisor-wise summary
    supervisor_summary = vouchers.values(
        'supervisor__name',
        'supervisor__mobile',
        'supervisor__email'
    ).annotate(
        voucher_count=Count('id'),
        total_receipts=Sum('receipt'),
        total_payments=Sum('payment'),
        net_amount=Sum('payment') - Sum('receipt')
    ).order_by('-net_amount')
    
    # Render PDF
    template = get_template('adminapp/vouchers/supervisor_voucher_summary_pdf.html')
    context = {
        'vouchers': vouchers,
        'summary': summary,
        'supervisor_summary': supervisor_summary,
        'period_name': period_name,
        'generated_date': timezone.now(),
        'company_name': 'Your Company Name',  # Replace with actual company name
    }
    
    html = template.render(context)
    
    # Create PDF
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="supervisor_voucher_summary_{date_filter}_{today}.pdf"'
    
    pisa_status = pisa.CreatePDF(html, dest=response)
    
    if pisa_status.err:
        return HttpResponse('We had some errors <pre>' + html + '</pre>')
    
    return response

@check_permission('voucher_view')
def supervisor_statement_pdf(request, supervisor_id):
    """Generate PDF statement for specific supervisor"""
    
    supervisor = get_object_or_404(PurchasingSupervisor, id=supervisor_id)
    
    # Get filter parameters
    date_filter = request.GET.get('date_filter', 'all')
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    
    # Get supervisor vouchers
    today = timezone.now().date()
    
    # Filter vouchers
    vouchers = SupervisorVoucher.objects.filter(supervisor=supervisor)
    
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
    
    # Calculate totals
    vouchers_summary = vouchers.aggregate(
        total_receipts=Sum('receipt'),
        total_payments=Sum('payment')
    )
    
    total_receipts = vouchers_summary['total_receipts'] or Decimal('0.00')
    total_payments = vouchers_summary['total_payments'] or Decimal('0.00')
    outstanding_balance = total_payments - total_receipts
    
    # Create transaction list for chronological order
    transactions = []
    
    for voucher in vouchers:
        if voucher.payment > 0:
            transactions.append({
                'date': voucher.date,
                'type': 'Payment',
                'reference': voucher.voucher_no,
                'description': voucher.description or 'Payment made to supervisor',
                'debit': voucher.payment,
                'credit': Decimal('0.00'),
                'balance': None
            })
        
        if voucher.receipt > 0:
            transactions.append({
                'date': voucher.date,
                'type': 'Receipt',
                'reference': voucher.voucher_no,
                'description': voucher.description or 'Payment received from supervisor',
                'debit': Decimal('0.00'),
                'credit': voucher.receipt,
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
    template = get_template('adminapp/vouchers/supervisor_statement_pdf.html')
    context = {
        'supervisor': supervisor,
        'transactions': transactions,
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
    safe_supervisor_name = re.sub(r'[^\w\s-]', '', supervisor.name).strip()
    response['Content-Disposition'] = f'attachment; filename="supervisor_statement_{safe_supervisor_name}_{date_filter}_{today}.pdf"'
    
    pisa_status = pisa.CreatePDF(html, dest=response)
    
    if pisa_status.err:
        return HttpResponse('We had some errors <pre>' + html + '</pre>')
    
    return response

@check_permission('voucher_edit')
def update_supervisor_voucher(request, voucher_id):
    """Update existing supervisor voucher"""
    voucher = get_object_or_404(SupervisorVoucher, id=voucher_id)
    
    if request.method == "POST":
        form = SupervisorVoucherForm(request.POST, instance=voucher)
        if form.is_valid():
            voucher = form.save(commit=False)
            
            # Recalculate balance excluding current voucher
            voucher_sums = SupervisorVoucher.objects.filter(
                supervisor=voucher.supervisor
            ).exclude(id=voucher_id).aggregate(
                total_receipt=Sum('receipt'),
                total_payment=Sum('payment')
            )
            
            total_receipt = voucher_sums['total_receipt'] or 0
            total_payment = voucher_sums['total_payment'] or 0
            
            last_total = total_payment - total_receipt
            voucher.remain_amount = last_total
            voucher.total_amount = last_total + (voucher.payment or 0) - (voucher.receipt or 0)
            
            voucher.save()
            messages.success(request, "Supervisor Voucher updated successfully ✅")
            return redirect("adminapp:supervisorvoucher_list")
    else:
        form = SupervisorVoucherForm(instance=voucher)
    
    return render(request, "adminapp/vouchers/supervisorvoucher_form.html", {
        "form": form,
        "is_update": True
    })

@check_permission('voucher_delete')
def delete_supervisor_voucher(request, voucher_id):
    """Delete supervisor voucher"""
    voucher = get_object_or_404(SupervisorVoucher, id=voucher_id)
    
    if request.method == "POST":
        voucher.delete()
        messages.success(request, "Supervisor Voucher deleted successfully ✅")
        return redirect("adminapp:supervisorvoucher_list")
    
    return render(request, "adminapp/vouchers/supervisorvoucher_confirm_delete.html", {
        "voucher": voucher
    })

@check_permission('voucher_delete')
def delete_supervisor_voucher_list(request, pk):
    voucher = get_object_or_404(SupervisorVoucher, pk=pk)

    try:
        voucher_no = voucher.voucher_no
        voucher.delete()
        messages.success(request, f'Supervisor voucher "{voucher_no}" deleted successfully!')
    except Exception as e:
        messages.error(request, f"Error deleting voucher: {str(e)}")

    return redirect('adminapp:supervisorvoucher_list')


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
@login_required
def local_purchase_voucher_detail(request, pk):
    """
    Display detailed information about a specific local purchase voucher.
    
    Args:
        request: HTTP request object
        pk: Primary key of the LocalPurchaseVoucher
        
    Returns:
        Rendered template with voucher details
    """
    voucher = get_object_or_404(LocalPurchaseVoucher, pk=pk)
    
    context = {
        'voucher': voucher,
    }
    
    return render(request, 'adminapp/vouchers/local_purchase_voucher_detail.html', context)

@check_permission('voucher_delete')
@login_required
def delete_local_purchase_voucher(request, pk):
    """
    Delete a local purchase voucher.
    
    Args:
        request: HTTP request object
        pk: Primary key of the LocalPurchaseVoucher
        
    Returns:
        Redirect to voucher list page
    """
    voucher = get_object_or_404(LocalPurchaseVoucher, pk=pk)
    
    if request.method == 'POST':
        voucher.delete()
        messages.success(request, 'Local Purchase Voucher deleted successfully.')
        return redirect('adminapp:localpurchasevoucher_list')
    
    return redirect('adminapp:local_purchase_voucher_detail', pk=pk)

@check_permission('voucher_view')
def delete_localpurchase_voucher_list(request, pk):
    voucher = get_object_or_404(LocalPurchaseVoucher, pk=pk)

    try:
        voucher_no = voucher.voucher_no
        voucher.delete()
        messages.success(request, f'Local purchase voucher "{voucher_no}" deleted successfully!')
    except Exception as e:
        messages.error(request, f"Error deleting voucher: {str(e)}")

    return redirect('adminapp:localpurchasevoucher_list')


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

@check_permission('voucher_view')
@login_required
def peeling_shed_voucher_detail(request, pk):
    """
    Display detailed information about a specific peeling shed voucher.
    
    Args:
        request: HTTP request object
        pk: Primary key of the PeelingShedVoucher
        
    Returns:
        Rendered template with voucher details
    """
    voucher = get_object_or_404(PeelingShedVoucher, pk=pk)
    
    context = {
        'voucher': voucher,
    }
    
    return render(request, 'adminapp/vouchers/peeling_shed_voucher_detail.html', context)


@check_permission('voucher_delete')
@login_required
def delete_peeling_shed_voucher(request, pk):
    """
    Delete a peeling shed voucher.
    
    Args:
        request: HTTP request object
        pk: Primary key of the PeelingShedVoucher
        
    Returns:
        Redirect to voucher list page
    """
    voucher = get_object_or_404(PeelingShedVoucher, pk=pk)
    
    if request.method == 'POST':
        voucher.delete()
        messages.success(request, 'Peeling Shed Voucher deleted successfully.')
        return redirect('adminapp:peeling_shed_voucher_list')
    
    return redirect('adminapp:peeling_shed_voucher_detail', pk=pk)

@check_permission('voucher_view')
def delete_peelingshed_voucher_list(request, pk):
    voucher = get_object_or_404(PeelingShedVoucher, pk=pk)

    try:
        voucher_no = voucher.voucher_no
        voucher.delete()
        messages.success(request, f'Peeling shed voucher "{voucher_no}" deleted successfully!')
    except Exception as e:
        messages.error(request, f"Error deleting voucher: {str(e)}")

    return redirect('adminapp:peeling_shed_voucher_list')


def get_sheds_with_freezing():
    """Get sheds that have completed freezing entries"""
    return Shed.objects.filter(
        freezing_shed_items__freezing_entry__freezing_status='complete'
    ).distinct().order_by('name')

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

class PeelingShedVoucherListView(ListView):
    model = PeelingShedVoucher
    template_name = "adminapp/vouchers/peelingshedvoucher_list.html"
    context_object_name = "vouchers"
    ordering = ["-date", "-id"]

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
            # Log form errors for debugging
            print("Form validation failed:")
            print(form.errors)
            messages.error(request, f"Form validation failed: {form.errors}")
    else:
        form = TenantVoucherForm()

    return render(request, "adminapp/vouchers/tenantvoucher_form.html", {"form": form})

@check_permission('voucher_view')
@login_required
def tenant_voucher_detail(request, pk):
    """
    Display detailed information about a specific tenant voucher.
    
    Args:
        request: HTTP request object
        pk: Primary key of the TenantVoucher
        
    Returns:
        Rendered template with voucher details
    """
    voucher = get_object_or_404(TenantVoucher, pk=pk)
    
    context = {
        'voucher': voucher,
    }
    
    return render(request, 'adminapp/vouchers/tenant_voucher_detail.html', context)


@check_permission('voucher_view')
def delete_tenant_voucher_list(request, pk):
    voucher = get_object_or_404(TenantVoucher, pk=pk)

    try:
        voucher_no = voucher.voucher_no
        voucher.delete()
        messages.success(request, f'Tenant voucher "{voucher_no}" deleted successfully!')
    except Exception as e:
        messages.error(request, f"Error deleting voucher: {str(e)}")

    return redirect('adminapp:tenantvoucher_list')


@check_permission('voucher_delete')
@login_required
def delete_tenant_voucher(request, pk):
    """
    Delete a tenant voucher.
    
    Args:
        request: HTTP request object
        pk: Primary key of the TenantVoucher
        
    Returns:
        Redirect to voucher list page
    """
    voucher = get_object_or_404(TenantVoucher, pk=pk)
    
    if request.method == 'POST':
        voucher.delete()
        messages.success(request, 'Tenant Voucher deleted successfully.')
        return redirect('adminapp:tenantvoucher_list')
    
    return redirect('adminapp:tenant_voucher_detail', pk=pk)

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
    """Generate comprehensive PDF summary report for tenant vouchers"""
    
    # Get filter parameters
    date_filter = request.GET.get('date_filter', 'all')
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    tenant_filter = request.GET.get('tenant')
    
    # Base queryset
    vouchers = TenantVoucher.objects.select_related('tenant').order_by('-date', '-id')
    
    today = timezone.now().date()
    period_name = "All Time"
    
    # Apply date filtering
    if date_filter == 'today':
        vouchers = vouchers.filter(date=today)
        period_name = f"Today ({today.strftime('%d %b %Y')})"
    
    elif date_filter == 'week':
        week_start = today - timedelta(days=today.weekday())
        week_end = week_start + timedelta(days=6)
        vouchers = vouchers.filter(date__range=[week_start, week_end])
        period_name = f"This Week ({week_start.strftime('%d %b')} to {week_end.strftime('%d %b %Y')})"
    
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
            period_name = f"Custom Range ({start_date_obj.strftime('%d %b %Y')} to {end_date_obj.strftime('%d %b %Y')})"
        except ValueError:
            period_name = "All Time"
    
    # Apply tenant filter
    selected_tenant = None
    if tenant_filter:
        try:
            vouchers = vouchers.filter(tenant_id=tenant_filter)
            selected_tenant = Tenant.objects.get(id=tenant_filter)
        except Tenant.DoesNotExist:
            pass
    
    # Calculate overall summary
    summary = vouchers.aggregate(
        total_vouchers=Count('id'),
        total_receipts=Sum('receipt'),
        total_payments=Sum('payment'),
    )
    
    # Handle None values
    for key, value in summary.items():
        if value is None:
            summary[key] = Decimal('0.00') if 'total' in key else 0
    
    # Calculate net amount
    summary['net_amount'] = summary['total_receipts'] - summary['total_payments']
    
    # Get tenant-wise summary with all details
    tenant_summary = vouchers.values(
        'tenant__id',
        'tenant__company_name',
        'tenant__contact_person',
        'tenant__phone',
        'tenant__email'
    ).annotate(
        voucher_count=Count('id'),
        total_receipts=Sum('receipt'),
        total_payments=Sum('payment'),
    ).order_by('-total_receipts')
    
    # Calculate net amount for each tenant
    for tenant in tenant_summary:
        tenant['net_amount'] = (tenant['total_receipts'] or Decimal('0.00')) - (tenant['total_payments'] or Decimal('0.00'))
        # Get latest voucher date for this tenant
        latest = vouchers.filter(tenant_id=tenant['tenant__id']).order_by('-date').first()
        tenant['latest_date'] = latest.date if latest else None
    
    
    # Prepare context
    context = {
        'vouchers': vouchers[:100],  # Limit to 100 for PDF performance
        'total_voucher_count': vouchers.count(),
        'summary': summary,
        'tenant_summary': tenant_summary,
        'period_name': period_name,
        'selected_tenant': selected_tenant,
        'generated_date': timezone.now(),
        'generated_by': request.user.full_name if hasattr(request.user, 'full_name') else 'Admin',
    }
    
    # Render template
    template = get_template('adminapp/vouchers/tenant_voucher_summary_pdf.html')
    html = template.render(context)
    
    # Create PDF response
    response = HttpResponse(content_type='application/pdf')
    filename = f"tenant_voucher_summary_{date_filter}_{today.strftime('%Y%m%d')}.pdf"
    response['Content-Disposition'] = f'inline; filename="{filename}"'
    
    # Generate PDF
    pisa_status = pisa.CreatePDF(
        io.BytesIO(html.encode("UTF-8")),
        dest=response,
        encoding='UTF-8'
    )
    
    if pisa_status.err:
        return HttpResponse(f'<h1>PDF Generation Error</h1><pre>{html}</pre>')
    
    return response


@check_permission('voucher_view')
def tenant_statement_pdf(request, tenant_id):
    """Generate comprehensive PDF statement for specific tenant with complete financial summary
    
    NOTE: This includes ALL bills except cancelled ones (draft, finalized, sent, paid)
    to match the balance shown on the tenant voucher page.
    """
    
    # Get tenant or 404
    tenant = get_object_or_404(Tenant, id=tenant_id)
    tenant_company_name = tenant.company_name
    
    # Get filter parameters
    date_filter = request.GET.get('date_filter', 'all')
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    
    today = timezone.now().date()
    period_name = "All Time"
    filter_start_date = None
    filter_end_date = None
    
    # Base querysets - filter by tenant directly
    # Include all bills EXCEPT cancelled (include draft, finalized, sent, paid)
    bills = TenantBill.objects.filter(
        tenant=tenant
    ).exclude(status='cancelled')
    
    vouchers = TenantVoucher.objects.filter(tenant=tenant)
    
    # Apply date filtering
    if date_filter == 'today':
        filter_start_date = today
        filter_end_date = today
        bills = bills.filter(bill_date=today)
        vouchers = vouchers.filter(date=today)
        period_name = f"Today ({today.strftime('%d %b %Y')})"
    
    elif date_filter == 'week':
        week_start = today - timedelta(days=today.weekday())
        week_end = week_start + timedelta(days=6)
        filter_start_date = week_start
        filter_end_date = week_end
        bills = bills.filter(bill_date__range=[week_start, week_end])
        vouchers = vouchers.filter(date__range=[week_start, week_end])
        period_name = f"This Week ({week_start.strftime('%d %b')} to {week_end.strftime('%d %b %Y')})"
    
    elif date_filter == 'month':
        month_start = today.replace(day=1)
        if today.month == 12:
            month_end = today.replace(year=today.year + 1, month=1, day=1) - timedelta(days=1)
        else:
            month_end = today.replace(month=today.month + 1, day=1) - timedelta(days=1)
        filter_start_date = month_start
        filter_end_date = month_end
        bills = bills.filter(bill_date__range=[month_start, month_end])
        vouchers = vouchers.filter(date__range=[month_start, month_end])
        period_name = f"This Month ({month_start.strftime('%B %Y')})"
    
    elif date_filter == 'year':
        year_start = today.replace(month=1, day=1)
        year_end = today.replace(month=12, day=31)
        filter_start_date = year_start
        filter_end_date = year_end
        bills = bills.filter(bill_date__range=[year_start, year_end])
        vouchers = vouchers.filter(date__range=[year_start, year_end])
        period_name = f"This Year ({today.year})"
    
    elif date_filter == 'custom' and start_date and end_date:
        try:
            start_date_obj = datetime.strptime(start_date, '%Y-%m-%d').date()
            end_date_obj = datetime.strptime(end_date, '%Y-%m-%d').date()
            filter_start_date = start_date_obj
            filter_end_date = end_date_obj
            bills = bills.filter(bill_date__range=[start_date_obj, end_date_obj])
            vouchers = vouchers.filter(date__range=[start_date_obj, end_date_obj])
            period_name = f"Custom Range ({start_date_obj.strftime('%d %b %Y')} to {end_date_obj.strftime('%d %b %Y')})"
        except ValueError:
            pass
    
    # ============================================
    # CALCULATE OPENING BALANCE (before filter period)
    # ============================================
    opening_balance = Decimal('0.00')
    
    if filter_start_date:
        # Get all transactions BEFORE the filter start date
        opening_bills = TenantBill.objects.filter(
            tenant=tenant,
            bill_date__lt=filter_start_date
        ).exclude(status='cancelled').aggregate(total=Sum('total_amount'))['total'] or Decimal('0.00')
        
        opening_vouchers = TenantVoucher.objects.filter(
            tenant=tenant,
            date__lt=filter_start_date
        ).aggregate(
            total_receipts=Sum('receipt'),
            total_payments=Sum('payment')
        )
        
        opening_receipts = opening_vouchers['total_receipts'] or Decimal('0.00')
        opening_payments = opening_vouchers['total_payments'] or Decimal('0.00')
        
        # Calculate opening balance using same logic as get_tenant_balance
        opening_balance = opening_bills - opening_receipts + opening_payments
    
    # Order by date
    bills = bills.order_by('bill_date', 'id')
    vouchers = vouchers.order_by('date', 'id')
    
    # ============================================
    # COMPLETE FINANCIAL SUMMARY CALCULATIONS
    # ============================================
    
    # Calculate bills summary - THIS WILL SHOW total_amount
    bills_total = bills.aggregate(total=Sum('total_amount'))['total'] or Decimal('0.00')
    bills_count = bills.count()
    
    # Calculate vouchers summary
    vouchers_summary = vouchers.aggregate(
        total_receipts=Sum('receipt'),
        total_payments=Sum('payment'),
        voucher_count=Count('id')
    )
    
    total_receipts = vouchers_summary['total_receipts'] or Decimal('0.00')
    total_payments = vouchers_summary['total_payments'] or Decimal('0.00')
    voucher_count = vouchers_summary['voucher_count'] or 0
    
    # Calculate period balance (transactions in current period only)
    period_balance = bills_total - total_receipts + total_payments
    
    # Calculate closing balance (opening + period transactions)
    closing_balance = opening_balance + period_balance
    
    # Calculate paid bills
    paid_bills = bills.filter(status='paid')
    paid_bills_total = paid_bills.aggregate(total=Sum('total_amount'))['total'] or Decimal('0.00')
    paid_bills_count = paid_bills.count()
    
    # Calculate unpaid bills (finalized or sent but not paid)
    unpaid_bills = bills.exclude(status='paid')
    unpaid_bills_total = unpaid_bills.aggregate(total=Sum('total_amount'))['total'] or Decimal('0.00')
    unpaid_bills_count = unpaid_bills.count()
    
    # Get last payment details
    last_payment = vouchers.filter(receipt__gt=0).order_by('-date').first()
    last_payment_amount = last_payment.receipt if last_payment else Decimal('0.00')
    last_payment_date = last_payment.date if last_payment else None
    
    # Get last bill details
    last_bill = bills.order_by('-bill_date').first()
    last_bill_amount = last_bill.total_amount if last_bill else Decimal('0.00')
    last_bill_date = last_bill.bill_date if last_bill else None
    
    # Calculate total transactions
    total_transactions = bills_count + voucher_count
    
    # Create comprehensive summary dictionary
    financial_summary = {
        # Bills - bills_total contains the sum of all total_amount fields
        'total_bills': bills_total,  # This is the sum of all bill.total_amount
        'bills_count': bills_count,
        'paid_bills_total': paid_bills_total,
        'paid_bills_count': paid_bills_count,
        'unpaid_bills_total': unpaid_bills_total,
        'unpaid_bills_count': unpaid_bills_count,
        
        # Vouchers/Payments
        'total_receipts': total_receipts,
        'total_payments': total_payments,
        'voucher_count': voucher_count,
        'net_vouchers': total_receipts - total_payments,
        
        # Balance - using get_tenant_balance logic
        'opening_balance': opening_balance,
        'period_balance': period_balance,
        'outstanding_balance': closing_balance,  # This matches get_tenant_balance remain_amount
        'remaining_balance': closing_balance,
        
        # Last Transaction Details
        'last_payment_amount': last_payment_amount,
        'last_payment_date': last_payment_date,
        'last_bill_amount': last_bill_amount,
        'last_bill_date': last_bill_date,
        
        # Overall
        'total_transactions': total_transactions,
    }
    
    # ============================================
    # CREATE TRANSACTION LIST WITH REMAINING BALANCE
    # ============================================
    
    transactions = []
    
    # Add opening balance entry if there's a filter and opening balance exists
    if filter_start_date and opening_balance != Decimal('0.00'):
        transactions.append({
            'date': filter_start_date,
            'type': 'Opening',
            'reference': 'O/B',
            'description': 'Opening Balance (Previous Transactions)',
            'debit': Decimal('0.00'),
            'credit': Decimal('0.00'),
            'balance': opening_balance,
            'status': 'opening',
            'is_opening': True
        })
    
    # Add bills as CHARGES (what tenant needs to pay)
    # Each bill's total_amount will be shown in the debit column
    for bill in bills:
        transactions.append({
            'date': bill.bill_date,
            'type': 'Bill',
            'reference': bill.bill_number,
            'description': f"Freezing Bill: {bill.from_date.strftime('%d %b')} to {bill.to_date.strftime('%d %b %Y')} ({bill.total_kg:.2f} KG)",
            'debit': bill.total_amount,  # THIS SHOWS THE BILL'S total_amount
            'credit': Decimal('0.00'),
            'balance': None,
            'status': bill.status,
            'is_opening': False,
            'bill_obj': bill,  # Keep reference to bill object for template access
        })
    
    # Add receipts and payments from vouchers
    for voucher in vouchers:
        # Receipt = Payment FROM tenant (reduces what they owe)
        if voucher.receipt > 0:
            transactions.append({
                'date': voucher.date,
                'type': 'Receipt',
                'reference': voucher.voucher_no,
                'description': voucher.description or 'Payment received from tenant',
                'debit': Decimal('0.00'),
                'credit': voucher.receipt,
                'balance': None,
                'status': 'completed',
                'is_opening': False
            })
        
        # Payment = Refund TO tenant (increases what they can claim)
        if voucher.payment > 0:
            transactions.append({
                'date': voucher.date,
                'type': 'Payment',
                'reference': voucher.voucher_no,
                'description': voucher.description or 'Refund made to tenant',
                'debit': voucher.payment,
                'credit': Decimal('0.00'),
                'balance': None,
                'status': 'completed',
                'is_opening': False
            })
    
    # Sort by date chronologically (opening balance stays first if exists)
    transactions.sort(key=lambda x: (x['date'], 0 if x.get('is_opening') else 1, x['type']))
    
    # Calculate REMAINING BALANCE using get_tenant_balance logic
    # Start with opening balance, add charges (debit), subtract payments (credit)
    remaining_balance = opening_balance
    
    for transaction in transactions:
        if transaction.get('is_opening'):
            # Opening balance already set
            continue
        
        # Apply same formula: bills - receipts + payments
        remaining_balance = remaining_balance + transaction['debit'] - transaction['credit']
        transaction['balance'] = remaining_balance
    
    # Get billing configuration if exists
    billing_config = None
    try:
        billing_config = TenantBillingConfiguration.objects.get(tenant=tenant, is_active=True)
    except TenantBillingConfiguration.DoesNotExist:
        pass
    
    # ============================================
    # PREPARE CONTEXT
    # ============================================
    
    context = {
        'tenant': tenant,
        'transactions': transactions,
        'financial_summary': financial_summary,
        
        # Keep backward compatibility
        'bills_total': bills_total,  # Sum of all total_amount fields
        'bills_count': bills_count,
        'total_receipts': total_receipts,
        'total_payments': total_payments,
        'voucher_count': voucher_count,
        'outstanding_balance': closing_balance,  # This is the remain_amount from get_tenant_balance
        'opening_balance': opening_balance,
        
        'period_name': period_name,
        'billing_config': billing_config,
        'generated_date': timezone.now(),
        'generated_by': request.user.full_name if hasattr(request.user, 'full_name') else 'Admin',
        'has_transactions': len(transactions) > 0,
    }
    
    # Render template
    template = get_template('adminapp/vouchers/tenant_statement_pdf.html')
    html = template.render(context)
    
    # Create PDF response
    response = HttpResponse(content_type='application/pdf')
    safe_tenant_name = tenant.company_name.replace(' ', '_').replace('/', '_')
    filename = f"tenant_statement_{safe_tenant_name}_{date_filter}_{today.strftime('%Y%m%d')}.pdf"
    response['Content-Disposition'] = f'inline; filename="{filename}"'
    
    # Generate PDF
    pisa_status = pisa.CreatePDF(
        io.BytesIO(html.encode("UTF-8")),
        dest=response,
        encoding='UTF-8'
    )
    
    if pisa_status.err:
        return HttpResponse(f'<h1>PDF Generation Error</h1><pre>{html}</pre>')
    
    return response




# ADMIN WORKINGS

from django.shortcuts import render
from django.db.models import Q, Sum, Count
from django.db.models.functions import TruncMonth
from datetime import datetime, timedelta
from collections import defaultdict
import json

def admin_dashboard(request):
    # Count incomplete freezing entries from both spot and local freezing
    incomplete_spot_freezing = FreezingEntrySpot.objects.filter(
        Q(freezing_status__iexact='Incomplete') | 
        Q(freezing_status__iexact='Pending') |
        Q(freezing_status__iexact='In Progress')
    ).count()
    
    incomplete_local_freezing = FreezingEntryLocal.objects.filter(
        Q(freezing_status__iexact='Incomplete') |
        Q(freezing_status__iexact='Pending') |
        Q(freezing_status__iexact='In Progress')
    ).count()
    
    # Total incomplete freezing count
    incomplete_freezing_count = incomplete_spot_freezing + incomplete_local_freezing
    
    # Total freezing entries
    total_freezing_entries = FreezingEntrySpot.objects.count() + FreezingEntryLocal.objects.count()
    
    # Calculate completed entries
    completed_today = total_freezing_entries - incomplete_freezing_count
    
    # ============ CHART DATA FOR SPOT FREEZING ============
    
    # Get current date and last 12 months
    today = datetime.now()
    twelve_months_ago = today - timedelta(days=365)
    
    # Monthly spot freezing data (last 12 months)
    monthly_data = FreezingEntrySpot.objects.filter(
        freezing_date__gte=twelve_months_ago
    ).annotate(
        month=TruncMonth('freezing_date')
    ).values('month').annotate(
        total_entries=Count('id'),
        complete_entries=Count('id', filter=Q(freezing_status__iexact='complete')),
        incomplete_entries=Count('id', filter=~Q(freezing_status__iexact='complete')),
        total_kg=Sum('total_kg'),
        total_usd=Sum('total_usd')
    ).order_by('month')
    
    # Prepare chart data
    chart_labels = []
    chart_complete = []
    chart_incomplete = []
    chart_kg = []
    chart_usd = []
    
    for data in monthly_data:
        month_name = data['month'].strftime('%b %Y')
        chart_labels.append(month_name)
        chart_complete.append(data['complete_entries'])
        chart_incomplete.append(data['incomplete_entries'])
        chart_kg.append(float(data['total_kg'] or 0))
        chart_usd.append(float(data['total_usd'] or 0))
    
    # Weekly data for last 8 weeks (SQLite-compatible approach)
    eight_weeks_ago = today - timedelta(weeks=8)
    weekly_entries_raw = FreezingEntrySpot.objects.filter(
        freezing_date__gte=eight_weeks_ago
    ).values('freezing_date', 'total_kg').order_by('freezing_date')
    
    # Group by date manually
    daily_data = defaultdict(lambda: {'entries': 0, 'kg': 0})
    for entry in weekly_entries_raw:
        date_str = entry['freezing_date'].strftime('%Y-%m-%d')
        daily_data[date_str]['entries'] += 1
        daily_data[date_str]['kg'] += float(entry['total_kg'] or 0)
    
    # Sort and prepare data
    weekly_labels = []
    weekly_entries = []
    weekly_kg = []
    for date_str in sorted(daily_data.keys()):
        date_obj = datetime.strptime(date_str, '%Y-%m-%d')
        weekly_labels.append(date_obj.strftime('%d %b'))
        weekly_entries.append(daily_data[date_str]['entries'])
        weekly_kg.append(daily_data[date_str]['kg'])
    
    # Status distribution for pie chart
    status_distribution = FreezingEntrySpot.objects.values('freezing_status').annotate(
        count=Count('id')
    )
    
    status_labels = []
    status_counts = []
    for status in status_distribution:
        status_labels.append(status['freezing_status'].title())
        status_counts.append(status['count'])
    
    # Top 5 items by quantity
    top_items = FreezingEntrySpotItem.objects.values(
        'item__name'
    ).annotate(
        total_kg=Sum('kg')
    ).order_by('-total_kg')[:5]
    
    top_item_names = [item['item__name'] for item in top_items]
    top_item_kg = [float(item['total_kg']) for item in top_items]
    
    # Other dashboard statistics
    total_subscribers = 1303
    total_sales = 1345
    total_orders = 576
    
    context = {
        'incomplete_freezing_count': incomplete_freezing_count,
        'total_freezing_entries': total_freezing_entries,
        'completed_today': completed_today,
        'incomplete_spot_freezing': incomplete_spot_freezing,
        'incomplete_local_freezing': incomplete_local_freezing,
        'total_subscribers': total_subscribers,
        'total_sales': total_sales,
        'total_orders': total_orders,
        
        # Chart data - convert to JSON for JavaScript
        'chart_labels': json.dumps(chart_labels),
        'chart_complete': json.dumps(chart_complete),
        'chart_incomplete': json.dumps(chart_incomplete),
        'chart_kg': json.dumps(chart_kg),
        'chart_usd': json.dumps(chart_usd),
        
        'weekly_labels': json.dumps(weekly_labels),
        'weekly_entries': json.dumps(weekly_entries),
        'weekly_kg': json.dumps(weekly_kg),
        
        'status_labels': json.dumps(status_labels),
        'status_counts': json.dumps(status_counts),
        
        'top_item_names': json.dumps(top_item_names),
        'top_item_kg': json.dumps(top_item_kg),
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

# temporary stock add 

# views.py - Function-based views for Stock management temporary
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.db import IntegrityError
from django.http import JsonResponse
from django.core.paginator import Paginator
from .models import Stock
from .forms import StockForm

def create_stock(request):
    """Create new stock entry"""
    if request.method == 'POST':
        form = StockForm(request.POST)
        if form.is_valid():
            try:
                stock = form.save()
                messages.success(request, f'Stock for {stock.item.name} created successfully!')
                return redirect('adminapp:list')
            except IntegrityError:
                messages.error(request, 'Stock with this combination already exists.')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = StockForm()
    
    context = {
        'form': form,
        'title': 'Create New Stock',
        'action': 'Create'
    }
    return render(request, 'adminapp/stock/create_stock.html', context)

def stock_list(request):
    """List all stocks with search and pagination"""
    stocks = Stock.objects.select_related(
        'store', 'brand', 'item', 'item_quality', 'freezing_category',
        'unit', 'glaze', 'species', 'item_grade'
    ).all()
    
    # Search functionality
    search_query = request.GET.get('search', '')
    if search_query:
        stocks = stocks.filter(
            item_name_icontains=search_query
        ) | stocks.filter(
            store_name_icontains=search_query
        ) | stocks.filter(
            brand_name_icontains=search_query
        )
    
    # Pagination
    paginator = Paginator(stocks, 10)  # 10 stocks per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'stocks': page_obj,
        'search_query': search_query,
        'total_stocks': stocks.count()
    }
    return render(request, 'adminapp/stock/stock_list.html', context)

def stock_detail(request, pk):
    """View detailed information about a stock"""
    stock = get_object_or_404(Stock, pk=pk)
    
    context = {
        'stock': stock
    }
    return render(request, 'adminapp/stock/stock_detail.html', context)

def update_stock(request, pk):
    """Update existing stock"""
    stock = get_object_or_404(Stock, pk=pk)
    
    if request.method == 'POST':
        form = StockForm(request.POST, instance=stock)
        if form.is_valid():
            try:
                updated_stock = form.save()
                messages.success(request, f'Stock for {updated_stock.item.name} updated successfully!')
                return redirect('adminapp:stock_detail', pk=updated_stock.pk)
            except IntegrityError:
                messages.error(request, 'Stock with this combination already exists.')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = StockForm(instance=stock)
    
    context = {
        'form': form,
        'stock': stock,
        'title': f'Update Stock - {stock.item.name}',
        'action': 'Update'
    }
    return render(request, 'adminapp/stock/update_stock.html', context)

def delete_stock(request, pk):
    """Delete stock entry"""
    stock = get_object_or_404(Stock, pk=pk)
    
    if request.method == 'POST':
        item_name = stock.item.name
        stock.delete()
        messages.success(request, f'Stock for {item_name} deleted successfully!')
        return redirect('adminapp:list')
    
    context = {
        'stock': stock
    }
    return render(request, 'adminapp/stock/delete_stock.html', context)

def stock_dashboard(request):
    """Dashboard with stock statistics"""
    total_stocks = Stock.objects.count()
    total_stores = Stock.objects.values('store').distinct().count()
    total_items = Stock.objects.values('item').distinct().count()
    
    # Recent stocks
    recent_stocks = Stock.objects.select_related(
        'store', 'item', 'brand'
    ).order_by('-id')[:5]
    
    # Low stock alerts (items with less than 10 kg)
    low_stock = Stock.objects.select_related(
        'store', 'item', 'brand'
    ).filter(kg_quantity__lt=10)[:5]
    
    context = {
        'total_stocks': total_stocks,
        'total_stores': total_stores,
        'total_items': total_items,
        'recent_stocks': recent_stocks,
        'low_stock': low_stock,
    }
    return render(request, 'adminapp/stock/dashboard.html', context)

def stock_search_ajax(request):
    """AJAX search for stocks"""
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        query = request.GET.get('q', '')
        if query:
            stocks = Stock.objects.select_related(
                'store', 'item', 'brand'
            ).filter(
                item_name_icontains=query
            )[:10]
            
            results = []
            for stock in stocks:
                results.append({
                    'id': stock.pk,
                    'item_name': stock.item.name,
                    'store_name': stock.store.name,
                    'brand_name': stock.brand.name,
                    'kg_quantity': str(stock.kg_quantity),
                    'url': f'/stock/{stock.pk}/'
                })
            
            return JsonResponse({'results': results})
    
    return JsonResponse({'results': []})





def spot_purchase_profit_loss_report(request):
    """
    Generate profit/loss report for spot purchases with comprehensive filters and ALL overhead calculations
    """
    from datetime import datetime, timedelta
    from django.db.models import Q, Sum, Count
    from decimal import Decimal
    from django.http import JsonResponse
    from django.shortcuts import render
    
    # Get all filter parameters
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    quick_filter = request.GET.get('quick_filter', '')
    
    # Basic filters
    selected_spots = request.GET.getlist('spots')
    selected_agents = request.GET.getlist('agents')
    selected_supervisors = request.GET.getlist('supervisors')
    
    # New comprehensive filters
    selected_items = request.GET.getlist('items')
    selected_species = request.GET.getlist('species')
    selected_item_categories = request.GET.getlist('item_categories')
    selected_item_qualities = request.GET.getlist('item_qualities')
    selected_item_types = request.GET.getlist('item_types')
    selected_item_grades = request.GET.getlist('item_grades')
    selected_item_brands = request.GET.getlist('item_brands')
    selected_freezing_categories = request.GET.getlist('freezing_categories')
    selected_processing_centers = request.GET.getlist('processing_centers')
    selected_stores = request.GET.getlist('stores')
    selected_packing_units = request.GET.getlist('packing_units')
    selected_glaze_percentages = request.GET.getlist('glaze_percentages')
    
    profit_filter = request.GET.get('profit_filter', 'all')  # all, profit, loss
    format_type = request.GET.get('format', 'html')  # html, json, print
    
    # Calculate dates based on quick filter or use today as default
    today = datetime.now().date()
    
    if quick_filter:
        start_date_obj, end_date_obj = calculate_quick_filter_dates(quick_filter, today)
        start_date = start_date_obj.strftime('%Y-%m-%d')
        end_date = end_date_obj.strftime('%Y-%m-%d')
    else:
        # Default to today if no dates specified
        if not start_date:
            start_date = today.strftime('%Y-%m-%d')
        if not end_date:
            end_date = today.strftime('%Y-%m-%d')
        
        try:
            start_date_obj = datetime.strptime(start_date, '%Y-%m-%d').date()
            end_date_obj = datetime.strptime(end_date, '%Y-%m-%d').date()
        except ValueError:
            error_msg = 'Invalid date format. Use YYYY-MM-DD'
            if format_type == 'json':
                return JsonResponse({'error': error_msg})
            else:
                context = build_filter_context(
                    error=error_msg,
                    report_data=[],
                    quick_filter=quick_filter,
                    start_date=start_date,
                    end_date=end_date
                )
                return render(request, 'spot_purchase_profit_loss_report.html', context)
    
    try:
        # Base query for spot purchases within date range
        spot_purchases = SpotPurchase.objects.filter(
            date__range=[start_date_obj, end_date_obj]
        ).prefetch_related('items', 'expense', 'agent', 'supervisor', 'spot')
        
        # Apply basic filters
        if selected_spots:
            spot_purchases = spot_purchases.filter(spot__id__in=selected_spots)
        if selected_agents:
            spot_purchases = spot_purchases.filter(agent__id__in=selected_agents)
        if selected_supervisors:
            spot_purchases = spot_purchases.filter(supervisor__id__in=selected_supervisors)
        
        # Apply item-level filters through freezing entries
        if any([selected_items, selected_species, selected_item_categories, selected_item_qualities,
                selected_item_types, selected_item_grades, selected_item_brands, 
                selected_freezing_categories, selected_processing_centers, selected_stores,
                selected_packing_units, selected_glaze_percentages]):
            
            # Get freezing entry IDs that match the filters
            freezing_query = FreezingEntrySpotItem.objects.all()
            
            if selected_items:
                freezing_query = freezing_query.filter(item__id__in=selected_items)
            if selected_species:
                freezing_query = freezing_query.filter(species__id__in=selected_species)
            if selected_item_qualities:
                freezing_query = freezing_query.filter(item_quality__id__in=selected_item_qualities)
            if selected_item_types:
                freezing_query = freezing_query.filter(peeling_type__id__in=selected_item_types)
            if selected_item_grades:
                freezing_query = freezing_query.filter(grade__id__in=selected_item_grades)
            if selected_item_brands:
                freezing_query = freezing_query.filter(brand__id__in=selected_item_brands)
            if selected_freezing_categories:
                freezing_query = freezing_query.filter(freezing_category__id__in=selected_freezing_categories)
            if selected_processing_centers:
                freezing_query = freezing_query.filter(processing_center__id__in=selected_processing_centers)
            if selected_stores:
                freezing_query = freezing_query.filter(store__id__in=selected_stores)
            if selected_packing_units:
                freezing_query = freezing_query.filter(unit__id__in=selected_packing_units)
            if selected_glaze_percentages:
                freezing_query = freezing_query.filter(glaze__id__in=selected_glaze_percentages)
            
            # Filter by item categories through item relationship
            if selected_item_categories:
                freezing_query = freezing_query.filter(item__category__id__in=selected_item_categories)
            
            # Get unique spot purchase IDs from matching freezing entries
            matching_spot_purchase_ids = freezing_query.values_list(
                'freezing_entry__spot__id', flat=True
            ).distinct()
            
            # Filter spot purchases to only those with matching freezing entries
            spot_purchases = spot_purchases.filter(id__in=matching_spot_purchase_ids)
        
        if not spot_purchases.exists():
            message = f'No spot purchases found for the selected criteria'
            if format_type == 'json':
                return JsonResponse({'message': message, 'total_purchases': 0})
            else:
                context = build_filter_context(
                    message=message,
                    report_data=[],
                    quick_filter=quick_filter,
                    start_date=start_date,
                    end_date=end_date,
                    selected_spots=selected_spots,
                    selected_agents=selected_agents,
                    selected_supervisors=selected_supervisors,
                    selected_items=selected_items,
                    selected_species=selected_species,
                    selected_item_categories=selected_item_categories,
                    selected_item_qualities=selected_item_qualities,
                    selected_item_types=selected_item_types,
                    selected_item_grades=selected_item_grades,
                    selected_item_brands=selected_item_brands,
                    selected_freezing_categories=selected_freezing_categories,
                    selected_processing_centers=selected_processing_centers,
                    selected_stores=selected_stores,
                    selected_packing_units=selected_packing_units,
                    selected_glaze_percentages=selected_glaze_percentages,
                    profit_filter=profit_filter
                )
                return render(request, 'spot_purchase_profit_loss_report.html', context)
        
        # Get ALL overhead totals (active records only)
        purchase_overhead_total = PurchaseOverhead.objects.filter(
            is_active=True
        ).aggregate(total=Sum('other_expenses'))['total'] or Decimal('0.00')
        
        peeling_overhead_total = PeelingOverhead.objects.filter(
            is_active=True
        ).aggregate(total=Sum('other_expenses'))['total'] or Decimal('0.00')
        
        processing_overhead_total = ProcessingOverhead.objects.filter(
            is_active=True
        ).aggregate(total=Sum('amount'))['total'] or Decimal('0.00')
        
        shipment_overhead_total = ShipmentOverhead.objects.filter(
            is_active=True
        ).aggregate(total=Sum('amount'))['total'] or Decimal('0.00')
        
        # Calculate profit/loss for each purchase
        report_data = []
        summary = {
            'total_purchases': 0,
            'total_purchase_amount': Decimal('0.00'),
            'total_purchase_overhead': Decimal('0.00'),
            'total_peeling_expenses': Decimal('0.00'),
            'total_peeling_overhead': Decimal('0.00'),
            'total_processing_overhead': Decimal('0.00'),
            'total_shipment_overhead': Decimal('0.00'),
            'total_freezing_tariff': Decimal('0.00'),
            'total_cost': Decimal('0.00'),
            'total_revenue': Decimal('0.00'),
            'total_profit_loss': Decimal('0.00'),
            'profit_count': 0,
            'loss_count': 0,
            'break_even_count': 0
        }
        
        for purchase in spot_purchases:
            # Get purchase cost
            purchase_cost = purchase.total_purchase_amount or Decimal('0.00')
            
            # Calculate peeling expenses
            peeling_cost = Decimal('0.00')
            freezing_entries = FreezingEntrySpot.objects.filter(
                spot=purchase
            ).prefetch_related('items__shed', 'items__item', 'items__peeling_type')
            
            for entry in freezing_entries:
                for item in entry.items.all():
                    if item.shed and item.peeling_type:
                        try:
                            shed_item = ShedItem.objects.get(
                                shed=item.shed,
                                item=item.item,
                                item_type=item.peeling_type
                            )
                            peeling_cost += item.kg * shed_item.amount
                        except ShedItem.DoesNotExist:
                            continue
            
            # Calculate freezing revenue and collect total kg
            freezing_revenue = Decimal('0.00')
            total_kg = Decimal('0.00')
            total_freezing_tariff = Decimal('0.00')
            peeling_kg = Decimal('0.00')
            
            for entry in freezing_entries:
                for item in entry.items.all():
                    item_revenue = item.usd_rate_item_to_inr or Decimal('0.00')
                    freezing_revenue += item_revenue
                    total_kg += item.kg or Decimal('0.00')
                    
                    # Track peeling kg separately
                    if item.shed and item.peeling_type:
                        peeling_kg += item.kg or Decimal('0.00')
                    
                    # Calculate freezing category tariff (only for active categories)
                    if item.freezing_category and item.freezing_category.is_active and item.freezing_category.tariff:
                        tariff_cost = (item.kg or Decimal('0.00')) * Decimal(str(item.freezing_category.tariff))
                        total_freezing_tariff += tariff_cost
            
            # Calculate ALL overheads for this purchase
            # 1. Purchase Overhead (applied to purchase quantity)
            purchase_quantity = purchase.total_quantity or Decimal('0.00')
            purchase_overhead_amount = purchase_overhead_total if purchase_quantity > 0 else Decimal('0.00')
            
            # 2. Peeling Overhead (applied to peeled kg only)
            peeling_overhead_amount = peeling_overhead_total if peeling_kg > 0 else Decimal('0.00')
            
            # 3. Processing Overhead (applied to total processed kg)
            processing_overhead_amount = total_kg * processing_overhead_total
            
            # 4. Shipment Overhead (applied to total kg)
            shipment_overhead_amount = shipment_overhead_total if total_kg > 0 else Decimal('0.00')
            
            # Calculate total cost including ALL overheads
            total_cost = (
                purchase_cost + 
                purchase_overhead_amount + 
                peeling_cost + 
                peeling_overhead_amount + 
                processing_overhead_amount + 
                shipment_overhead_amount + 
                total_freezing_tariff
            )
            
            # Calculate profit/loss
            profit_loss = freezing_revenue - total_cost
            
            # Calculate profit percentage
            if total_cost > 0:
                profit_percentage = (profit_loss / total_cost * 100)
            else:
                profit_percentage = 0
            
            # Determine profit status
            if profit_loss > 0:
                profit_status = 'Profit'
                summary['profit_count'] += 1
            elif profit_loss < 0:
                profit_status = 'Loss'
                summary['loss_count'] += 1
            else:
                profit_status = 'Break Even'
                summary['break_even_count'] += 1
            
            # Apply profit filter
            if profit_filter == 'profit' and profit_loss <= 0:
                continue
            elif profit_filter == 'loss' and profit_loss >= 0:
                continue
            
            purchase_data = {
                'id': purchase.id,
                'date': purchase.date,
                'voucher_number': purchase.voucher_number,
                'spot_name': purchase.spot.location_name if purchase.spot else 'N/A',
                'agent_name': purchase.agent.name if purchase.agent else 'N/A',
                'supervisor_name': purchase.supervisor.name if purchase.supervisor else 'N/A',
                'purchase_amount': float(purchase_cost),
                'purchase_overhead': float(purchase_overhead_amount),
                'peeling_expenses': float(peeling_cost),
                'peeling_overhead': float(peeling_overhead_amount),
                'processing_overhead': float(processing_overhead_amount),
                'shipment_overhead': float(shipment_overhead_amount),
                'freezing_tariff': float(total_freezing_tariff),
                'total_cost': float(total_cost),
                'freezing_revenue': float(freezing_revenue),
                'profit_loss': float(profit_loss),
                'profit_percentage': float(profit_percentage),
                'profit_status': profit_status,
                'freezing_entries_count': freezing_entries.count(),
                'total_items': sum(entry.items.count() for entry in freezing_entries),
                'total_kg': float(total_kg),
                'peeling_kg': float(peeling_kg)
            }
            
            report_data.append(purchase_data)
            
            # Update summary
            summary['total_purchase_amount'] += purchase_cost
            summary['total_purchase_overhead'] += purchase_overhead_amount
            summary['total_peeling_expenses'] += peeling_cost
            summary['total_peeling_overhead'] += peeling_overhead_amount
            summary['total_processing_overhead'] += processing_overhead_amount
            summary['total_shipment_overhead'] += shipment_overhead_amount
            summary['total_freezing_tariff'] += total_freezing_tariff
            summary['total_cost'] += total_cost
            summary['total_revenue'] += freezing_revenue
            summary['total_profit_loss'] += profit_loss
        
        # Calculate final summary
        summary['total_purchases'] = len(report_data)
        if summary['total_cost'] > 0:
            summary['overall_profit_margin'] = float(summary['total_profit_loss'] / summary['total_cost'] * 100)
        else:
            summary['overall_profit_margin'] = 0
        
        # Convert Decimal to float for JSON serialization
        for key in ['total_purchase_amount', 'total_purchase_overhead', 'total_peeling_expenses', 
                   'total_peeling_overhead', 'total_processing_overhead', 'total_shipment_overhead',
                   'total_freezing_tariff', 'total_cost', 'total_revenue', 'total_profit_loss']:
            summary[key] = float(summary[key])
        
        # Add overhead rates to summary
        summary['purchase_overhead_rate'] = float(purchase_overhead_total)
        summary['peeling_overhead_rate'] = float(peeling_overhead_total)
        summary['processing_overhead_rate'] = float(processing_overhead_total)
        summary['shipment_overhead_rate'] = float(shipment_overhead_total)
        
        # Sort by date (newest first)
        report_data.sort(key=lambda x: x['date'], reverse=True)
        
        # Return based on format
        if format_type == 'json':
            return JsonResponse({
                'success': True,
                'date_range': {'start': start_date, 'end': end_date},
                'summary': summary,
                'data': report_data,
                'filters': {
                    'spots': selected_spots,
                    'agents': selected_agents,
                    'supervisors': selected_supervisors,
                    'items': selected_items,
                    'species': selected_species,
                    'item_categories': selected_item_categories,
                    'item_qualities': selected_item_qualities,
                    'item_types': selected_item_types,
                    'item_grades': selected_item_grades,
                    'item_brands': selected_item_brands,
                    'freezing_categories': selected_freezing_categories,
                    'processing_centers': selected_processing_centers,
                    'stores': selected_stores,
                    'packing_units': selected_packing_units,
                    'glaze_percentages': selected_glaze_percentages,
                    'profit_filter': profit_filter,
                    'quick_filter': quick_filter
                }
            })
        
        # Build full context for template
        context = build_filter_context(
            report_data=report_data,
            summary=summary,
            quick_filter=quick_filter,
            start_date=start_date,
            end_date=end_date,
            selected_spots=selected_spots,
            selected_agents=selected_agents,
            selected_supervisors=selected_supervisors,
            selected_items=selected_items,
            selected_species=selected_species,
            selected_item_categories=selected_item_categories,
            selected_item_qualities=selected_item_qualities,
            selected_item_types=selected_item_types,
            selected_item_grades=selected_item_grades,
            selected_item_brands=selected_item_brands,
            selected_freezing_categories=selected_freezing_categories,
            selected_processing_centers=selected_processing_centers,
            selected_stores=selected_stores,
            selected_packing_units=selected_packing_units,
            selected_glaze_percentages=selected_glaze_percentages,
            profit_filter=profit_filter,
            is_print=(format_type == 'print')
        )
        
        template = 'spot_purchase_profit_loss_report_print.html' if format_type == 'print' else 'spot_purchase_profit_loss_report.html'
        return render(request, template, context)
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        error_msg = f'An error occurred: {str(e)}'
        if format_type == 'json':
            return JsonResponse({'error': error_msg})
        else:
            context = build_filter_context(
                error=error_msg,
                report_data=[],
                quick_filter=quick_filter,
                start_date=start_date,
                end_date=end_date
            )
            return render(request, 'spot_purchase_profit_loss_report.html', context)

def spot_purchase_profit_loss_report_print(request):
    """
    Generate comprehensive print report with correct calculations
    """
    
    # Get filter parameters
    quick_filter = request.GET.get('quick_filter', '')
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    
    # Filters
    selected_spots = request.GET.getlist('spots')
    selected_agents = request.GET.getlist('agents')
    selected_supervisors = request.GET.getlist('supervisors')
    selected_items = request.GET.getlist('items')
    selected_species = request.GET.getlist('species')
    selected_item_categories = request.GET.getlist('item_categories')
    selected_item_qualities = request.GET.getlist('item_qualities')
    selected_item_types = request.GET.getlist('item_types')
    selected_item_grades = request.GET.getlist('item_grades')
    selected_item_brands = request.GET.getlist('item_brands')
    selected_freezing_categories = request.GET.getlist('freezing_categories')
    selected_processing_centers = request.GET.getlist('processing_centers')
    selected_stores = request.GET.getlist('stores')
    selected_packing_units = request.GET.getlist('packing_units')
    selected_glaze_percentages = request.GET.getlist('glaze_percentages')
    profit_filter = request.GET.get('profit_filter', 'all')
    
    # Calculate dates
    today = datetime.now().date()
    
    if quick_filter:
        start_date_obj, end_date_obj = calculate_quick_filter_dates(quick_filter, today)
        start_date = start_date_obj.strftime('%Y-%m-%d')
        end_date = end_date_obj.strftime('%Y-%m-%d')
    else:
        if not start_date:
            start_date = today.strftime('%Y-%m-%d')
        if not end_date:
            end_date = today.strftime('%Y-%m-%d')
        
        try:
            start_date_obj = datetime.strptime(start_date, '%Y-%m-%d').date()
            end_date_obj = datetime.strptime(end_date, '%Y-%m-%d').date()
        except ValueError:
            context = {'error': 'Invalid date format'}
            return render(request, 'spot_purchase_profit_loss_report_print.html', context)
    
    try:
        # Get USD rate from Settings
        try:
            active_settings = Settings.objects.filter(is_active=True).first()
            usd_rate = active_settings.dollar_rate_to_inr if active_settings else Decimal('84.00')
        except:
            usd_rate = Decimal('84.00')
        
        # Base query
        spot_purchases = SpotPurchase.objects.filter(
            date__range=[start_date_obj, end_date_obj]
        ).prefetch_related(
            'items__item',
            'expense',
            'agent',
            'supervisor',
            'spot'
        ).select_related('spot', 'agent', 'supervisor')
        
        # Apply filters
        if selected_spots:
            spot_purchases = spot_purchases.filter(spot__id__in=selected_spots)
        if selected_agents:
            spot_purchases = spot_purchases.filter(agent__id__in=selected_agents)
        if selected_supervisors:
            spot_purchases = spot_purchases.filter(supervisor__id__in=selected_supervisors)
        
        # Apply item-level filters
        if any([selected_items, selected_species, selected_item_categories, selected_item_qualities,
                selected_item_types, selected_item_grades, selected_item_brands,
                selected_freezing_categories, selected_processing_centers, selected_stores,
                selected_packing_units, selected_glaze_percentages]):
            
            freezing_query = FreezingEntrySpotItem.objects.all()
            
            if selected_items:
                freezing_query = freezing_query.filter(item__id__in=selected_items)
            if selected_species:
                freezing_query = freezing_query.filter(species__id__in=selected_species)
            if selected_item_qualities:
                freezing_query = freezing_query.filter(item_quality__id__in=selected_item_qualities)
            if selected_item_types:
                freezing_query = freezing_query.filter(peeling_type__id__in=selected_item_types)
            if selected_item_grades:
                freezing_query = freezing_query.filter(grade__id__in=selected_item_grades)
            if selected_item_brands:
                freezing_query = freezing_query.filter(brand__id__in=selected_item_brands)
            if selected_freezing_categories:
                freezing_query = freezing_query.filter(freezing_category__id__in=selected_freezing_categories)
            if selected_processing_centers:
                freezing_query = freezing_query.filter(processing_center__id__in=selected_processing_centers)
            if selected_stores:
                freezing_query = freezing_query.filter(store__id__in=selected_stores)
            if selected_packing_units:
                freezing_query = freezing_query.filter(unit__id__in=selected_packing_units)
            if selected_glaze_percentages:
                freezing_query = freezing_query.filter(glaze__id__in=selected_glaze_percentages)
            if selected_item_categories:
                freezing_query = freezing_query.filter(item__category__id__in=selected_item_categories)
            
            matching_spot_purchase_ids = freezing_query.values_list(
                'freezing_entry__spot__id', flat=True
            ).distinct()
            
            spot_purchases = spot_purchases.filter(id__in=matching_spot_purchase_ids)
        
        if not spot_purchases.exists():
            context = {
                'message': 'No spot purchases found',
                'report_data': [],
                'usd_rate': float(usd_rate),
                'date_range_text': get_date_range_text(quick_filter, start_date, end_date)
            }
            return render(request, 'spot_purchase_profit_loss_report_print.html', context)
        
        # Get overhead totals
        purchase_overhead_total = PurchaseOverhead.objects.filter(
            is_active=True
        ).aggregate(total=Sum('other_expenses'))['total'] or Decimal('0.00')
        
        peeling_overhead_total = PeelingOverhead.objects.filter(
            is_active=True
        ).aggregate(total=Sum('other_expenses'))['total'] or Decimal('0.00')
        
        processing_overhead_total = ProcessingOverhead.objects.filter(
            is_active=True
        ).aggregate(total=Sum('amount'))['total'] or Decimal('0.00')
        
        shipment_overhead_total = ShipmentOverhead.objects.filter(
            is_active=True
        ).aggregate(total=Sum('amount'))['total'] or Decimal('0.00')
        
        # Process each purchase
        report_data = []
        summary = {
            'total_purchases': 0,
            'total_purchase_quantity': Decimal('0.00'),
            'total_purchase_amount': Decimal('0.00'),
            'total_purchase_expense': Decimal('0.00'),
            'total_purchase_overhead': Decimal('0.00'),
            'total_peeling_expenses': Decimal('0.00'),
            'total_peeling_overhead': Decimal('0.00'),
            'total_processing_overhead': Decimal('0.00'),
            'total_shipment_overhead': Decimal('0.00'),
            'total_all_overheads': Decimal('0.00'),
            'total_freezing_tariff': Decimal('0.00'),
            'total_cost': Decimal('0.00'),
            'total_revenue': Decimal('0.00'),
            'total_profit_loss': Decimal('0.00'),
            'profit_count': 0,
            'loss_count': 0,
            'break_even_count': 0
        }
        
        for purchase in spot_purchases:
            # CORRECT CALCULATIONS AS PER YOUR SPECIFICATIONS
            
            # 1. PURCHASE QUANTITY = total_quantity
            purchase_quantity = purchase.total_quantity or Decimal('0.00')
            
            # 2. PURCHASE AMOUNT = total_amount
            purchase_amount = purchase.total_amount or Decimal('0.00')
            
            # 3. TOTAL PURCHASE EXPENSE = total_expense from expense table
            purchase_expense = Decimal('0.00')
            if hasattr(purchase, 'expense') and purchase.expense:
                purchase_expense = purchase.expense.total_expense or Decimal('0.00')
            
            # 4. TOTAL COST = total_amount + total_expense
            total_purchase_cost = purchase_amount + purchase_expense
            
            # 5. COST/KG = (total_amount + total_expense) / total_quantity
            cost_per_kg = Decimal('0.00')
            if purchase_quantity > 0:
                cost_per_kg = total_purchase_cost / purchase_quantity
            
            # 6. PURCHASE RATE/KG = total_amount / total_quantity
            purchase_rate_per_kg = Decimal('0.00')
            if purchase_quantity > 0:
                purchase_rate_per_kg = purchase_amount / purchase_quantity
            
            # Peeling expenses
            peeling_cost = Decimal('0.00')
            peeling_breakdown = []
            
            freezing_entries = FreezingEntrySpot.objects.filter(
                spot=purchase
            ).prefetch_related(
                'items__shed',
                'items__item',
                'items__item_quality',
                'items__species',
                'items__peeling_type',
                'items__grade__species',
                'items__processing_center',
                'items__store',
                'items__unit',
                'items__glaze',
                'items__freezing_category',
                'items__brand'
            )
            
            # Calculate peeling costs
            peeling_kg = Decimal('0.00')
            for entry in freezing_entries:
                for item in entry.items.all():
                    if item.shed and item.peeling_type:
                        try:
                            shed_item = ShedItem.objects.get(
                                shed=item.shed,
                                item=item.item,
                                item_type=item.peeling_type
                            )
                            item_peeling_cost = (item.kg or Decimal('0.00')) * shed_item.amount
                            peeling_cost += item_peeling_cost
                            peeling_kg += item.kg or Decimal('0.00')
                            
                            peeling_breakdown.append({
                                'shed_name': item.shed.name,
                                'item_type': item.peeling_type.name,
                                'quantity': float(item.kg or 0),
                                'rate': float(shed_item.amount),
                                'amount': float(item_peeling_cost)
                            })
                        except ShedItem.DoesNotExist:
                            continue
            
            # Calculate freezing revenue and items FROM FREEZING DB
            freezing_revenue = Decimal('0.00')
            freezing_items = []
            total_freezing_kg = Decimal('0.00')  # This is TOTAL PRODUCTION QUANTITY
            total_freezing_usd = Decimal('0.00')
            total_freezing_tariff = Decimal('0.00')
            freezing_tariff_breakdown = []
            processing_details = []
            
            for entry in freezing_entries:
                for item in entry.items.all():
                    item_revenue = item.usd_rate_item_to_inr or Decimal('0.00')
                    item_usd = item.usd_rate_item or Decimal('0.00')
                    freezing_revenue += item_revenue
                    total_freezing_usd += item_usd
                    total_freezing_kg += item.kg or Decimal('0.00')
                    
                    # Freezing tariff
                    item_tariff_cost = Decimal('0.00')
                    if (item.freezing_category and 
                        item.freezing_category.is_active and 
                        hasattr(item.freezing_category, 'tariff') and 
                        item.freezing_category.tariff):
                        item_tariff_cost = (item.kg or Decimal('0.00')) * Decimal(str(item.freezing_category.tariff))
                        total_freezing_tariff += item_tariff_cost
                        
                        # Tariff breakdown
                        existing = next((t for t in freezing_tariff_breakdown 
                                       if t['category_name'] == item.freezing_category.name), None)
                        if existing:
                            existing['quantity'] += float(item.kg or 0)
                            existing['amount'] += float(item_tariff_cost)
                        else:
                            freezing_tariff_breakdown.append({
                                'category_name': item.freezing_category.name,
                                'tariff_rate': float(item.freezing_category.tariff),
                                'quantity': float(item.kg or 0),
                                'amount': float(item_tariff_cost)
                            })
                    
                    # Processing details
                    processing_details.append({
                        'item_quality': item.item_quality.quality if item.item_quality else 'N/A',
                        'packing': f"{item.unit.unit_code if item.unit else ''} - {item.glaze.percentage if item.glaze else ''}%",
                        'unit': item.unit.unit_code if item.unit else 'N/A',
                        'grade': f"{item.peeling_type.name if item.peeling_type else ''}, {item.grade.grade if item.grade else ''}",
                        'total_slab': float(item.slab_quantity or 0),
                        'total_quantity': float(item.kg or 0),
                        'price_usd': float(item.usd_rate_per_kg or 0),
                        'amount_usd': float(item.usd_rate_item or 0),
                        'amount_inr': float(item.usd_rate_item_to_inr or 0)
                    })
                    
                    # Freezing items
                    freezing_items.append({
                        'item_name': item.item.name if item.item else 'N/A',
                        'item_quality': item.item_quality.quality if item.item_quality else 'N/A',
                        'species': item.species.name if item.species else 'N/A',
                        'peeling_type': item.peeling_type.name if item.peeling_type else 'N/A',
                        'shed_name': item.shed.name if item.shed else 'N/A',
                        'processing_center': item.processing_center.name if item.processing_center else 'N/A',
                        'store': item.store.name if item.store else 'N/A',
                        'freezing_category': item.freezing_category.name if item.freezing_category else 'N/A',
                        'kg': float(item.kg or 0),
                        'usd_rate_per_kg': float(item.usd_rate_per_kg or 0),
                        'usd_rate_item': float(item.usd_rate_item or 0),
                        'usd_rate_item_to_inr': float(item.usd_rate_item_to_inr or 0),
                        'yield_percentage': float(item.yield_percentage or 0),
                        'slab_quantity': float(item.slab_quantity or 0),
                        'c_s_quantity': float(item.c_s_quantity or 0),
                        'unit': item.unit.unit_code if item.unit else 'N/A',
                        'glaze': f"{item.glaze.percentage}%" if item.glaze else 'N/A',
                        'brand': item.brand.name if item.brand else 'N/A',
                        'grade': f"{item.grade.species.name} - {item.grade.grade}" if item.grade and item.grade.species else 'N/A',
                        'tariff_cost': float(item_tariff_cost)
                    })
            
            # Calculate overheads - ALL rates multiply by TOTAL PRODUCTION QUANTITY (total_freezing_kg)
            purchase_overhead_amount = total_freezing_kg * purchase_overhead_total
            peeling_overhead_amount = total_freezing_kg * peeling_overhead_total
            processing_overhead_amount = total_freezing_kg * processing_overhead_total
            shipment_overhead_amount = total_freezing_kg * shipment_overhead_total
            
            # TOTAL PROCESSING EXP = sum of all overheads
            total_all_overheads = (
                purchase_overhead_amount +
                peeling_overhead_amount +
                processing_overhead_amount +
                shipment_overhead_amount
            )
            
            # INCOME = TOTAL AMOUNT/INR - TOTAL PROCESSING EXP
            income = freezing_revenue - total_all_overheads
            
            # PROCESSING OVERHEADS PER KG = sum of overheads / TOTAL PRODUCTION QUANTITY
            processing_overhead_per_kg = Decimal('0.00')
            if total_freezing_kg > 0:
                processing_overhead_per_kg = total_all_overheads / total_freezing_kg
            
            # Calculate total slabs for SUBTOTAL row
            total_slabs = sum(detail['total_slab'] for detail in processing_details)
            
            # Calculate average price USD for SUBTOTAL
            avg_price_usd = Decimal('0.00')
            if total_freezing_kg > 0:
                avg_price_usd = total_freezing_usd / total_freezing_kg
            
            # Grand Total Cost
            grand_total_cost = (
                total_purchase_cost +
                purchase_overhead_amount +
                peeling_cost +
                peeling_overhead_amount +
                processing_overhead_amount +
                shipment_overhead_amount +
                total_freezing_tariff
            )
            
            # Total Profit/Loss
            total_profit_loss = freezing_revenue - grand_total_cost
            
            # Profit/Loss Per KG = total_profit_loss / total_freezing_kg
            profit_loss_per_kg = Decimal('0.00')
            if total_freezing_kg > 0:
                profit_loss_per_kg = total_profit_loss / total_freezing_kg
            
            if grand_total_cost > 0:
                profit_percentage = (total_profit_loss / grand_total_cost * 100)
            else:
                profit_percentage = Decimal('0.00')
            
            if total_profit_loss > 0:
                profit_status = 'Profit'
                summary['profit_count'] += 1
            elif total_profit_loss < 0:
                profit_status = 'Loss'
                summary['loss_count'] += 1
            else:
                profit_status = 'Break Even'
                summary['break_even_count'] += 1
            
            # Apply profit filter
            if profit_filter == 'profit' and total_profit_loss <= 0:
                continue
            elif profit_filter == 'loss' and total_profit_loss >= 0:
                continue
            
            # Get purchase items with names
            purchase_items = []
            purchase_item_names = []
            for item in purchase.items.all():
                item_name = item.item.name if item.item else 'N/A'
                purchase_items.append({
                    'item_name': item_name,
                    'quantity': float(item.quantity or 0),
                    'boxes': float(item.boxes or 0),
                    'rate': float(item.rate or 0),
                    'total_rate': float(item.total_rate or 0),
                    'amount': float(item.amount or 0)
                })
                if item.item and item.item.name and item.item.name not in purchase_item_names:
                    purchase_item_names.append(item.item.name)
            
            # Create comma-separated string of item names
            purchase_item_names_str = ', '.join(purchase_item_names) if purchase_item_names else 'N/A'
            
            # Expense details
            expense_details = {}
            if hasattr(purchase, 'expense') and purchase.expense:
                expense = purchase.expense
                expense_details = {
                    'ice_expense': float(expense.ice_expense or 0),
                    'vehicle_rent': float(expense.vehicle_rent or 0),
                    'loading_and_unloading': float(expense.loading_and_unloading or 0),
                    'peeling_charge': float(expense.peeling_charge or 0),
                    'other_expense': float(expense.other_expense or 0),
                    'total_expense': float(expense.total_expense or 0)
                }
            
            # Overhead breakdown
            overhead_breakdown = [
                {'type': 'Purchase Overhead', 'rate': float(purchase_overhead_total), 'amount': float(purchase_overhead_amount)},
                {'type': 'Peeling Overhead', 'rate': float(peeling_overhead_total), 'amount': float(peeling_overhead_amount)},
                {'type': 'Processing Overhead', 'rate': float(processing_overhead_total), 'amount': float(processing_overhead_amount)},
                {'type': 'Shipment Overhead', 'rate': float(shipment_overhead_total), 'amount': float(shipment_overhead_amount)},
            ]
            
            purchase_data = {
                'id': purchase.id,
                'date': purchase.date,
                'voucher_number': purchase.voucher_number or '',
                'spot_name': purchase.spot.location_name if purchase.spot else 'N/A',
                'spot_agent': purchase.agent.name if purchase.agent else 'N/A',
                'spot_supervisor': purchase.supervisor.name if purchase.supervisor else 'N/A',
                
                # Correct calculations
                'purchase_quantity': float(purchase_quantity),
                'purchase_amount': float(purchase_amount),
                'purchase_expense': float(purchase_expense),
                'total_purchase_cost': float(total_purchase_cost),
                'cost_per_kg': float(cost_per_kg),
                'purchase_rate_per_kg': float(purchase_rate_per_kg),
                
                'purchase_overhead': float(purchase_overhead_amount),
                'peeling_expenses': float(peeling_cost),
                'peeling_overhead': float(peeling_overhead_amount),
                'processing_overhead': float(processing_overhead_amount),
                'shipment_overhead': float(shipment_overhead_amount),
                'freezing_tariff': float(total_freezing_tariff),
                
                # NEW CALCULATED FIELDS
                'total_all_overheads': float(total_all_overheads),
                'income': float(income),
                'processing_overhead_per_kg': float(processing_overhead_per_kg),
                'total_slabs': total_slabs,
                'avg_price_usd': float(avg_price_usd),
                'total_kg_processed': float(total_freezing_kg),
                
                'grand_total_cost': float(grand_total_cost),
                'freezing_revenue': float(freezing_revenue),
                'total_freezing_usd': float(total_freezing_usd),
                'total_freezing_kg': float(total_freezing_kg),
                
                'total_profit_loss': float(total_profit_loss),
                'profit_loss_per_kg': float(profit_loss_per_kg),
                'profit_percentage': float(profit_percentage),
                'profit_status': profit_status,
                
                'peeling_kg': float(peeling_kg),
                
                # Detailed breakdowns
                'purchase_items': purchase_items,
                'purchase_item_names': purchase_item_names_str,
                'expense_details': expense_details,
                'peeling_breakdown': peeling_breakdown,
                'freezing_items': freezing_items,
                'freezing_tariff_breakdown': freezing_tariff_breakdown,
                'overhead_breakdown': overhead_breakdown,
                'processing_details': processing_details,
                'processing_overhead_rate': float(processing_overhead_total)
            }
            
            report_data.append(purchase_data)
            
            # Update summary
            summary['total_purchase_quantity'] += purchase_quantity
            summary['total_purchase_amount'] += purchase_amount
            summary['total_purchase_expense'] += purchase_expense
            summary['total_purchase_overhead'] += purchase_overhead_amount
            summary['total_peeling_expenses'] += peeling_cost
            summary['total_peeling_overhead'] += peeling_overhead_amount
            summary['total_processing_overhead'] += processing_overhead_amount
            summary['total_shipment_overhead'] += shipment_overhead_amount
            summary['total_all_overheads'] += total_all_overheads
            summary['total_freezing_tariff'] += total_freezing_tariff
            summary['total_cost'] += grand_total_cost
            summary['total_revenue'] += freezing_revenue
            summary['total_profit_loss'] += total_profit_loss
        
        # Calculate summary
        summary['total_purchases'] = len(report_data)
        if summary['total_cost'] > 0:
            summary['overall_profit_margin'] = float(summary['total_profit_loss'] / summary['total_cost'] * 100)
        else:
            summary['overall_profit_margin'] = 0.0
        
        # Convert Decimal to float
        for key in ['total_purchase_quantity', 'total_purchase_amount', 'total_purchase_expense',
                   'total_purchase_overhead', 'total_peeling_expenses',
                   'total_peeling_overhead', 'total_processing_overhead', 'total_shipment_overhead',
                   'total_all_overheads', 'total_freezing_tariff', 'total_cost', 'total_revenue', 'total_profit_loss']:
            summary[key] = float(summary[key])
        
        # Add overhead rates
        summary['purchase_overhead_rate'] = float(purchase_overhead_total)
        summary['peeling_overhead_rate'] = float(peeling_overhead_total)
        summary['processing_overhead_rate'] = float(processing_overhead_total)
        summary['shipment_overhead_rate'] = float(shipment_overhead_total)
        
        # Sort by date
        report_data.sort(key=lambda x: x['date'], reverse=True)
        
        context = {
            'report_data': report_data,
            'summary': summary,
            'usd_rate': float(usd_rate),
            'start_date': start_date,
            'end_date': end_date,
            'date_range_text': get_date_range_text(quick_filter, start_date, end_date),
        }
        
        return render(request, 'spot_purchase_profit_loss_report_print.html', context)
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        context = {
            'error': f'An error occurred: {str(e)}',
            'report_data': [],
            'usd_rate': float(usd_rate) if 'usd_rate' in locals() else 84.00,
            'date_range_text': get_date_range_text(quick_filter, start_date, end_date)
        }
        return render(request, 'spot_purchase_profit_loss_report_print.html', context)

def build_filter_context(**kwargs):
    """
    Helper function to build context with all filter options.
    Accepts any keyword arguments and merges them with defaults.
    """
    # Get filter options (only active records where applicable)
    spots = PurchasingSpot.objects.all().order_by('location_name')
    agents = PurchasingAgent.objects.all().order_by('name')
    supervisors = PurchasingSupervisor.objects.filter(is_active=True).order_by('name')
    items = Item.objects.all().order_by('name')
    all_species = Species.objects.all().order_by('name')
    item_categories = ItemCategory.objects.all().order_by('name')
    item_qualities = ItemQuality.objects.all().order_by('quality')
    item_types = ItemType.objects.all().order_by('name')
    item_grades = ItemGrade.objects.all().order_by('grade')
    item_brands = ItemBrand.objects.all().order_by('name')
    freezing_categories = FreezingCategory.objects.filter(is_active=True).order_by('name')
    processing_centers = ProcessingCenter.objects.filter(is_active=True).order_by('name')
    stores = Store.objects.filter(is_active=True).order_by('name')
    packing_units = PackingUnit.objects.all().order_by('unit_code')
    glaze_percentages = GlazePercentage.objects.all().order_by('percentage')
    
    # Extract date parameters for date_range_text
    quick_filter = kwargs.get('quick_filter', '')
    start_date = kwargs.get('start_date', '')
    end_date = kwargs.get('end_date', '')
    
    # Base context with defaults
    context = {
        'report_data': [],
        'summary': None,
        'spots': spots,
        'agents': agents,
        'supervisors': supervisors,
        'items': items,
        'all_species': all_species,
        'item_categories': item_categories,
        'item_qualities': item_qualities,
        'item_types': item_types,
        'item_grades': item_grades,
        'item_brands': item_brands,
        'freezing_categories': freezing_categories,
        'processing_centers': processing_centers,
        'stores': stores,
        'packing_units': packing_units,
        'glaze_percentages': glaze_percentages,
        'selected_spots': [],
        'selected_agents': [],
        'selected_supervisors': [],
        'selected_items': [],
        'selected_species': [],
        'selected_item_categories': [],
        'selected_item_qualities': [],
        'selected_item_types': [],
        'selected_item_grades': [],
        'selected_item_brands': [],
        'selected_freezing_categories': [],
        'selected_processing_centers': [],
        'selected_stores': [],
        'selected_packing_units': [],
        'selected_glaze_percentages': [],
        'profit_filter': 'all',
        'quick_filter': quick_filter,
        'start_date': start_date,
        'end_date': end_date,
        'date_range_text': get_date_range_text(quick_filter, start_date, end_date),
        'is_print': False,
    }
    
    # Update context with any provided kwargs
    context.update(kwargs)
    
    return context

def calculate_quick_filter_dates(quick_filter, base_date):
    """
    Helper function to calculate date ranges for quick filters
    """
    from datetime import timedelta
    import calendar
    
    if quick_filter == 'today':
        return base_date, base_date
    elif quick_filter == 'yesterday':
        yesterday = base_date - timedelta(days=1)
        return yesterday, yesterday
    elif quick_filter == 'this_week':
        days_since_monday = base_date.weekday()
        start_date = base_date - timedelta(days=days_since_monday)
        return start_date, base_date
    elif quick_filter == 'last_week':
        days_since_monday = base_date.weekday()
        last_monday = base_date - timedelta(days=days_since_monday + 7)
        last_sunday = last_monday + timedelta(days=6)
        return last_monday, last_sunday
    elif quick_filter == 'this_month':
        start_date = base_date.replace(day=1)
        return start_date, base_date
    elif quick_filter == 'last_month':
        if base_date.month == 1:
            last_month = base_date.replace(year=base_date.year-1, month=12, day=1)
        else:
            last_month = base_date.replace(month=base_date.month-1, day=1)
        _, last_day = calendar.monthrange(last_month.year, last_month.month)
        start_date = last_month
        end_date = last_month.replace(day=last_day)
        return start_date, end_date
    elif quick_filter == 'this_quarter':
        quarter_start_month = ((base_date.month - 1) // 3) * 3 + 1
        start_date = base_date.replace(month=quarter_start_month, day=1)
        return start_date, base_date
    elif quick_filter == 'last_quarter':
        current_quarter_start = ((base_date.month - 1) // 3) * 3 + 1
        if current_quarter_start == 1:
            last_quarter_start = base_date.replace(year=base_date.year-1, month=10, day=1)
            last_quarter_end = base_date.replace(year=base_date.year-1, month=12, day=31)
        else:
            last_quarter_start = base_date.replace(month=current_quarter_start-3, day=1)
            last_quarter_end_month = current_quarter_start - 1
            _, last_day = calendar.monthrange(base_date.year, last_quarter_end_month)
            last_quarter_end = base_date.replace(month=last_quarter_end_month, day=last_day)
        return last_quarter_start, last_quarter_end
    elif quick_filter == 'this_year':
        start_date = base_date.replace(month=1, day=1)
        return start_date, base_date
    elif quick_filter == 'last_year':
        start_date = base_date.replace(year=base_date.year-1, month=1, day=1)
        end_date = base_date.replace(year=base_date.year-1, month=12, day=31)
        return start_date, end_date
    else:
        # Default to today
        return base_date, base_date

def get_date_range_text(quick_filter, start_date, end_date):
    """Helper function to generate human-readable date range text"""
    if quick_filter:
        filter_names = {
            'today': 'Today',
            'yesterday': 'Yesterday', 
            'this_week': 'This Week',
            'last_week': 'Last Week',
            'this_month': 'This Month',
            'last_month': 'Last Month',
            'this_quarter': 'This Quarter',
            'last_quarter': 'Last Quarter',
            'this_year': 'This Year',
            'last_year': 'Last Year'
        }
        return filter_names.get(quick_filter, f"{start_date} to {end_date}")
    else:
        return f"{start_date} to {end_date}"
    

    
# ---------------- Buyer CRUD ----------------

def buyer_list(request):
    buyers = Buyer.objects.all().order_by("name")
    return render(request, "adminapp/Buyer/buyer_list.html", {"buyers": buyers})

def buyer_create(request):
    if request.method == "POST":
        form = BuyerForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Buyer created successfully!")
            return redirect("adminapp:buyer_list")
    else:
        form = BuyerForm()
    return render(request, "adminapp/Buyer/buyer_form.html", {"form": form, "title": "Create Buyer"})

def buyer_update(request, pk):
    buyer = get_object_or_404(Buyer, pk=pk)
    if request.method == "POST":
        form = BuyerForm(request.POST, instance=buyer)
        if form.is_valid():
            form.save()
            messages.success(request, "Buyer updated successfully!")
            return redirect("adminapp:buyer_list")
    else:
        form = BuyerForm(instance=buyer)
    return render(request, "adminapp/Buyer/buyer_form.html", {"form": form, "title": "Update Buyer"})

def buyer_delete(request, pk):
    buyer = get_object_or_404(Buyer, pk=pk)
    if request.method == "POST":
        buyer.delete()
        messages.success(request, "Buyer deleted successfully!")
        return redirect("adminapp:buyer_list")
    return render(request, "adminapp/confirm_delete.html", {"buyer": buyer})


# ---------------- Shipment Destination CRUD ----------------

def destination_list(request):
    destinations = ShipmentDestination.objects.all().order_by("country")
    return render(request, "adminapp/Shipment/destination_list.html", {"destinations": destinations})

def destination_create(request):
    if request.method == "POST":
        form = ShipmentDestinationForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Shipment Destination created successfully!")
            return redirect("adminapp:destination_list")
    else:
        form = ShipmentDestinationForm()
    return render(request, "adminapp/Shipment/destination_form.html", {"form": form, "title": "Create Destination"})

def destination_update(request, pk):
    destination = get_object_or_404(ShipmentDestination, pk=pk)
    if request.method == "POST":
        form = ShipmentDestinationForm(request.POST, instance=destination)
        if form.is_valid():
            form.save()
            messages.success(request, "Shipment Destination updated successfully!")
            return redirect("adminapp:destination_list")
    else:
        form = ShipmentDestinationForm(instance=destination)
    return render(request, "adminapp/Shipment/destination_form.html", {"form": form, "title": "Update Destination"})

def destination_delete(request, pk):
    destination = get_object_or_404(ShipmentDestination, pk=pk)
    if request.method == "POST":
        destination.delete()
        messages.success(request, "Shipment Destination deleted successfully!")
        return redirect("adminapp:destination_list")
    return render(request, "adminapp/confirm_delete.html", {"destination": destination})


# ---------------- Sales Entry CRUD ----------------

def create_sales_entry(request):
    if request.method == "POST":
        form = SalesEntryForm(request.POST)
        formset = SalesEntryItemFormSet(request.POST)
        
        # Debug: Print form errors
        print("=" * 50)
        print("FORM VALIDATION")
        print("=" * 50)
        print(f"Form is valid: {form.is_valid()}")
        if not form.is_valid():
            print("Form Errors:")
            print(form.errors)
            print(form.non_field_errors())
        
        print(f"\nFormset is valid: {formset.is_valid()}")
        if not formset.is_valid():
            print("Formset Errors:")
            print(formset.errors)
            print(formset.non_form_errors())
        print("=" * 50)

        if form.is_valid() and formset.is_valid():
            try:
                with transaction.atomic():
                    # Save the sales entry
                    sales_entry = form.save()
                    print(f"✓ Sales Entry saved: {sales_entry.invoice_no}")
                    
                    # Process each item in the formset
                    items = formset.save(commit=False)
                    
                    if not items:
                        messages.warning(request, "Please add at least one item to the sales entry.")
                        sales_entry.delete()  # Rollback the sales entry
                        raise ValueError("No items in formset")
                    
                    print(f"\n=== PROCESSING {len(items)} SALES ITEMS ===")
                    
                    for item in items:
                        item.sales_entry = sales_entry
                        item.save()
                        print(f"\n✓ Item saved: {item.species} - Cartons: {item.cartons}, Qty: {item.quantity}")
                        
                        # Deduct from stock
                        deduct_stock_for_sales_item(item)
                        
                        # ✅ CREATE STOCK MOVEMENT for SHIPMENT (NEGATIVE quantity)
                        try:
                            # Get the item name - check which field exists in SalesEntryItem
                            item_name = None
                            if hasattr(item, 'item'):
                                item_name = item.item
                            elif hasattr(item, 'product'):
                                item_name = item.product
                            elif hasattr(item, 'stock_item'):
                                item_name = item.stock_item
                            
                            # Build stock filter based on available fields
                            stock_filters = {}
                            
                            # Add fields that exist in your SalesEntryItem model
                            if hasattr(item, 'brand') and item.brand:
                                stock_filters['brand'] = item.brand
                            if hasattr(item, 'species') and item.species:
                                stock_filters['species'] = item.species
                            if hasattr(item, 'grade') and item.grade:
                                stock_filters['item_grade'] = item.grade
                            if hasattr(item, 'unit') and item.unit:
                                stock_filters['unit'] = item.unit
                            if hasattr(item, 'glaze') and item.glaze:
                                stock_filters['glaze'] = item.glaze
                            if hasattr(item, 'peeling_type') and item.peeling_type:
                                stock_filters['peeling_type'] = item.peeling_type
                            if hasattr(item, 'freezing_category') and item.freezing_category:
                                stock_filters['freezing_category'] = item.freezing_category
                            if hasattr(item, 'item_quality') and item.item_quality:
                                stock_filters['item_quality'] = item.item_quality
                            
                            # Try to find stock record
                            stock = Stock.objects.filter(**stock_filters).first()
                            
                            if stock:
                                # Create NEGATIVE movement for shipment/sale
                                movement_data = {
                                    'movement_type': 'shipment',
                                    'movement_date': sales_entry.invoice_date if hasattr(sales_entry, 'invoice_date') else timezone.now().date(),
                                    'voucher_number': str(sales_entry.invoice_no),
                                    'store': stock.store,
                                    'item': stock.item,
                                    'brand': stock.brand,
                                    'cs_quantity': -Decimal(str(item.cartons)),  # NEGATIVE for sale
                                    'kg_quantity': -Decimal(str(item.quantity)),  # NEGATIVE for sale
                                    'slab_quantity': Decimal('0'),
                                    'usd_rate_per_kg': stock.usd_rate_per_kg or Decimal('0'),
                                    'usd_rate_item': stock.usd_rate_item or Decimal('0'),
                                    'usd_rate_item_to_inr': stock.usd_rate_item_to_inr or Decimal('0'),
                                    'reference_model': 'SalesEntry',
                                    'reference_id': str(sales_entry.id),
                                    'created_by': request.user if request.user.is_authenticated else None,
                                    'notes': f"Sale - Invoice: {sales_entry.invoice_no}"
                                }
                                
                                # Add optional fields from stock
                                if stock.item_quality:
                                    movement_data['item_quality'] = stock.item_quality
                                if stock.freezing_category:
                                    movement_data['freezing_category'] = stock.freezing_category
                                if stock.peeling_type:
                                    movement_data['peeling_type'] = stock.peeling_type
                                if stock.unit:
                                    movement_data['unit'] = stock.unit
                                if stock.glaze:
                                    movement_data['glaze'] = stock.glaze
                                if stock.species:
                                    movement_data['species'] = stock.species
                                if stock.item_grade:
                                    movement_data['item_grade'] = stock.item_grade
                                
                                # Add customer info if available
                                if hasattr(sales_entry, 'customer') and sales_entry.customer:
                                    movement_data['notes'] = f"Sale - Invoice: {sales_entry.invoice_no}, Customer: {sales_entry.customer.name}"
                                
                                StockMovement.objects.create(**movement_data)
                                print(f"  ✓ StockMovement created: Shipment -{item.quantity} kg")
                            else:
                                print(f"  ⚠ Warning: No stock record found for movement tracking")
                                print(f"  Search filters: {stock_filters}")
                                messages.warning(request, f"Stock not found for movement tracking")
                                
                        except Exception as e:
                            print(f"  ✗ Error creating StockMovement: {e}")
                            import traceback
                            traceback.print_exc()
                            # Don't fail the transaction, just log the error
                            messages.warning(request, f"Stock movement tracking error: {str(e)}")
                    
                    # Delete removed items
                    for obj in formset.deleted_objects:
                        obj.delete()
                    
                    print(f"\n=== SALES ENTRY COMPLETE ===")
                    messages.success(request, f"Sales entry {sales_entry.invoice_no} created successfully! ✅")
                    return redirect("adminapp:sales_entry_list")
                    
            except ValueError as e:
                messages.error(request, f"Stock error: {str(e)}")
                logger.error(f"Stock error in create_sales_entry: {str(e)}")
            except Exception as e:
                messages.error(request, f"Error creating sales entry: {str(e)}")
                logger.error(f"Error in create_sales_entry: {str(e)}", exc_info=True)
        else:
            # Show specific error messages
            if not form.is_valid():
                for field, errors in form.errors.items():
                    for error in errors:
                        messages.error(request, f"{field}: {error}")
            
            if not formset.is_valid():
                for i, form_errors in enumerate(formset.errors):
                    if form_errors:
                        messages.error(request, f"Item {i+1}: {form_errors}")
                if formset.non_form_errors():
                    for error in formset.non_form_errors():
                        messages.error(request, f"Formset error: {error}")
    else:
        form = SalesEntryForm()
        formset = SalesEntryItemFormSet()

    return render(request, "adminapp/sales/sales_entry_form.html", {
        "form": form,
        "formset": formset,
        "action": "Create",
    })

def deduct_stock_for_sales_item(sales_item):
    """
    Deduct stock quantities based on sales entry item.
    """
    sales_entry = sales_item.sales_entry
    
    # Build filter dynamically to handle None values
    filter_kwargs = {
        'item': sales_entry.item,
        'species': sales_item.species,
        'item_grade': sales_item.grade,
    }
    
    # Add optional fields only if they exist
    if sales_entry.brand:
        filter_kwargs['brand'] = sales_entry.brand
    if sales_entry.item_quality:
        filter_kwargs['item_quality'] = sales_entry.item_quality
    if sales_entry.unit:
        filter_kwargs['unit'] = sales_entry.unit
    if sales_entry.glaze:
        filter_kwargs['glaze'] = sales_entry.glaze
    if sales_entry.freezing_category:
        filter_kwargs['freezing_category'] = sales_entry.freezing_category
    
    try:
        # Find matching stock record
        stock_qs = Stock.objects.filter(**filter_kwargs)
        
        if not stock_qs.exists():
            # Try to find partial match and show what's available
            # Get available stocks without using .name (in case models don't have name field)
            available_stocks = Stock.objects.filter(
                item=sales_entry.item
            ).select_related('item', 'species', 'item_grade')[:5]
            
            error_msg = f"No stock found for: {sales_entry.item}"
            if sales_item.species:
                error_msg += f" - {sales_item.species}"
            if sales_item.grade:
                error_msg += f" - {sales_item.grade}"
            
            if available_stocks:
                error_msg += f"\n\nAvailable stocks for {sales_entry.item}:"
                for stock in available_stocks:
                    species_str = str(stock.species) if stock.species else 'N/A'
                    grade_str = str(stock.item_grade) if stock.item_grade else 'N/A'
                    error_msg += f"\n- {species_str} {grade_str}: {stock.cs_quantity} cartons, {stock.kg_quantity} kg"
            
            raise ValueError(error_msg)
        
        stock = stock_qs.first()
        
        # Check if sufficient stock exists
        if stock.cs_quantity < sales_item.cartons:
            raise ValueError(
                f"Insufficient carton stock for {sales_entry.item} - {sales_item.species if sales_item.species else 'N/A'}. "
                f"Available: {stock.cs_quantity}, Required: {sales_item.cartons}"
            )
        
        if stock.kg_quantity < sales_item.quantity:
            raise ValueError(
                f"Insufficient kg stock for {sales_entry.item} - {sales_item.species if sales_item.species else 'N/A'}. "
                f"Available: {stock.kg_quantity}, Required: {sales_item.quantity}"
            )
        
        # Deduct quantities
        old_cs = stock.cs_quantity
        old_kg = stock.kg_quantity
        
        stock.cs_quantity -= sales_item.cartons
        stock.kg_quantity -= sales_item.quantity
        stock.save()
        
        print(f"Stock deducted: {sales_entry.item}")
        print(f"  Cartons: {old_cs} -> {stock.cs_quantity} (deducted {sales_item.cartons})")
        print(f"  KG: {old_kg} -> {stock.kg_quantity} (deducted {sales_item.quantity})")
        
    except Stock.DoesNotExist:
        raise ValueError(
            f"No stock found matching: {sales_entry.item} - "
            f"{sales_item.species if sales_item.species else 'N/A'}"
        )

def update_sales_entry(request, pk):
    """
    Update existing sales entry - restores old stock, deletes old movements, 
    deducts new stock, and creates new movements.
    """
    sales_entry = get_object_or_404(SalesEntry, pk=pk)
    
    if request.method == "POST":
        form = SalesEntryForm(request.POST, instance=sales_entry)
        formset = SalesEntryItemFormSet(request.POST, instance=sales_entry)

        if form.is_valid() and formset.is_valid():
            try:
                with transaction.atomic():
                    print(f"\n=== UPDATING SALES ENTRY: {sales_entry.invoice_no} ===")
                    
                    # STEP 1: Restore stock from old items
                    print(f"\n--- STEP 1: RESTORING OLD STOCK ---")
                    old_items = sales_entry.items.all()
                    for old_item in old_items:
                        try:
                            restore_stock_for_sales_item(old_item)
                            print(f"  ✓ Restored: {old_item.species} - {old_item.quantity} kg")
                        except Exception as e:
                            print(f"  ✗ Error restoring stock: {e}")
                    
                    # STEP 2: Delete old StockMovement records
                    print(f"\n--- STEP 2: DELETING OLD STOCK MOVEMENTS ---")
                    old_movements = StockMovement.objects.filter(
                        reference_model='SalesEntry',
                        reference_id=str(sales_entry.id)
                    )
                    movement_count = old_movements.count()
                    old_movements.delete()
                    print(f"  ✓ Deleted {movement_count} old movement(s)")
                    
                    # STEP 3: Save the updated entry
                    print(f"\n--- STEP 3: SAVING UPDATED ENTRY ---")
                    sales_entry = form.save()
                    print(f"  ✓ Sales entry updated: {sales_entry.invoice_no}")
                    
                    # STEP 4: Process new/updated items
                    print(f"\n--- STEP 4: PROCESSING NEW ITEMS ---")
                    items = formset.save(commit=False)
                    
                    if not items:
                        messages.warning(request, "Please add at least one item to the sales entry.")
                        raise ValueError("No items in formset")
                    
                    for item in items:
                        item.sales_entry = sales_entry
                        item.save()
                        print(f"\n  ✓ Item saved: {item.species} - Cartons: {item.cartons}, Qty: {item.quantity}")
                        
                        # Deduct from stock
                        deduct_stock_for_sales_item(item)
                        
                        # ✅ CREATE NEW STOCK MOVEMENT for SHIPMENT
                        try:
                            # Build stock filter based on available fields
                            stock_filters = {}
                            
                            if hasattr(item, 'brand') and item.brand:
                                stock_filters['brand'] = item.brand
                            if hasattr(item, 'species') and item.species:
                                stock_filters['species'] = item.species
                            if hasattr(item, 'grade') and item.grade:
                                stock_filters['item_grade'] = item.grade
                            if hasattr(item, 'unit') and item.unit:
                                stock_filters['unit'] = item.unit
                            if hasattr(item, 'glaze') and item.glaze:
                                stock_filters['glaze'] = item.glaze
                            if hasattr(item, 'peeling_type') and item.peeling_type:
                                stock_filters['peeling_type'] = item.peeling_type
                            if hasattr(item, 'freezing_category') and item.freezing_category:
                                stock_filters['freezing_category'] = item.freezing_category
                            if hasattr(item, 'item_quality') and item.item_quality:
                                stock_filters['item_quality'] = item.item_quality
                            
                            # Find stock record
                            stock = Stock.objects.filter(**stock_filters).first()
                            
                            if stock:
                                # Create NEGATIVE movement for shipment/sale
                                movement_data = {
                                    'movement_type': 'shipment',
                                    'movement_date': sales_entry.invoice_date if hasattr(sales_entry, 'invoice_date') else timezone.now().date(),
                                    'voucher_number': str(sales_entry.invoice_no),
                                    'store': stock.store,
                                    'item': stock.item,
                                    'brand': stock.brand,
                                    'cs_quantity': -Decimal(str(item.cartons)),  # NEGATIVE for sale
                                    'kg_quantity': -Decimal(str(item.quantity)),  # NEGATIVE for sale
                                    'slab_quantity': Decimal('0'),
                                    'usd_rate_per_kg': stock.usd_rate_per_kg or Decimal('0'),
                                    'usd_rate_item': stock.usd_rate_item or Decimal('0'),
                                    'usd_rate_item_to_inr': stock.usd_rate_item_to_inr or Decimal('0'),
                                    'reference_model': 'SalesEntry',
                                    'reference_id': str(sales_entry.id),
                                    'created_by': request.user if request.user.is_authenticated else None,
                                    'notes': f"Sale (Updated) - Invoice: {sales_entry.invoice_no}"
                                }
                                
                                # Add optional fields from stock
                                if stock.item_quality:
                                    movement_data['item_quality'] = stock.item_quality
                                if stock.freezing_category:
                                    movement_data['freezing_category'] = stock.freezing_category
                                if stock.peeling_type:
                                    movement_data['peeling_type'] = stock.peeling_type
                                if stock.unit:
                                    movement_data['unit'] = stock.unit
                                if stock.glaze:
                                    movement_data['glaze'] = stock.glaze
                                if stock.species:
                                    movement_data['species'] = stock.species
                                if stock.item_grade:
                                    movement_data['item_grade'] = stock.item_grade
                                
                                # Add customer info if available
                                if hasattr(sales_entry, 'customer') and sales_entry.customer:
                                    movement_data['notes'] = f"Sale (Updated) - Invoice: {sales_entry.invoice_no}, Customer: {sales_entry.customer.name}"
                                
                                StockMovement.objects.create(**movement_data)
                                print(f"    ✓ NEW StockMovement created: Shipment -{item.quantity} kg")
                            else:
                                print(f"    ⚠ Warning: No stock record found for movement tracking")
                                print(f"    Search filters: {stock_filters}")
                                
                        except Exception as e:
                            print(f"    ✗ Error creating StockMovement: {e}")
                            import traceback
                            traceback.print_exc()
                            messages.warning(request, f"Stock movement tracking error: {str(e)}")
                    
                    # STEP 5: Handle deleted items (already restored above)
                    for obj in formset.deleted_objects:
                        obj.delete()
                    
                    print(f"\n=== UPDATE COMPLETE ===")
                    messages.success(request, f"Sales entry {sales_entry.invoice_no} updated successfully! ✅")
                    return redirect("adminapp:sales_entry_detail", pk=pk)
                    
            except ValueError as e:
                messages.error(request, f"Stock error: {str(e)}")
                logger.error(f"Stock error in update_sales_entry: {str(e)}")
            except Exception as e:
                messages.error(request, f"Error updating sales entry: {str(e)}")
                logger.error(f"Error in update_sales_entry: {str(e)}", exc_info=True)
        else:
            messages.error(request, "Please correct the errors in the form.")
            # Show specific error messages
            if not form.is_valid():
                for field, errors in form.errors.items():
                    for error in errors:
                        messages.error(request, f"{field}: {error}")
            
            if not formset.is_valid():
                for i, form_errors in enumerate(formset.errors):
                    if form_errors:
                        messages.error(request, f"Item {i+1}: {form_errors}")
    else:
        form = SalesEntryForm(instance=sales_entry)
        formset = SalesEntryItemFormSet(instance=sales_entry)

    return render(request, "adminapp/sales/sales_entry_form.html", {
        "form": form,
        "formset": formset,
        "action": "Update",
        "sales_entry": sales_entry,
    })

def restore_stock_for_sales_item(sales_item):
    """
    Restore stock quantities when sales entry is updated or deleted.
    """
    sales_entry = sales_item.sales_entry
    
    filter_kwargs = {
        'item': sales_entry.item,
        'species': sales_item.species,
        'item_grade': sales_item.grade,
    }
    
    if sales_entry.brand:
        filter_kwargs['brand'] = sales_entry.brand
    if sales_entry.item_quality:
        filter_kwargs['item_quality'] = sales_entry.item_quality
    if sales_entry.unit:
        filter_kwargs['unit'] = sales_entry.unit
    if sales_entry.glaze:
        filter_kwargs['glaze'] = sales_entry.glaze
    if sales_entry.freezing_category:
        filter_kwargs['freezing_category'] = sales_entry.freezing_category
    
    try:
        stock = Stock.objects.filter(**filter_kwargs).first()
        
        if stock:
            stock.cs_quantity += sales_item.cartons
            stock.kg_quantity += sales_item.quantity
            stock.save()
            print(f"Stock restored: {sales_entry.item} - Cartons: {sales_item.cartons}, KG: {sales_item.quantity}")
        
    except Exception as e:
        logger.error(f"Error restoring stock: {str(e)}")

def delete_sales_entry(request, pk):
    """
    Delete sales entry, restore stock, and remove stock movements.
    """
    sales_entry = get_object_or_404(SalesEntry, pk=pk)
    
    if request.method == "POST":
        try:
            with transaction.atomic():
                print(f"\n=== DELETING SALES ENTRY: {sales_entry.invoice_no} ===")
                
                # STEP 1: Restore stock for all items
                print(f"\n--- STEP 1: RESTORING STOCK ---")
                items = sales_entry.items.all()
                for item in items:
                    try:
                        restore_stock_for_sales_item(item)
                        print(f"  ✓ Restored: {item.species} - Cartons: {item.cartons}, Qty: {item.quantity} kg")
                    except Exception as e:
                        print(f"  ✗ Error restoring stock: {e}")
                        messages.warning(request, f"Error restoring stock for {item.species}: {str(e)}")
                
                # STEP 2: Delete associated StockMovement records
                print(f"\n--- STEP 2: DELETING STOCK MOVEMENTS ---")
                stock_movements = StockMovement.objects.filter(
                    reference_model='SalesEntry',
                    reference_id=str(sales_entry.id)
                )
                movement_count = stock_movements.count()
                stock_movements.delete()
                print(f"  ✓ Deleted {movement_count} stock movement(s)")
                
                # STEP 3: Delete the sales entry
                print(f"\n--- STEP 3: DELETING SALES ENTRY ---")
                invoice_no = sales_entry.invoice_no
                sales_entry.delete()
                print(f"  ✓ Sales entry deleted: {invoice_no}")
                
                print(f"\n=== DELETE COMPLETE ===")
                messages.success(request, f"Sales entry {invoice_no} deleted and stock restored! ✅")
                return redirect("adminapp:sales_entry_list")
                
        except Exception as e:
            print(f"\n✗ Error deleting sales entry: {e}")
            import traceback
            traceback.print_exc()
            messages.error(request, f"Error deleting sales entry: {str(e)}")
            logger.error(f"Error in delete_sales_entry: {str(e)}", exc_info=True)
    
    return render(request, "adminapp/sales/sales_entry_confirm_delete.html", {
        "sales_entry": sales_entry,
    })

def sales_entry_list(request):
    """
    List all sales entries with search and filter.
    """
    sales_entries = SalesEntry.objects.all().select_related(
        'buyer', 'item', 'brand'
    ).prefetch_related('items').order_by('-date')
    
    # Search functionality
    search_query = request.GET.get('search', '')
    if search_query:
        sales_entries = sales_entries.filter(
            Q(voucher_no__icontains=search_query) |
            Q(invoice_no__icontains=search_query) |
            Q(buyer__name__icontains=search_query) |
            Q(buyer_order_no__icontains=search_query)
        )
    
    # Status filter
    status_filter = request.GET.get('status', '')
    if status_filter:
        sales_entries = sales_entries.filter(status=status_filter)
    
    # Date range filter
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')
    if date_from:
        sales_entries = sales_entries.filter(date__gte=date_from)
    if date_to:
        sales_entries = sales_entries.filter(date__lte=date_to)
    
    # Pagination
    paginator = Paginator(sales_entries, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'search_query': search_query,
        'status_filter': status_filter,
        'date_from': date_from,
        'date_to': date_to,
        'status_choices': SalesEntry.STATUS_CHOICES,
    }
    
    return render(request, "adminapp/sales/sales_entry_list.html", context)

def confirm_sales_entry(request, pk):
    """
    Change sales entry status to confirmed.
    """
    sales_entry = get_object_or_404(SalesEntry, pk=pk)
    
    if request.method == "POST":
        sales_entry.status = 'confirmed'
        sales_entry.save()
        messages.success(request, f"Sales entry {sales_entry.invoice_no} confirmed!")
        return redirect("adminapp:sales_entry_detail", pk=pk)
    
    return redirect("adminapp:sales_entry_detail", pk=pk)

def sales_entry_detail(request, pk):
    """
    Display detailed view of a sales entry.
    """
    sales_entry = get_object_or_404(
        SalesEntry.objects.select_related(
            'buyer', 'item', 'brand', 'unit', 'glaze', 'freezing_category', 'item_quality'
        ).prefetch_related('items__species', 'items__peeling_type', 'items__grade'),
        pk=pk
    )
    
    return render(request, "adminapp/sales/sales_entry_detail.html", {
        "sales_entry": sales_entry,
    })

def sales_entry_invoice_pdf(request, pk):
    """
    Generate and download PDF invoice for a sales entry.
    """
    sales_entry = get_object_or_404(
        SalesEntry.objects.select_related(
            'buyer', 'item', 'brand', 'unit', 'glaze', 'freezing_category', 'item_quality'
        ).prefetch_related('items__species', 'items__peeling_type', 'items__grade'),
        pk=pk
    )
    
    # Prepare context
    context = {
        'sales_entry': sales_entry,
        'company_name': 'AM FISHERIES',  # You can make this dynamic
    }
    
    # Get template
    template = get_template('adminapp/sales/sales_entry_invoice_pdf.html')
    html = template.render(context)
    
    # Create PDF
    result = BytesIO()
    pdf = pisa.pisaDocument(BytesIO(html.encode("UTF-8")), result)
    
    if not pdf.err:
        # Return PDF as download
        response = HttpResponse(result.getvalue(), content_type='application/pdf')
        filename = f"Invoice_{sales_entry.invoice_no}_{sales_entry.date.strftime('%Y%m%d')}.pdf"
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response
    
    return HttpResponse('Error generating PDF', status=400)




def stock_adjustment(request):
    """Adjust stock - create new or update existing with tracking"""
    if request.method == 'POST':
        form = StockAdjustmentForm(request.POST)
        if form.is_valid():
            try:
                with transaction.atomic():
                    # Get form data
                    store = form.cleaned_data['store']
                    item = form.cleaned_data['item']
                    brand = form.cleaned_data['brand']
                    item_quality = form.cleaned_data.get('item_quality')
                    unit = form.cleaned_data.get('unit')
                    glaze = form.cleaned_data.get('glaze')
                    species = form.cleaned_data.get('species')
                    item_grade = form.cleaned_data.get('item_grade')
                    peeling_type = form.cleaned_data.get('peeling_type')
                    freezing_category = form.cleaned_data.get('freezing_category')
                    
                    cs_adjustment = form.cleaned_data.get('cs_adjustment', 0) or Decimal('0')
                    kg_adjustment = form.cleaned_data.get('kg_adjustment', 0) or Decimal('0')
                    
                    usd_rate_per_kg = form.cleaned_data.get('usd_rate_per_kg', 0) or Decimal('0')
                    usd_rate_item = form.cleaned_data.get('usd_rate_item', 0) or Decimal('0')
                    usd_rate_item_to_inr = form.cleaned_data.get('usd_rate_item_to_inr', 0) or Decimal('0')
                    
                    notes = form.cleaned_data.get('notes', '') or 'Manual stock adjustment'
                    
                    # Determine movement type based on adjustment direction
                    if cs_adjustment > 0 or kg_adjustment > 0:
                        movement_type = 'adjustment_plus'
                        action = "increased"
                    elif cs_adjustment < 0 or kg_adjustment < 0:
                        movement_type = 'adjustment_minus'
                        action = "decreased"
                    else:
                        messages.info(request, 'No quantity changes detected.')
                        return redirect('adminapp:list')
                    
                    # Generate voucher number
                    voucher_number = f"ADJ-{timezone.now().strftime('%Y%m%d%H%M%S')}"
                    movement_date = timezone.now().date()
                    
                    # Build stock filters
                    print(f"\n=== STOCK ADJUSTMENT ===")
                    print(f"Item: {item.name}")
                    print(f"CS Adjustment: {cs_adjustment}")
                    print(f"KG Adjustment: {kg_adjustment}")
                    print(f"Movement Type: {movement_type}")
                    
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
                    stock_filters = {k: v for k, v in stock_filters.items() if v is not None}
                    
                    # Get or create stock
                    existing_stock = Stock.objects.select_for_update().filter(**stock_filters).first()
                    
                    if existing_stock:
                        print(f"\nUpdating existing stock:")
                        print(f"  Current: CS={existing_stock.cs_quantity}, KG={existing_stock.kg_quantity}")
                        
                        old_kg = existing_stock.kg_quantity
                        new_kg = old_kg + kg_adjustment
                        
                        # Calculate weighted average rates if adding positive quantity
                        if kg_adjustment > 0 and new_kg > 0:
                            old_usd_per_kg = existing_stock.usd_rate_per_kg or Decimal('0')
                            old_usd_item = existing_stock.usd_rate_item or Decimal('0')
                            old_inr = existing_stock.usd_rate_item_to_inr or Decimal('0')
                            
                            # Weighted average formula
                            existing_stock.usd_rate_per_kg = (
                                (old_kg * old_usd_per_kg) + (kg_adjustment * usd_rate_per_kg)
                            ) / new_kg
                            
                            existing_stock.usd_rate_item = (
                                (old_kg * old_usd_item) + (kg_adjustment * usd_rate_item)
                            ) / new_kg
                            
                            existing_stock.usd_rate_item_to_inr = (
                                (old_kg * old_inr) + (kg_adjustment * usd_rate_item_to_inr)
                            ) / new_kg
                            
                            print(f"  Rates (Weighted Avg):")
                            print(f"    USD/kg: {old_usd_per_kg:.2f} → {existing_stock.usd_rate_per_kg:.2f}")
                            print(f"    USD/item: {old_usd_item:.2f} → {existing_stock.usd_rate_item:.2f}")
                            print(f"    INR: {old_inr:.2f} → {existing_stock.usd_rate_item_to_inr:.2f}")
                        elif kg_adjustment < 0 and old_kg > 0:
                            # When reducing, recalculate rates by removing the contribution
                            abs_kg_adj = abs(kg_adjustment)
                            
                            old_usd_per_kg = existing_stock.usd_rate_per_kg or Decimal('0')
                            old_usd_item = existing_stock.usd_rate_item or Decimal('0')
                            old_inr = existing_stock.usd_rate_item_to_inr or Decimal('0')
                            
                            # Current weighted totals
                            current_usd_per_kg_total = old_kg * old_usd_per_kg
                            current_usd_item_total = old_kg * old_usd_item
                            current_inr_total = old_kg * old_inr
                            
                            # Remove the contribution (using current average rates)
                            remaining_usd_per_kg_total = current_usd_per_kg_total - (abs_kg_adj * old_usd_per_kg)
                            remaining_usd_item_total = current_usd_item_total - (abs_kg_adj * old_usd_item)
                            remaining_inr_total = current_inr_total - (abs_kg_adj * old_inr)
                            
                            if new_kg > 0:
                                existing_stock.usd_rate_per_kg = remaining_usd_per_kg_total / new_kg
                                existing_stock.usd_rate_item = remaining_usd_item_total / new_kg
                                existing_stock.usd_rate_item_to_inr = remaining_inr_total / new_kg
                                
                                print(f"  Recalculated Rates (after reduction):")
                                print(f"    USD/kg: {old_usd_per_kg:.2f} → {existing_stock.usd_rate_per_kg:.2f}")
                                print(f"    USD/item: {old_usd_item:.2f} → {existing_stock.usd_rate_item:.2f}")
                                print(f"    INR: {old_inr:.2f} → {existing_stock.usd_rate_item_to_inr:.2f}")
                            else:
                                existing_stock.usd_rate_per_kg = Decimal('0')
                                existing_stock.usd_rate_item = Decimal('0')
                                existing_stock.usd_rate_item_to_inr = Decimal('0')
                                print(f"  Stock depleted, rates set to 0")
                        
                        # Update quantities
                        existing_stock.cs_quantity += cs_adjustment
                        existing_stock.kg_quantity += kg_adjustment
                        
                        print(f"  New: CS={existing_stock.cs_quantity}, KG={existing_stock.kg_quantity}")
                        
                        # Delete stock if both quantities are zero
                        if existing_stock.cs_quantity == 0 and existing_stock.kg_quantity == 0:
                            print(f"  Stock depleted to zero, deleting entry")
                            existing_stock.delete()
                        else:
                            existing_stock.save()
                            if existing_stock.cs_quantity < 0 or existing_stock.kg_quantity < 0:
                                print(f"  ⚠ WARNING: Stock is NEGATIVE!")
                                messages.warning(
                                    request,
                                    f"Warning: {item.name} stock is negative "
                                    f"(CS: {existing_stock.cs_quantity}, KG: {existing_stock.kg_quantity})"
                                )
                            else:
                                print(f"  ✓ Stock updated successfully")
                    else:
                        # Create new stock entry (only if adjustment is positive)
                        if cs_adjustment > 0 or kg_adjustment > 0:
                            new_stock_data = {
                                **stock_filters,
                                'cs_quantity': cs_adjustment,
                                'kg_quantity': kg_adjustment,
                                'usd_rate_per_kg': usd_rate_per_kg,
                                'usd_rate_item': usd_rate_item,
                                'usd_rate_item_to_inr': usd_rate_item_to_inr,
                            }
                            
                            existing_stock = Stock.objects.create(**new_stock_data)
                            print(f"\n✓ New stock CREATED for {item.name}")
                            print(f"  CS={existing_stock.cs_quantity}, KG={existing_stock.kg_quantity}")
                        else:
                            raise ValueError("Cannot create new stock with negative adjustment")
                    
                    # CREATE STOCK MOVEMENT RECORD
                    StockMovement.objects.create(
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
                        cs_quantity=cs_adjustment,  # Store the adjustment (can be positive or negative)
                        kg_quantity=kg_adjustment,  # Store the adjustment (can be positive or negative)
                        slab_quantity=Decimal('0'),
                        usd_rate_per_kg=usd_rate_per_kg,
                        usd_rate_item=usd_rate_item,
                        usd_rate_item_to_inr=usd_rate_item_to_inr,
                        reference_model='StockAdjustment',
                        reference_id=voucher_number,
                        created_by=request.user if request.user.is_authenticated else None,
                        notes=notes
                    )
                    print(f"  ✓ Stock movement record created")
                    
                    # Get final stock state for message
                    final_stock = Stock.objects.filter(**stock_filters).first()
                    
                    if final_stock:
                        messages.success(
                            request, 
                            f'Stock {action} for {item.name}! '
                            f'New CS: {final_stock.cs_quantity}, New KG: {final_stock.kg_quantity}'
                        )
                    else:
                        messages.success(
                            request, 
                            f'Stock adjustment completed for {item.name}! Stock record removed (zero quantity).'
                        )
                    
                    print(f"✓ Stock adjustment complete\n")
                    return redirect('adminapp:list')
                    
            except Exception as e:
                print(f"✗ Error in stock adjustment: {e}")
                import traceback
                traceback.print_exc()
                messages.error(request, f'Error adjusting stock: {str(e)}')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = StockAdjustmentForm()
    
    context = {
        'form': form,
        'title': 'Stock Adjustment',
        'action': 'Adjust'
    }
    return render(request, 'adminapp/stock/stock_adjustment.html', context)

def get_current_stock(request):
    """AJAX endpoint to get current stock quantities"""
    if request.method == 'GET':
        store_id = request.GET.get('store')
        item_id = request.GET.get('item')
        brand_id = request.GET.get('brand')
        item_quality_id = request.GET.get('item_quality') or None
        unit_id = request.GET.get('unit') or None
        glaze_id = request.GET.get('glaze') or None
        item_grade_id = request.GET.get('item_grade') or None
        peeling_type_id = request.GET.get('peeling_type') or None
        
        # Convert empty strings to None
        if item_quality_id == '':
            item_quality_id = None
        if unit_id == '':
            unit_id = None
        if glaze_id == '':
            glaze_id = None
        if item_grade_id == '':
            item_grade_id = None
        if peeling_type_id == '':
            peeling_type_id = None
        
        try:
            stock = Stock.objects.get(
                store_id=store_id,
                item_id=item_id,
                brand_id=brand_id,
                item_quality_id=item_quality_id,
                unit_id=unit_id,
                glaze_id=glaze_id,
                item_grade_id=item_grade_id,
                peeling_type_id=peeling_type_id
            )
            return JsonResponse({
                'exists': True,
                'cs_quantity': float(stock.cs_quantity),
                'kg_quantity': float(stock.kg_quantity),
                'usd_rate_per_kg': float(stock.usd_rate_per_kg),
                'usd_rate_item': float(stock.usd_rate_item),
                'usd_rate_item_to_inr': float(stock.usd_rate_item_to_inr),
            })
        except Stock.DoesNotExist:
            return JsonResponse({
                'exists': False,
                'cs_quantity': 0,
                'kg_quantity': 0
            })
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    
    return JsonResponse({'error': 'Invalid request'}, status=400)






def tenant_stock_adjustment(request):
    """Adjust tenant stock - create new or update existing"""
    if request.method == 'POST':
        form = TenantStockAdjustmentForm(request.POST)
        if form.is_valid():
            try:
                with transaction.atomic():
                    # Get form data
                    tenant = form.cleaned_data['tenant_company_name']
                    item = form.cleaned_data['item']
                    brand = form.cleaned_data['brand']
                    item_quality = form.cleaned_data.get('item_quality')
                    unit = form.cleaned_data['unit']
                    glaze = form.cleaned_data['glaze']
                    grade = form.cleaned_data['grade']
                    peeling_type = form.cleaned_data.get('peeling_type')
                    freezing_category = form.cleaned_data['freezing_category']
                    
                    processing_center = form.cleaned_data.get('processing_center')
                    store = form.cleaned_data.get('store')
                    
                    # Ensure adjustment values are Decimal
                    slab_adjustment = Decimal(str(form.cleaned_data.get('slab_adjustment') or 0))
                    cs_adjustment = Decimal(str(form.cleaned_data.get('cs_adjustment') or 0))
                    kg_adjustment = Decimal(str(form.cleaned_data.get('kg_adjustment') or 0))
                    
                    remarks = form.cleaned_data.get('remarks', '')
                    
                    # Build lookup dictionary dynamically
                    lookup_params = {
                        'tenant_company_name': tenant,
                        'item': item,
                        'brand': brand,
                        'unit': unit,
                        'glaze': glaze,
                        'grade': grade,
                        'freezing_category': freezing_category,
                        'item_quality': item_quality,
                        'peeling_type': peeling_type,
                        'processing_center': processing_center,
                        'store': store,
                    }
                    
                    # Try to find existing tenant stock
                    try:
                        tenant_stock = TenantStock.objects.get(**lookup_params)
                        created = False
                        
                        # ✅ Update BOTH available AND original quantities
                        tenant_stock.available_slab += slab_adjustment
                        tenant_stock.available_c_s += cs_adjustment
                        tenant_stock.available_kg += kg_adjustment
                        
                        tenant_stock.original_slab += slab_adjustment
                        tenant_stock.original_c_s += cs_adjustment
                        tenant_stock.original_kg += kg_adjustment
                        
                        if remarks:
                            tenant_stock.remarks = remarks
                        
                    except TenantStock.DoesNotExist:
                        # Create new tenant stock
                        created = True
                        tenant_stock = TenantStock(
                            tenant_company_name=tenant,
                            item=item,
                            brand=brand,
                            item_quality=item_quality,
                            unit=unit,
                            glaze=glaze,
                            grade=grade,
                            peeling_type=peeling_type,
                            freezing_category=freezing_category,
                            processing_center=processing_center,
                            store=store,
                            available_slab=slab_adjustment,
                            available_c_s=cs_adjustment,
                            available_kg=kg_adjustment,
                            original_slab=slab_adjustment,
                            original_c_s=cs_adjustment,
                            original_kg=kg_adjustment,
                            remarks=remarks
                        )
                    
                    # Check for negative stock
                    if tenant_stock.available_slab < 0 or tenant_stock.available_c_s < 0 or tenant_stock.available_kg < 0:
                        messages.warning(
                            request, 
                            f'Warning: Tenant stock adjusted but resulted in negative quantity. '
                            f'Available - Slab: {tenant_stock.available_slab}, CS: {tenant_stock.available_c_s}, KG: {tenant_stock.available_kg}'
                        )
                    
                    # ✅ Also check original quantities for negative values
                    if tenant_stock.original_slab < 0 or tenant_stock.original_c_s < 0 or tenant_stock.original_kg < 0:
                        messages.warning(
                            request, 
                            f'Warning: Original stock also resulted in negative quantity. '
                            f'Original - Slab: {tenant_stock.original_slab}, CS: {tenant_stock.original_c_s}, KG: {tenant_stock.original_kg}'
                        )
                    
                    tenant_stock.save()
                    
                    if created:
                        messages.success(
                            request, 
                            f'New tenant stock created for {tenant.company_name} - {tenant_stock.item.name}! '
                            f'Slab: {tenant_stock.available_slab}, CS: {tenant_stock.available_c_s}, KG: {tenant_stock.available_kg}'
                        )
                    else:
                        # Determine action based on total adjustment
                        total_adjustment = slab_adjustment + cs_adjustment + kg_adjustment
                        action = "increased" if total_adjustment > 0 else "decreased" if total_adjustment < 0 else "adjusted"
                        messages.success(
                            request, 
                            f'Tenant stock {action} for {tenant.company_name} - {tenant_stock.item.name}! '
                            f'Adjustment: Slab {slab_adjustment:+}, CS {cs_adjustment:+}, KG {kg_adjustment:+} | '
                            f'Available: Slab: {tenant_stock.available_slab}, CS: {tenant_stock.available_c_s}, KG: {tenant_stock.available_kg} | '
                            f'Original: Slab: {tenant_stock.original_slab}, CS: {tenant_stock.original_c_s}, KG: {tenant_stock.original_kg}'
                        )
                    
                    return redirect('adminapp:tenant_stock_list')
                    
            except Exception as e:
                messages.error(request, f'Error adjusting tenant stock: {str(e)}')
        else:
            # Show form validation errors
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f'{field}: {error}')
    else:
        form = TenantStockAdjustmentForm()
    
    context = {
        'form': form,
        'title': 'Tenant Stock Adjustment',
        'action': 'Adjust'
    }
    return render(request, 'adminapp/TenantStock/tenant_stock_adjustment.html', context)

def get_current_tenant_stock(request):
    """AJAX endpoint to get current tenant stock quantities"""
    if request.method == 'GET':
        tenant_id = request.GET.get('tenant')
        item_id = request.GET.get('item')
        brand_id = request.GET.get('brand')
        unit_id = request.GET.get('unit')
        glaze_id = request.GET.get('glaze')
        grade_id = request.GET.get('grade')
        freezing_category_id = request.GET.get('freezing_category')
        
        item_quality_id = request.GET.get('item_quality') or None
        peeling_type_id = request.GET.get('peeling_type') or None
        processing_center_id = request.GET.get('processing_center') or None
        store_id = request.GET.get('store') or None
        
        # Convert empty strings to None
        if item_quality_id == '':
            item_quality_id = None
        if peeling_type_id == '':
            peeling_type_id = None
        if processing_center_id == '':
            processing_center_id = None
        if store_id == '':
            store_id = None
        
        try:
            # Build lookup with direct values (allow both locations)
            tenant_stock = TenantStock.objects.get(
                tenant_company_name_id=tenant_id,
                item_id=item_id,
                brand_id=brand_id,
                unit_id=unit_id,
                glaze_id=glaze_id,
                grade_id=grade_id,
                freezing_category_id=freezing_category_id,
                item_quality_id=item_quality_id,
                peeling_type_id=peeling_type_id,
                processing_center_id=processing_center_id,
                store_id=store_id
            )
            
            return JsonResponse({
                'exists': True,
                'available_slab': float(tenant_stock.available_slab),
                'available_c_s': float(tenant_stock.available_c_s),
                'available_kg': float(tenant_stock.available_kg),
                'original_slab': float(tenant_stock.original_slab),
                'original_c_s': float(tenant_stock.original_c_s),
                'original_kg': float(tenant_stock.original_kg),
                'remarks': tenant_stock.remarks or ''
            })
        except TenantStock.DoesNotExist:
            return JsonResponse({
                'exists': False,
                'available_slab': 0,
                'available_c_s': 0,
                'available_kg': 0,
                'original_slab': 0,
                'original_c_s': 0,
                'original_kg': 0
            })
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    
    return JsonResponse({'error': 'Invalid request'}, status=400)

def tenant_stock_list(request):
    """List all tenant stocks with filtering and search"""
    tenant_stocks = TenantStock.objects.all().select_related(
        'tenant_company_name', 'item', 'brand', 'item_quality', 'unit',
        'glaze', 'species', 'grade', 'freezing_category',
        'processing_center', 'store', 'peeling_type'
    )
    
    # Filters
    tenant_id = request.GET.get('tenant')
    item_id = request.GET.get('item')
    brand_id = request.GET.get('brand')
    location_type = request.GET.get('location_type')
    location_id = request.GET.get('location_id')
    
    if tenant_id:
        tenant_stocks = tenant_stocks.filter(tenant_company_name_id=tenant_id)
    if item_id:
        tenant_stocks = tenant_stocks.filter(item_id=item_id)
    if brand_id:
        tenant_stocks = tenant_stocks.filter(brand_id=brand_id)
    if location_type == 'processing_center' and location_id:
        tenant_stocks = tenant_stocks.filter(processing_center_id=location_id)
    elif location_type == 'store' and location_id:
        tenant_stocks = tenant_stocks.filter(store_id=location_id)
    
    # Search by tenant name or item name
    search = request.GET.get('search')
    if search:
        tenant_stocks = tenant_stocks.filter(
            Q(tenant_company_name__name__icontains=search) |
            Q(item__name__icontains=search)
        )
    
    context = {
        'tenant_stocks': tenant_stocks,
        'title': 'Tenant Stock List',
        'tenants': Tenant.objects.all(),
        'items': Item.objects.all(),
        'brands': ItemBrand.objects.all(),
        'processing_centers': ProcessingCenter.objects.all(),
        'stores': Store.objects.all(),
    }
    return render(request, 'adminapp/TenantStock/tenant_stock_list.html', context)

def tenant_stock_delete(request, pk):
    """Delete tenant stock entry"""
    try:
        tenant_stock = TenantStock.objects.get(pk=pk)
        
        if request.method == 'POST':
            # Store info for success message
            tenant_name = tenant_stock.tenant_company_name.company_name
            item_name = tenant_stock.item.name
            
            # Delete the tenant stock
            tenant_stock.delete()
            
            messages.success(
                request,
                f'Tenant stock for {tenant_name} - {item_name} has been deleted successfully!'
            )
            return redirect('adminapp:tenant_stock_list')
        
        # GET request - show confirmation page
        context = {
            'tenant_stock': tenant_stock,
            'title': 'Delete Tenant Stock'
        }
        return render(request, 'adminapp/confirm_delete.html', context)
        
    except TenantStock.DoesNotExist:
        messages.error(request, 'Tenant stock not found.')
        return redirect('adminapp:tenant_stock_list')
    except Exception as e:
        messages.error(request, f'Error deleting tenant stock: {str(e)}')
        return redirect('adminapp:tenant_stock_list')




# Added by AGK 20-10-2025


from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import ListView
from django.http import JsonResponse
from django.db.models import Q
from adminapp.models import Notification
from adminapp.utils.notification_helper import get_unread_count, get_recent_notifications


class NotificationListView(LoginRequiredMixin, ListView):
    """
    Display all notifications for the current user
    """
    model = Notification
    template_name = 'adminapp/notification_list.html'
    context_object_name = 'notifications'
    paginate_by = 20
    
    def get_queryset(self):
        user = self.request.user
        
        # Get notifications targeted to this user or all users
        queryset = Notification.objects.filter(
            is_active=True
        ).filter(
            Q(target_users=user) | Q(target_users__isnull=True)
        ).select_related('user').distinct().order_by('-created_at')
        
        # Filter by type if specified
        notification_type = self.request.GET.get('type')
        if notification_type:
            queryset = queryset.filter(notification_type=notification_type)
        
        # Filter by action if specified
        action_type = self.request.GET.get('action')
        if action_type:
            queryset = queryset.filter(action_type=action_type)
        
        # Filter by read/unread status
        status = self.request.GET.get('status')
        if status == 'unread':
            queryset = queryset.exclude(read_by=user)
        elif status == 'read':
            queryset = queryset.filter(read_by=user)
        
        return queryset
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        
        # Add unread count
        context['unread_count'] = get_unread_count(user)
        
        # Add filter values
        context['current_type'] = self.request.GET.get('type', '')
        context['current_action'] = self.request.GET.get('action', '')
        context['current_status'] = self.request.GET.get('status', '')
        
        # Add notification types and actions for filters
        context['notification_types'] = Notification.NOTIFICATION_TYPES
        context['action_types'] = Notification.ACTION_TYPES
        
        # Mark which notifications are read by this user
        for notification in context['notifications']:
            notification.is_read = notification.is_read_by(user)
        
        return context


class UnreadNotificationsView(LoginRequiredMixin, ListView):
    """
    Display only unread notifications
    """
    model = Notification
    template_name = 'adminapp/notifications/notification_unread.html'
    context_object_name = 'notifications'
    paginate_by = 20
    
    def get_queryset(self):
        user = self.request.user
        
        queryset = Notification.objects.filter(
            is_active=True
        ).filter(
            Q(target_users=user) | Q(target_users__isnull=True)
        ).exclude(
            read_by=user
        ).select_related('user').distinct().order_by('-created_at')
        
        return queryset
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['unread_count'] = self.get_queryset().count()
        return context


@login_required
def mark_notification_read(request, pk):
    """
    Mark a single notification as read
    """
    notification = get_object_or_404(Notification, pk=pk, is_active=True)
    notification.mark_as_read(request.user)
    
    # If AJAX request, return JSON
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return JsonResponse({
            'success': True,
            'unread_count': get_unread_count(request.user)
        })
    
    # Otherwise redirect to the notification's link or back
    next_url = request.GET.get('next')
    if next_url:
        return redirect(next_url)
    elif notification.link_url:
        return redirect(notification.link_url)
    else:
        return redirect('adminapp:notification_list')


@login_required
def mark_all_notifications_read(request):
    """
    Mark all notifications as read for the current user
    """
    user = request.user
    
    # Get all unread notifications for this user
    unread_notifications = Notification.objects.filter(
        is_active=True
    ).filter(
        Q(target_users=user) | Q(target_users__isnull=True)
    ).exclude(read_by=user).distinct()
    
    # Mark all as read
    for notification in unread_notifications:
        notification.mark_as_read(user)
    
    # If AJAX request
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return JsonResponse({
            'success': True,
            'marked_count': unread_notifications.count(),
            'unread_count': 0
        })
    
    return redirect('adminapp:notification_list')


@login_required
def delete_notification(request, pk):
    """
    Delete (deactivate) a notification
    """
    notification = get_object_or_404(Notification, pk=pk)
    
    # Only allow user who created it or admins to delete
    if request.user == notification.user or request.user.is_superuser:
        notification.is_active = False
        notification.save()
    
    # If AJAX request
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return JsonResponse({
            'success': True,
            'unread_count': get_unread_count(request.user)
        })
    
    return redirect('adminapp:notification_list')


@login_required
def get_unread_count_ajax(request):

    """
    AJAX endpoint to get unread notification count
    """
    count = get_unread_count(request.user)
    return JsonResponse({'unread_count': count})



# adminapp/views/notification_views.py (add this function)

from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.shortcuts import render, redirect

@login_required
def test_notification(request):
    """
    Test view to create a notification
    """
    # Add a message
    messages.success(request, "This is a test notification!")
    messages.info(request, "This is an info message!")
    messages.warning(request, "This is a warning!")
    
    # Redirect to notifications list
    return redirect('adminapp:notification_list')


def local_purchase_profit_loss_report(request):
    """
    Generate profit/loss report for local purchases with filters and date range
    Only shows active records from all related models
    Fixed to match spot purchase overhead calculations exactly
    """
    from datetime import datetime, timedelta
    from django.db.models import Q, Sum, Count
    from decimal import Decimal
    from django.http import JsonResponse
    from django.shortcuts import render
    
    # Get filter parameters
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    quick_filter = request.GET.get('quick_filter', '')
    selected_parties = request.GET.getlist('parties')
    selected_items = request.GET.getlist('items')
    selected_species = request.GET.getlist('species')
    selected_item_categories = request.GET.getlist('item_categories')
    selected_item_qualities = request.GET.getlist('item_qualities')
    selected_item_types = request.GET.getlist('item_types')
    selected_item_grades = request.GET.getlist('item_grades')
    selected_item_brands = request.GET.getlist('item_brands')
    selected_freezing_categories = request.GET.getlist('freezing_categories')
    selected_processing_centers = request.GET.getlist('processing_centers')
    selected_stores = request.GET.getlist('stores')
    selected_packing_units = request.GET.getlist('packing_units')
    selected_glaze_percentages = request.GET.getlist('glaze_percentages')
    profit_filter = request.GET.get('profit_filter', 'all')
    format_type = request.GET.get('format', 'html')
    
    # Calculate dates based on quick filter or use today as default
    today = datetime.now().date()
    
    if quick_filter:
        start_date_obj, end_date_obj = calculate_quick_filter_dates(quick_filter, today)
        start_date = start_date_obj.strftime('%Y-%m-%d')
        end_date = end_date_obj.strftime('%Y-%m-%d')
    else:
        # Default to today if no dates specified
        if not start_date:
            start_date = today.strftime('%Y-%m-%d')
        if not end_date:
            end_date = today.strftime('%Y-%m-%d')
        
        try:
            start_date_obj = datetime.strptime(start_date, '%Y-%m-%d').date()
            end_date_obj = datetime.strptime(end_date, '%Y-%m-%d').date()
        except ValueError:
            error_msg = 'Invalid date format. Use YYYY-MM-DD'
            if format_type == 'json':
                return JsonResponse({'error': error_msg})
            else:
                context = {'error': error_msg, 'report_data': []}
                return render(request, 'local_purchase_profit_loss_report.html', context)
    
    try:
        # Base query for local purchases within date range
        local_purchases = LocalPurchase.objects.filter(
            date__range=[start_date_obj, end_date_obj]
        ).prefetch_related('items', 'party_name')
        
        # Apply party filter (LocalParty doesn't have is_active field)
        if selected_parties:
            local_purchases = local_purchases.filter(party_name__id__in=selected_parties)
        
        # Apply item filter (Item doesn't have is_active field)
        if selected_items:
            local_purchases = local_purchases.filter(items__item__id__in=selected_items).distinct()
        
        # Apply species filter (Species doesn't have is_active field)
        if selected_species:
            local_purchases = local_purchases.filter(items__species__id__in=selected_species).distinct()
        
        # Apply item category filter
        if selected_item_categories:
            local_purchases = local_purchases.filter(items__item__category__id__in=selected_item_categories).distinct()
        
        # Apply item quality filter
        if selected_item_qualities:
            local_purchases = local_purchases.filter(items__item_quality__id__in=selected_item_qualities).distinct()
        
        # Apply item type filter
        if selected_item_types:
            local_purchases = local_purchases.filter(items__item_type__id__in=selected_item_types).distinct()
        
        # Apply item grade filter
        if selected_item_grades:
            local_purchases = local_purchases.filter(items__grade__id__in=selected_item_grades).distinct()
        
        if not local_purchases.exists():
            message = f'No local purchases found for the selected criteria'
            if format_type == 'json':
                return JsonResponse({'message': message, 'total_purchases': 0})
            else:
                # Get filter options for template - only active records
                context = get_filter_context(
                    quick_filter, start_date, end_date, 
                    selected_parties, selected_items, selected_species, 
                    profit_filter, message,
                    selected_item_categories=selected_item_categories,
                    selected_item_qualities=selected_item_qualities,
                    selected_item_types=selected_item_types,
                    selected_item_grades=selected_item_grades,
                    selected_item_brands=selected_item_brands,
                    selected_freezing_categories=selected_freezing_categories,
                    selected_processing_centers=selected_processing_centers,
                    selected_stores=selected_stores,
                    selected_packing_units=selected_packing_units,
                    selected_glaze_percentages=selected_glaze_percentages
                )
                return render(request, 'local_purchase_profit_loss_report.html', context)
        
        # Get overhead totals (LOCAL PURCHASES DON'T HAVE PEELING)
        # FIXED: Get ALL active overhead records and sum them - EXACTLY like print version
        purchase_overheads = PurchaseOverhead.objects.filter(is_active=True)
        purchase_overhead_total = Decimal('0.00')
        if purchase_overheads.exists():
            for overhead in purchase_overheads:
                if hasattr(overhead, 'other_expenses') and overhead.other_expenses:
                    purchase_overhead_total += Decimal(str(overhead.other_expenses))
        
        processing_overheads = ProcessingOverhead.objects.filter(is_active=True)
        processing_overhead_total = Decimal('0.00')
        if processing_overheads.exists():
            for overhead in processing_overheads:
                if hasattr(overhead, 'amount') and overhead.amount:
                    processing_overhead_total += Decimal(str(overhead.amount))
        
        shipment_overheads = ShipmentOverhead.objects.filter(is_active=True)
        shipment_overhead_total = Decimal('0.00')
        if shipment_overheads.exists():
            for overhead in shipment_overheads:
                if hasattr(overhead, 'amount') and overhead.amount:
                    shipment_overhead_total += Decimal(str(overhead.amount))
        
        # Calculate profit/loss for each purchase
        report_data = []
        summary = {
            'total_purchases': 0,
            'total_purchase_amount': Decimal('0.00'),
            'total_purchase_overhead': Decimal('0.00'),
            'total_processing_overhead': Decimal('0.00'),
            'total_shipment_overhead': Decimal('0.00'),
            'total_all_overheads': Decimal('0.00'),
            'total_freezing_tariff': Decimal('0.00'),
            'total_cost': Decimal('0.00'),
            'total_revenue': Decimal('0.00'),
            'total_profit_loss': Decimal('0.00'),
            'profit_count': 0,
            'loss_count': 0,
            'break_even_count': 0
        }
        
        for purchase in local_purchases:
            # Get purchase cost
            purchase_cost = purchase.total_amount or Decimal('0.00')
            
            # Calculate freezing revenue and collect total kg for overhead calculations
            freezing_revenue = Decimal('0.00')
            total_kg = Decimal('0.00')
            total_freezing_tariff = Decimal('0.00')
            
            freezing_entries = FreezingEntryLocal.objects.filter(
                party=purchase
            ).prefetch_related('items__item', 'items__freezing_category')
            
            # Apply freezing entry filters
            if selected_item_brands:
                freezing_entries = freezing_entries.filter(items__brand__id__in=selected_item_brands).distinct()
            
            if selected_freezing_categories:
                freezing_entries = freezing_entries.filter(
                    items__freezing_category__id__in=selected_freezing_categories,
                    items__freezing_category__is_active=True
                ).distinct()
            
            if selected_processing_centers:
                freezing_entries = freezing_entries.filter(
                    items__processing_center__id__in=selected_processing_centers,
                    items__processing_center__is_active=True
                ).distinct()
            
            if selected_stores:
                freezing_entries = freezing_entries.filter(
                    items__store__id__in=selected_stores,
                    items__store__is_active=True
                ).distinct()
            
            if selected_packing_units:
                freezing_entries = freezing_entries.filter(items__unit__id__in=selected_packing_units).distinct()
            
            if selected_glaze_percentages:
                freezing_entries = freezing_entries.filter(items__glaze__id__in=selected_glaze_percentages).distinct()
            
            for entry in freezing_entries:
                for item in entry.items.all():
                    item_revenue = item.usd_rate_item_to_inr or Decimal('0.00')
                    freezing_revenue += item_revenue
                    total_kg += item.kg or Decimal('0.00')
                    
                    # Calculate freezing category tariff (ONLY ACTIVE CATEGORIES)
                    if (item.freezing_category and 
                        item.freezing_category.is_active and 
                        item.freezing_category.tariff):
                        tariff_cost = (item.kg or Decimal('0.00')) * Decimal(str(item.freezing_category.tariff))
                        total_freezing_tariff += tariff_cost
            
            # FIXED: Calculate ALL overheads EXACTLY like print version
            # ALL rates multiply by TOTAL PRODUCTION QUANTITY (total_kg)
            purchase_overhead_amount = total_kg * purchase_overhead_total
            processing_overhead_amount = total_kg * processing_overhead_total
            shipment_overhead_amount = total_kg * shipment_overhead_total
            
            # Calculate total of all overheads (NO peeling for local purchases)
            total_all_overheads = (
                purchase_overhead_amount + 
                processing_overhead_amount + 
                shipment_overhead_amount
            )
            
            # Calculate total cost including ALL overheads
            total_cost = (
                purchase_cost + 
                total_all_overheads + 
                total_freezing_tariff
            )
            
            # Calculate profit/loss
            profit_loss = freezing_revenue - total_cost
            
            # Calculate profit percentage
            if total_cost > 0:
                profit_percentage = (profit_loss / total_cost * 100)
            else:
                profit_percentage = 0
            
            # Determine profit status
            if profit_loss > 0:
                profit_status = 'Profit'
                summary['profit_count'] += 1
            elif profit_loss < 0:
                profit_status = 'Loss'
                summary['loss_count'] += 1
            else:
                profit_status = 'Break Even'
                summary['break_even_count'] += 1
            
            purchase_data = {
                'id': purchase.id,
                'date': purchase.date,
                'voucher_number': purchase.voucher_number,
                'party_name': purchase.party_name.party if purchase.party_name else 'N/A',
                'purchase_amount': float(purchase_cost),
                'purchase_overhead': float(purchase_overhead_amount),
                'processing_overhead': float(processing_overhead_amount),
                'shipment_overhead': float(shipment_overhead_amount),
                'total_all_overheads': float(total_all_overheads),
                'freezing_tariff': float(total_freezing_tariff),
                'total_cost': float(total_cost),
                'freezing_revenue': float(freezing_revenue),
                'profit_loss': float(profit_loss),
                'profit_percentage': float(profit_percentage),
                'profit_status': profit_status,
                'freezing_entries_count': freezing_entries.count(),
                'total_items': sum(entry.items.count() for entry in freezing_entries),
                'total_kg': float(total_kg)
            }
            
            # Apply profit filter
            if profit_filter == 'profit' and profit_loss <= 0:
                continue
            elif profit_filter == 'loss' and profit_loss >= 0:
                continue
            
            report_data.append(purchase_data)
            
            # Update summary
            summary['total_purchase_amount'] += purchase_cost
            summary['total_purchase_overhead'] += purchase_overhead_amount
            summary['total_processing_overhead'] += processing_overhead_amount
            summary['total_shipment_overhead'] += shipment_overhead_amount
            summary['total_all_overheads'] += total_all_overheads
            summary['total_freezing_tariff'] += total_freezing_tariff
            summary['total_cost'] += total_cost
            summary['total_revenue'] += freezing_revenue
            summary['total_profit_loss'] += profit_loss
        
        # Calculate final summary
        summary['total_purchases'] = len(report_data)
        
        # Recalculate total_all_overheads from the three overhead components
        summary['total_all_overheads'] = (
            summary['total_purchase_overhead'] + 
            summary['total_processing_overhead'] + 
            summary['total_shipment_overhead']
        )
        
        if summary['total_cost'] > 0:
            summary['overall_profit_margin'] = float(summary['total_profit_loss'] / summary['total_cost'] * 100)
        else:
            summary['overall_profit_margin'] = 0
        
        # Convert Decimal to float for JSON serialization
        for key in ['total_purchase_amount', 'total_purchase_overhead', 'total_processing_overhead',
                   'total_shipment_overhead', 'total_all_overheads', 'total_freezing_tariff', 
                   'total_cost', 'total_revenue', 'total_profit_loss']:
            summary[key] = float(summary[key])
        
        # Add overhead rates to summary
        summary['purchase_overhead_rate'] = float(purchase_overhead_total)
        summary['processing_overhead_rate'] = float(processing_overhead_total)
        summary['shipment_overhead_rate'] = float(shipment_overhead_total)
        
        # Sort by date (newest first)
        report_data.sort(key=lambda x: x['date'], reverse=True)
        
        # Return based on format
        if format_type == 'json':
            return JsonResponse({
                'success': True,
                'date_range': {'start': start_date, 'end': end_date},
                'summary': summary,
                'data': report_data,
                'filters': {
                    'parties': selected_parties,
                    'items': selected_items,
                    'species': selected_species,
                    'item_categories': selected_item_categories,
                    'item_qualities': selected_item_qualities,
                    'item_types': selected_item_types,
                    'item_grades': selected_item_grades,
                    'item_brands': selected_item_brands,
                    'freezing_categories': selected_freezing_categories,
                    'processing_centers': selected_processing_centers,
                    'stores': selected_stores,
                    'packing_units': selected_packing_units,
                    'glaze_percentages': selected_glaze_percentages,
                    'profit_filter': profit_filter,
                    'quick_filter': quick_filter
                }
            })
        
        # Get filter options for template - only active records
        context = get_filter_context(
            quick_filter, start_date, end_date,
            selected_parties, selected_items, selected_species,
            profit_filter, None, report_data, summary,
            selected_item_categories=selected_item_categories,
            selected_item_qualities=selected_item_qualities,
            selected_item_types=selected_item_types,
            selected_item_grades=selected_item_grades,
            selected_item_brands=selected_item_brands,
            selected_freezing_categories=selected_freezing_categories,
            selected_processing_centers=selected_processing_centers,
            selected_stores=selected_stores,
            selected_packing_units=selected_packing_units,
            selected_glaze_percentages=selected_glaze_percentages
        )
        
        template = 'local_purchase_profit_loss_report_print.html' if format_type == 'print' else 'local_purchase_profit_loss_report.html'
        return render(request, template, context)
        
    except Exception as e:
        import traceback
        error_msg = f'An error occurred: {str(e)}'
        print(f"DEBUG - Full error traceback:\n{traceback.format_exc()}")
        
        if format_type == 'json':
            return JsonResponse({'error': error_msg})
        else:
            context = get_filter_context(
                quick_filter, start_date, end_date,
                selected_parties, selected_items, selected_species,
                profit_filter, error_msg,
                selected_item_categories=selected_item_categories,
                selected_item_qualities=selected_item_qualities,
                selected_item_types=selected_item_types,
                selected_item_grades=selected_item_grades,
                selected_item_brands=selected_item_brands,
                selected_freezing_categories=selected_freezing_categories,
                selected_processing_centers=selected_processing_centers,
                selected_stores=selected_stores,
                selected_packing_units=selected_packing_units,
                selected_glaze_percentages=selected_glaze_percentages
            )
            return render(request, 'local_purchase_profit_loss_report.html', context)

def get_filter_context(quick_filter, start_date, end_date, selected_parties, 
                       selected_items, selected_species, profit_filter, 
                       message=None, report_data=None, summary=None,
                       selected_item_categories=None, selected_item_qualities=None,
                       selected_item_types=None, selected_item_grades=None,
                       selected_item_brands=None, selected_freezing_categories=None,
                       selected_processing_centers=None, selected_stores=None,
                       selected_packing_units=None, selected_glaze_percentages=None):
    """
    Helper function to get filter context with only active records
    """
    # Get ALL filter options - only active records where applicable
    parties = LocalParty.objects.all().order_by('party')  # No is_active field
    items = Item.objects.all().order_by('name')  # No is_active field
    all_species = Species.objects.all().order_by('name')  # No is_active field
    item_categories = ItemCategory.objects.all().order_by('name')  # No is_active field
    item_qualities = ItemQuality.objects.all().order_by('quality')  # No is_active field
    item_types = ItemType.objects.all().order_by('name')  # No is_active field
    item_grades = ItemGrade.objects.all().order_by('grade')  # No is_active field
    item_brands = ItemBrand.objects.all().order_by('name')  # No is_active field
    packing_units = PackingUnit.objects.all().order_by('unit_code')  # No is_active field
    glaze_percentages = GlazePercentage.objects.all().order_by('percentage')  # No is_active field
    
    # Get active processing centers, stores and freezing categories
    processing_centers = ProcessingCenter.objects.filter(is_active=True).order_by('name')
    stores = Store.objects.filter(is_active=True).order_by('name')
    freezing_categories = FreezingCategory.objects.filter(is_active=True).order_by('name')
    
    context = {
        'quick_filter': quick_filter,
        'start_date': start_date,
        'end_date': end_date,
        'parties': parties,
        'items': items,
        'all_species': all_species,
        'item_categories': item_categories,
        'item_qualities': item_qualities,
        'item_types': item_types,
        'item_grades': item_grades,
        'item_brands': item_brands,
        'freezing_categories': freezing_categories,
        'processing_centers': processing_centers,
        'stores': stores,
        'packing_units': packing_units,
        'glaze_percentages': glaze_percentages,
        'selected_parties': selected_parties or [],
        'selected_items': selected_items or [],
        'selected_species': selected_species or [],
        'selected_item_categories': selected_item_categories or [],
        'selected_item_qualities': selected_item_qualities or [],
        'selected_item_types': selected_item_types or [],
        'selected_item_grades': selected_item_grades or [],
        'selected_item_brands': selected_item_brands or [],
        'selected_freezing_categories': selected_freezing_categories or [],
        'selected_processing_centers': selected_processing_centers or [],
        'selected_stores': selected_stores or [],
        'selected_packing_units': selected_packing_units or [],
        'selected_glaze_percentages': selected_glaze_percentages or [],
        'profit_filter': profit_filter,
        'date_range_text': get_date_range_text(quick_filter, start_date, end_date),
    }
    
    if message:
        context['message'] = message
        context['report_data'] = []
    elif report_data is not None:
        context['report_data'] = report_data
        context['summary'] = summary
    else:
        context['report_data'] = []
    
    return context

def get_date_range_text(quick_filter, start_date, end_date):
    """Generate human-readable date range text"""
    if quick_filter:
        filter_texts = {
            'today': 'Today',
            'yesterday': 'Yesterday',
            'this_week': 'This Week',
            'last_week': 'Last Week',
            'this_month': 'This Month',
            'last_month': 'Last Month',
            'this_quarter': 'This Quarter',
            'last_quarter': 'Last Quarter',
            'this_year': 'This Year',
            'last_year': 'Last Year',
        }
        return filter_texts.get(quick_filter, f'{start_date} to {end_date}')
    return f'{start_date} to {end_date}'

def calculate_quick_filter_dates(filter_type, today):
    """Calculate date ranges for quick filters"""
    from datetime import timedelta
    
    if filter_type == 'today':
        return today, today
    
    elif filter_type == 'yesterday':
        yesterday = today - timedelta(days=1)
        return yesterday, yesterday
    
    elif filter_type == 'this_week':
        week_start = today - timedelta(days=today.weekday())
        return week_start, today
    
    elif filter_type == 'last_week':
        week_start = today - timedelta(days=today.weekday() + 7)
        week_end = week_start + timedelta(days=6)
        return week_start, week_end
    
    elif filter_type == 'this_month':
        month_start = today.replace(day=1)
        return month_start, today
    
    elif filter_type == 'last_month':
        last_month_end = today.replace(day=1) - timedelta(days=1)
        last_month_start = last_month_end.replace(day=1)
        return last_month_start, last_month_end
    
    elif filter_type == 'this_quarter':
        quarter = (today.month - 1) // 3
        quarter_start = today.replace(month=quarter * 3 + 1, day=1)
        return quarter_start, today
    
    elif filter_type == 'last_quarter':
        quarter = (today.month - 1) // 3
        if quarter == 0:
            last_quarter_start = today.replace(year=today.year - 1, month=10, day=1)
            last_quarter_end = today.replace(year=today.year - 1, month=12, day=31)
        else:
            last_quarter_start = today.replace(month=(quarter - 1) * 3 + 1, day=1)
            last_quarter_end = today.replace(month=quarter * 3, day=1) - timedelta(days=1)
        return last_quarter_start, last_quarter_end
    
    elif filter_type == 'this_year':
        year_start = today.replace(month=1, day=1)
        return year_start, today
    
    elif filter_type == 'last_year':
        last_year_start = today.replace(year=today.year - 1, month=1, day=1)
        last_year_end = today.replace(year=today.year - 1, month=12, day=31)
        return last_year_start, last_year_end
    
    return today, today

def local_purchase_profit_loss_report_print(request):
    """
    Generate comprehensive print report with correct calculations matching spot purchase format
    """
    from datetime import datetime
    from django.db.models import Sum
    from decimal import Decimal
    from django.shortcuts import render
    
    # Get filter parameters
    quick_filter = request.GET.get('quick_filter', '')
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    
    # Filters
    selected_parties = request.GET.getlist('parties')
    selected_items = request.GET.getlist('items')
    selected_item_categories = request.GET.getlist('item_categories')
    selected_item_qualities = request.GET.getlist('item_qualities')
    selected_item_types = request.GET.getlist('item_types')
    selected_item_grades = request.GET.getlist('item_grades')
    selected_item_brands = request.GET.getlist('item_brands')
    selected_freezing_categories = request.GET.getlist('freezing_categories')
    selected_processing_centers = request.GET.getlist('processing_centers')
    selected_stores = request.GET.getlist('stores')
    selected_packing_units = request.GET.getlist('packing_units')
    selected_glaze_percentages = request.GET.getlist('glaze_percentages')
    profit_filter = request.GET.get('profit_filter', 'all')
    
    # Calculate dates
    today = datetime.now().date()
    
    if quick_filter:
        start_date_obj, end_date_obj = calculate_quick_filter_dates(quick_filter, today)
        start_date = start_date_obj.strftime('%Y-%m-%d')
        end_date = end_date_obj.strftime('%Y-%m-%d')
    else:
        if not start_date:
            start_date = today.strftime('%Y-%m-%d')
        if not end_date:
            end_date = today.strftime('%Y-%m-%d')
        
        try:
            start_date_obj = datetime.strptime(start_date, '%Y-%m-%d').date()
            end_date_obj = datetime.strptime(end_date, '%Y-%m-%d').date()
        except ValueError:
            context = {'error': 'Invalid date format'}
            return render(request, 'local_purchase_profit_loss_report_print.html', context)
    
    try:
        # Get USD rate from Settings
        try:
            active_settings = Settings.objects.filter(is_active=True).first()
            usd_rate = active_settings.dollar_rate_to_inr if active_settings else Decimal('84.00')
        except:
            usd_rate = Decimal('84.00')
        
        # Base query
        local_purchases = LocalPurchase.objects.filter(
            date__range=[start_date_obj, end_date_obj]
        ).prefetch_related(
            'items__item',
            'items__item__category',
            'items__item_quality',
            'items__item_type',
            'items__grade',
            'party_name'
        ).select_related('party_name')
        
        # Apply filters
        if selected_parties:
            local_purchases = local_purchases.filter(party_name__id__in=selected_parties)
        
        if selected_items:
            local_purchases = local_purchases.filter(items__item__id__in=selected_items).distinct()
        
        if selected_item_categories:
            local_purchases = local_purchases.filter(items__item__category__id__in=selected_item_categories).distinct()
        
        if selected_item_qualities:
            local_purchases = local_purchases.filter(items__item_quality__id__in=selected_item_qualities).distinct()
        
        if selected_item_types:
            local_purchases = local_purchases.filter(items__item_type__id__in=selected_item_types).distinct()
        
        if selected_item_grades:
            local_purchases = local_purchases.filter(items__grade__id__in=selected_item_grades).distinct()
        
        # Apply freezing-level filters
        if any([selected_item_brands, selected_freezing_categories, selected_processing_centers, 
                selected_stores, selected_packing_units, selected_glaze_percentages]):
            
            freezing_query = FreezingEntryLocalItem.objects.all()
            
            if selected_item_brands:
                freezing_query = freezing_query.filter(brand__id__in=selected_item_brands)
            if selected_freezing_categories:
                freezing_query = freezing_query.filter(freezing_category__id__in=selected_freezing_categories)
            if selected_processing_centers:
                freezing_query = freezing_query.filter(processing_center__id__in=selected_processing_centers)
            if selected_stores:
                freezing_query = freezing_query.filter(store__id__in=selected_stores)
            if selected_packing_units:
                freezing_query = freezing_query.filter(unit__id__in=selected_packing_units)
            if selected_glaze_percentages:
                freezing_query = freezing_query.filter(glaze__id__in=selected_glaze_percentages)
            
            matching_purchase_ids = freezing_query.values_list(
                'freezing_entry__party__id', flat=True
            ).distinct()
            
            local_purchases = local_purchases.filter(id__in=matching_purchase_ids)
        
        if not local_purchases.exists():
            context = {
                'message': 'No local purchases found',
                'report_data': [],
                'usd_rate': float(usd_rate),
                'date_range_text': get_date_range_text(quick_filter, start_date, end_date)
            }
            return render(request, 'local_purchase_profit_loss_report_print.html', context)
        
        # Get overhead totals (LOCAL PURCHASES DON'T HAVE PEELING)
        # FIXED: Get ALL active overhead records and sum them
        purchase_overheads = PurchaseOverhead.objects.filter(is_active=True)
        purchase_overhead_total = Decimal('0.00')
        if purchase_overheads.exists():
            for overhead in purchase_overheads:
                if hasattr(overhead, 'other_expenses') and overhead.other_expenses:
                    purchase_overhead_total += Decimal(str(overhead.other_expenses))
        
        processing_overheads = ProcessingOverhead.objects.filter(is_active=True)
        processing_overhead_total = Decimal('0.00')
        if processing_overheads.exists():
            for overhead in processing_overheads:
                if hasattr(overhead, 'amount') and overhead.amount:
                    processing_overhead_total += Decimal(str(overhead.amount))
        
        shipment_overheads = ShipmentOverhead.objects.filter(is_active=True)
        shipment_overhead_total = Decimal('0.00')
        if shipment_overheads.exists():
            for overhead in shipment_overheads:
                if hasattr(overhead, 'amount') and overhead.amount:
                    shipment_overhead_total += Decimal(str(overhead.amount))
        
        # DEBUG OUTPUT (remove in production)
        print(f"Purchase Overhead Total: {purchase_overhead_total}")
        print(f"Processing Overhead Total: {processing_overhead_total}")
        print(f"Shipment Overhead Total: {shipment_overhead_total}")
        
        # Process each purchase
        report_data = []
        summary = {
            'total_purchases': 0,
            'total_purchase_quantity': Decimal('0.00'),
            'total_purchase_amount': Decimal('0.00'),
            'total_purchase_overhead': Decimal('0.00'),
            'total_processing_overhead': Decimal('0.00'),
            'total_shipment_overhead': Decimal('0.00'),
            'total_all_overheads': Decimal('0.00'),
            'total_freezing_tariff': Decimal('0.00'),
            'total_cost': Decimal('0.00'),
            'total_revenue': Decimal('0.00'),
            'total_profit_loss': Decimal('0.00'),
            'profit_count': 0,
            'loss_count': 0,
            'break_even_count': 0
        }
        
        for purchase in local_purchases:
            # 1. PURCHASE QUANTITY = total_quantity
            purchase_quantity = purchase.total_quantity or Decimal('0.00')
            
            # 2. PURCHASE AMOUNT = total_amount
            purchase_amount = purchase.total_amount or Decimal('0.00')
            
            # 3. COST/KG = purchase_amount / purchase_quantity
            cost_per_kg = Decimal('0.00')
            if purchase_quantity > 0:
                cost_per_kg = purchase_amount / purchase_quantity
            
            # Get freezing entries
            freezing_entries = FreezingEntryLocal.objects.filter(
                party=purchase
            ).prefetch_related(
                'items__item',
                'items__item_quality',
                'items__peeling_type',
                'items__grade',
                'items__processing_center',
                'items__store',
                'items__unit',
                'items__glaze',
                'items__freezing_category',
                'items__brand'
            )
            
            # Calculate freezing revenue and items
            freezing_revenue = Decimal('0.00')
            freezing_items = []
            total_freezing_kg = Decimal('0.00')
            total_freezing_usd = Decimal('0.00')
            total_freezing_tariff = Decimal('0.00')
            freezing_tariff_breakdown = []
            processing_details = []
            
            for entry in freezing_entries:
                for item in entry.items.all():
                    item_revenue = item.usd_rate_item_to_inr or Decimal('0.00')
                    item_usd = item.usd_rate_item or Decimal('0.00')
                    freezing_revenue += item_revenue
                    total_freezing_usd += item_usd
                    total_freezing_kg += item.kg or Decimal('0.00')
                    
                    # Freezing tariff
                    item_tariff_cost = Decimal('0.00')
                    if (item.freezing_category and 
                        item.freezing_category.is_active and 
                        hasattr(item.freezing_category, 'tariff') and 
                        item.freezing_category.tariff):
                        item_tariff_cost = (item.kg or Decimal('0.00')) * Decimal(str(item.freezing_category.tariff))
                        total_freezing_tariff += item_tariff_cost
                        
                        # Tariff breakdown
                        existing = next((t for t in freezing_tariff_breakdown 
                                       if t['category_name'] == item.freezing_category.name), None)
                        if existing:
                            existing['quantity'] += float(item.kg or 0)
                            existing['amount'] += float(item_tariff_cost)
                        else:
                            freezing_tariff_breakdown.append({
                                'category_name': item.freezing_category.name,
                                'tariff_rate': float(item.freezing_category.tariff),
                                'quantity': float(item.kg or 0),
                                'amount': float(item_tariff_cost)
                            })
                    
                    # Processing details
                    processing_details.append({
                        'item_quality': item.item_quality.quality if item.item_quality else 'N/A',
                        'packing': f"{item.unit.unit_code if item.unit else ''} - {item.glaze.percentage if item.glaze else ''}%",
                        'unit': item.unit.unit_code if item.unit else 'N/A',
                        'grade': f"{item.peeling_type.name if item.peeling_type else ''}, {item.grade.grade if item.grade else ''}",
                        'total_slab': float(item.slab_quantity or 0),
                        'total_quantity': float(item.kg or 0),
                        'price_usd': float(item.usd_rate_per_kg or 0),
                        'amount_usd': float(item.usd_rate_item or 0),
                        'amount_inr': float(item.usd_rate_item_to_inr or 0)
                    })
                    
                    # Freezing items
                    freezing_items.append({
                        'item_name': item.item.name if item.item else 'N/A',
                        'item_quality': item.item_quality.quality if item.item_quality else 'N/A',
                        'peeling_type': item.peeling_type.name if item.peeling_type else 'N/A',
                        'processing_center': item.processing_center.name if item.processing_center else 'N/A',
                        'store': item.store.name if item.store else 'N/A',
                        'freezing_category': item.freezing_category.name if item.freezing_category else 'N/A',
                        'kg': float(item.kg or 0),
                        'usd_rate_per_kg': float(item.usd_rate_per_kg or 0),
                        'usd_rate_item': float(item.usd_rate_item or 0),
                        'usd_rate_item_to_inr': float(item.usd_rate_item_to_inr or 0),
                        'slab_quantity': float(item.slab_quantity or 0),
                        'c_s_quantity': float(item.c_s_quantity or 0),
                        'unit': item.unit.unit_code if item.unit else 'N/A',
                        'glaze': f"{item.glaze.percentage}%" if item.glaze else 'N/A',
                        'brand': item.brand.name if item.brand else 'N/A',
                        'grade': f"{item.grade.grade if item.grade else 'N/A'}",
                        'tariff_cost': float(item_tariff_cost)
                    })
            
            # Calculate overheads - ALL rates multiply by TOTAL PRODUCTION QUANTITY
            purchase_overhead_amount = total_freezing_kg * purchase_overhead_total
            processing_overhead_amount = total_freezing_kg * processing_overhead_total
            shipment_overhead_amount = total_freezing_kg * shipment_overhead_total
            
            # TOTAL PROCESSING EXP = sum of all overheads
            total_all_overheads = (
                purchase_overhead_amount +
                processing_overhead_amount +
                shipment_overhead_amount
            )
            
            # INCOME = TOTAL AMOUNT/INR - TOTAL PROCESSING EXP
            income = freezing_revenue - total_all_overheads
            
            # PROCESSING OVERHEADS PER KG
            processing_overhead_per_kg = Decimal('0.00')
            if total_freezing_kg > 0:
                processing_overhead_per_kg = total_all_overheads / total_freezing_kg
            
            # Calculate totals
            total_slabs = sum(detail['total_slab'] for detail in processing_details)
            avg_price_usd = Decimal('0.00')
            if total_freezing_kg > 0:
                avg_price_usd = total_freezing_usd / total_freezing_kg
            
            # Grand Total Cost
            grand_total_cost = (
                purchase_amount +
                purchase_overhead_amount +
                processing_overhead_amount +
                shipment_overhead_amount +
                total_freezing_tariff
            )
            
            # Total Profit/Loss
            total_profit_loss = freezing_revenue - grand_total_cost
            
            # Profit/Loss Per KG
            profit_loss_per_kg = Decimal('0.00')
            if total_freezing_kg > 0:
                profit_loss_per_kg = total_profit_loss / total_freezing_kg
            
            if grand_total_cost > 0:
                profit_percentage = (total_profit_loss / grand_total_cost * 100)
            else:
                profit_percentage = Decimal('0.00')
            
            if total_profit_loss > 0:
                profit_status = 'Profit'
                summary['profit_count'] += 1
            elif total_profit_loss < 0:
                profit_status = 'Loss'
                summary['loss_count'] += 1
            else:
                profit_status = 'Break Even'
                summary['break_even_count'] += 1
            
            # Apply profit filter
            if profit_filter == 'profit' and total_profit_loss <= 0:
                continue
            elif profit_filter == 'loss' and total_profit_loss >= 0:
                continue
            
            # Get purchase items
            purchase_items = []
            purchase_item_names = []
            for item in purchase.items.all():
                item_name = item.item.name if item.item else 'N/A'
                purchase_items.append({
                    'item_name': item_name,
                    'item_quality': item.item_quality.quality if item.item_quality else 'N/A',
                    'item_type': item.item_type.name if item.item_type else 'N/A',
                    'grade': f"{item.grade.grade if item.grade else 'N/A'}",
                    'quantity': float(item.quantity or 0),
                    'rate': float(item.rate or 0),
                    'amount': float(item.amount or 0)
                })
                if item.item and item.item.name and item.item.name not in purchase_item_names:
                    purchase_item_names.append(item.item.name)
            
            purchase_item_names_str = ', '.join(purchase_item_names) if purchase_item_names else 'N/A'
            
            # Overhead breakdown - FIXED: Now showing individual overheads correctly
            overhead_breakdown = [
                {'type': 'Purchase Overhead', 'rate': float(purchase_overhead_total), 'amount': float(purchase_overhead_amount)},
                {'type': 'Processing Overhead', 'rate': float(processing_overhead_total), 'amount': float(processing_overhead_amount)},
                {'type': 'Shipment Overhead', 'rate': float(shipment_overhead_total), 'amount': float(shipment_overhead_amount)},
            ]
            
            purchase_data = {
                'id': purchase.id,
                'date': purchase.date,
                'voucher_number': purchase.voucher_number or '',
                'party_name': purchase.party_name.party if purchase.party_name else 'N/A',
                
                # Calculations
                'purchase_quantity': float(purchase_quantity),
                'purchase_amount': float(purchase_amount),
                'cost_per_kg': float(cost_per_kg),
                
                'purchase_overhead': float(purchase_overhead_amount),
                'processing_overhead': float(processing_overhead_amount),
                'shipment_overhead': float(shipment_overhead_amount),
                'freezing_tariff': float(total_freezing_tariff),
                
                'total_all_overheads': float(total_all_overheads),
                'income': float(income),
                'processing_overhead_per_kg': float(processing_overhead_per_kg),
                'total_slabs': total_slabs,
                'avg_price_usd': float(avg_price_usd),
                'total_kg_processed': float(total_freezing_kg),
                
                'grand_total_cost': float(grand_total_cost),
                'freezing_revenue': float(freezing_revenue),
                'total_freezing_usd': float(total_freezing_usd),
                'total_freezing_kg': float(total_freezing_kg),
                
                'total_profit_loss': float(total_profit_loss),
                'profit_loss_per_kg': float(profit_loss_per_kg),
                'profit_percentage': float(profit_percentage),
                'profit_status': profit_status,
                
                # Detailed breakdowns
                'purchase_items': purchase_items,
                'purchase_item_names': purchase_item_names_str,
                'freezing_items': freezing_items,
                'freezing_tariff_breakdown': freezing_tariff_breakdown,
                'overhead_breakdown': overhead_breakdown,
                'processing_details': processing_details,
            }
            
            report_data.append(purchase_data)
            
            # Update summary
            summary['total_purchase_quantity'] += purchase_quantity
            summary['total_purchase_amount'] += purchase_amount
            summary['total_purchase_overhead'] += purchase_overhead_amount
            summary['total_processing_overhead'] += processing_overhead_amount
            summary['total_shipment_overhead'] += shipment_overhead_amount
            summary['total_all_overheads'] += total_all_overheads
            summary['total_freezing_tariff'] += total_freezing_tariff
            summary['total_cost'] += grand_total_cost
            summary['total_revenue'] += freezing_revenue
            summary['total_profit_loss'] += total_profit_loss
        
        # Calculate summary
        summary['total_purchases'] = len(report_data)
        if summary['total_cost'] > 0:
            summary['overall_profit_margin'] = float(summary['total_profit_loss'] / summary['total_cost'] * 100)
        else:
            summary['overall_profit_margin'] = 0.0
        
        # Convert Decimal to float
        for key in ['total_purchase_quantity', 'total_purchase_amount',
                   'total_purchase_overhead', 'total_processing_overhead', 'total_shipment_overhead',
                   'total_all_overheads', 'total_freezing_tariff', 'total_cost', 'total_revenue', 'total_profit_loss']:
            summary[key] = float(summary[key])
        
        # Add overhead rates
        summary['purchase_overhead_rate'] = float(purchase_overhead_total)
        summary['processing_overhead_rate'] = float(processing_overhead_total)
        summary['shipment_overhead_rate'] = float(shipment_overhead_total)
        
        # Sort by date
        report_data.sort(key=lambda x: x['date'], reverse=True)
        
        context = {
            'report_data': report_data,
            'summary': summary,
            'usd_rate': float(usd_rate),
            'start_date': start_date,
            'end_date': end_date,
            'date_range_text': get_date_range_text(quick_filter, start_date, end_date),
        }
        
        return render(request, 'local_purchase_profit_loss_report_print.html', context)
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        context = {
            'error': f'An error occurred: {str(e)}',
            'report_data': [],
            'usd_rate': float(usd_rate) if 'usd_rate' in locals() else 84.00,
            'date_range_text': get_date_range_text(quick_filter, start_date, end_date) if 'quick_filter' in locals() else 'N/A'
        }
        return render(request, 'local_purchase_profit_loss_report_print.html', context)

