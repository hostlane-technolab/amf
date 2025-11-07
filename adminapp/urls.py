from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static


# nammude client paranjhu name chage cheyyan athu too risk anu athukondu html name mathre matittullu
# item category ennu parayunne elam item quality anu  model name itemQuality
# item group ennu parayunne elam item category anu model name itemCategory


app_name = 'adminapp'

urlpatterns = [

    path('admin_dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('user_dashboard/', views.user_dashboard, name='user_dashboard'),

    path('users/<str:user_id>/permissions/', views.assign_user_permissions, name='assign_user_permissions'),

    path('master/', views.master, name='master'),

    path('login/', views.user_login, name='admin_login'),
    
    path('', views.admin_logout, name='admin_logout'),

    path('create-user/', views.create_user_view, name='create_user'),
    path('users/edit/<uuid:pk>/', views.CustomUserUpdateView.as_view(), name='edit_user'),
    path('users-list/', views.users_list_view, name='users_list'),
    path('users/<uuid:user_id>/', views.user_profile_view, name='user_profile_view'),
    path('user/delete/<str:pk>/', views.UserDeleteView.as_view(), name='user_delete'),

    
    # Operational & Location Masters
    path('processing-center/create/', views.ProcessingCenterCreateView.as_view(), name='processing_center_create'),
    path('processing-center/list/', views.ProcessingCenterListView.as_view(), name='processing_center_list'),
    path('processing-center/update/<str:pk>/', views.ProcessingCenterUpdateView.as_view(), name='processing_center_update'),
    path('processing-center/delete/<str:pk>/', views.ProcessingCenterDeleteView.as_view(), name='processing_center_delete'),

    path('store/create/', views.StoreCreateView.as_view(), name='store_create'),
    path('store/list/', views.StoreListView.as_view(), name='store_list'),
    path('store/update/<str:pk>/', views.StoreUpdateView.as_view(), name='store_update'),
    path('store/delete/<str:pk>/', views.StoreDeleteView.as_view(), name='store_delete'),


    # shed
    path('shed/add/', views.create_shed, name='create_shed'),
    path('ajax/get-item-types/', views.get_item_types, name='get_item_types'),
    path('peeling-center/list/', views.ShedListView.as_view(), name='peeling_center_list'),
    path('shed/<str:pk>/edit/', views.update_shed, name='update_shed'),
    path('peeling-center/delete/<str:pk>/', views.ShedDeleteView.as_view(), name='peeling_center_delete'),

    path('LocalParty/create/', views.LocalPartyCreateView.as_view(), name='LocalParty_create'),
    path('LocalParty/list/', views.LocalPartyListView.as_view(), name='LocalParty_list'),
    path('LocalParty/update/<str:pk>/', views.LocalPartyUpdateView.as_view(), name='LocalParty_update'),
    path('LocalParty/delete/<str:pk>/', views.LocalPartyDeleteView.as_view(), name='LocalParty_delete'),

    path('purchasing-spot/create/', views.PurchasingSpotCreateView.as_view(), name='purchasing_spot_create'),
    path('purchasing-spot/list/', views.PurchasingSpotListView.as_view(), name='purchasing_spot_list'),
    path('purchasing-spot/update/<str:pk>/', views.PurchasingSpotUpdateView.as_view(), name='purchasing_spot_update'),
    path('purchasing-spot/delete/<str:pk>/', views.PurchasingSpotDeleteView.as_view(), name='purchasing_spot_delete'),

    # Personnel Masters
    path('purchasing-supervisor/create/', views.PurchasingSupervisorCreateView.as_view(), name='purchasing_supervisor_create'),
    path('purchasing-supervisor/list/', views.PurchasingSupervisorListView.as_view(), name='purchasing_supervisor_list'),
    path('purchasing-supervisor/update/<str:pk>/', views.PurchasingSupervisorUpdateView.as_view(), name='purchasing_supervisor_update'),
    path('purchasing-supervisor/delete/<str:pk>/', views.PurchasingSupervisorDeleteView.as_view(), name='purchasing_supervisor_delete'),

    path('purchasing-agent/create/', views.PurchasingAgentCreateView.as_view(), name='purchasing_agent_create'),
    path('purchasing-agent/list/', views.PurchasingAgentListView.as_view(), name='purchasing_agent_list'),
    path('purchasing-agent/update/<str:pk>/', views.PurchasingAgentUpdateView.as_view(), name='purchasing_agent_update'),
    path('purchasing-agent/delete/<str:pk>/', views.PurchasingAgentDeleteView.as_view(), name='purchasing_agent_delete'),

    # Item & Product Masters
    path('item-category/create/', views.ItemCategoryCreateView.as_view(), name='item_category_create'),
    path('item-category/list/', views.ItemCategoryListView.as_view(), name='item_category_list'),
    path('item-category/update/<str:pk>/', views.ItemCategoryUpdateView.as_view(), name='item_category_update'),
    path('item-category/delete/<str:pk>/', views.ItemCategoryDeleteView.as_view(), name='item_category_delete'),

    path('item/create/', views.ItemCreateView.as_view(), name='item_create'),
    path('item/list/', views.ItemListView.as_view(), name='item_list'),
    path('item/update/<str:pk>/', views.ItemUpdateView.as_view(), name='item_update'),
    path('item/delete/<str:pk>/', views.ItemDeleteView.as_view(), name='item_delete'),

    path('item/quality/create/', views.ItemQualityCreateView.as_view(), name='item_quality_create'),
    path('item/quality/list/', views.ItemQualityListView.as_view(), name='item_quality_list'),
    path('item/quality/update/<str:pk>/', views.ItemQualityUpdateView.as_view(), name='item_quality_update'),
    path('item/quality/delete/<str:pk>/', views.ItemQualityDeleteView.as_view(), name='item_quality_delete'),

    path('species/', views.SpeciesListView.as_view(), name='species_list'),
    path('species/create/', views.SpeciesCreateView.as_view(), name='species_create'),
    path('species/<str:pk>/update/', views.SpeciesUpdateView.as_view(), name='species_update'),
    path('species/<str:pk>/delete/', views.SpeciesDeleteView.as_view(), name='species_delete'),


    path('item-grade/create/', views.ItemGradeCreateView.as_view(), name='item_grade_create'),
    path('ajax/load-species/', views.load_species, name='ajax_load_species'),
    path('item-grade/list/', views.ItemGradeListView.as_view(), name='item_grade_list'),
    path('item-grade/update/<str:pk>/', views.ItemGradeUpdateView.as_view(), name='item_grade_update'),
    path('item-grade/delete/<str:pk>/', views.ItemGradeDeleteView.as_view(), name='item_grade_delete'),

    path('freezing-category/create/', views.FreezingCategoryCreateView.as_view(), name='freezing_category_create'),
    path('freezing-category/list/', views.FreezingCategoryListView.as_view(), name='freezing_category_list'),
    path('freezing-category/update/<str:pk>/', views.FreezingCategoryUpdateView.as_view(), name='freezing_category_update'),
    path('freezing-category/delete/<str:pk>/', views.FreezingCategoryDeleteView.as_view(), name='freezing_category_delete'),

    path('packing-unit/create/', views.PackingUnitCreateView.as_view(), name='packing_unit_create'),
    path('packing-unit/list/', views.PackingUnitListView.as_view(), name='packing_unit_list'),
    path('packing-unit/update/<str:pk>/', views.PackingUnitUpdateView.as_view(), name='packing_unit_update'),
    path('packing-unit/delete/<str:pk>/', views.PackingUnitDeleteView.as_view(), name='packing_unit_delete'),

    path('glaze-percentage/create/', views.GlazePercentageCreateView.as_view(), name='glaze_percentage_create'),
    path('glaze-percentage/list/', views.GlazePercentageListView.as_view(), name='glaze_percentage_list'),
    path('glaze-percentage/update/<str:pk>/', views.GlazePercentageUpdateView.as_view(), name='glaze_percentage_update'),
    path('glaze-percentage/delete/<str:pk>/', views.GlazePercentageDeleteView.as_view(), name='glaze_percentage_delete'),

    path('item-brand/create/', views.ItemBrandCreateView.as_view(), name='item_brand_create'),
    path('item-brand/list/', views.ItemBrandListView.as_view(), name='item_brand_list'),
    path('item-brand/update/<str:pk>/', views.ItemBrandUpdateView.as_view(), name='item_brand_update'),
    path('item-brand/delete/<str:pk>/', views.ItemBrandDeleteView.as_view(), name='item_brand_delete'),

    path('item-type/create/', views.ItemTypeCreateView.as_view(), name='item_type_create'),
    path('item-type/list/', views.ItemTypeListView.as_view(), name='item_type_list'),
    path('item-type/update/<str:pk>/', views.ItemTypeUpdateView.as_view(), name='item_type_update'),
    path('item-type/delete/<str:pk>/', views.ItemTypeDeleteView.as_view(), name='item_type_delete'),

    # Financial & Expense Masters
    path('tenant/create/', views.TenantCreateView.as_view(), name='tenant_create'),
    path('tenant/list/', views.TenantListView.as_view(), name='tenant_list'),
    path('tenant/update/<str:pk>/', views.TenantUpdateView.as_view(), name='tenant_update'),
    path('tenant/delete/<str:pk>/', views.TenantDeleteView.as_view(), name='tenant_delete'),
 
    path('purchase-overhead/create/', views.PurchaseOverheadCreateView.as_view(), name='purchase_overhead_create'),
    path('purchase-overhead/list/', views.PurchaseOverheadListView.as_view(), name='purchase_overhead_list'),
    path('purchase-overhead/update/<str:pk>/', views.PurchaseOverheadUpdateView.as_view(), name='purchase_overhead_update'),
    path('purchase-overhead/delete/<str:pk>/', views.PurchaseOverheadDeleteView.as_view(), name='purchase_overhead_delete'),

    path('peeling-overhead/create/', views.PeelingOverheadCreateView.as_view(), name='peeling_overhead_create'),
    path('peeling-overhead/list/', views.PeelingOverheadListView.as_view(), name='peeling_overhead_list'),
    path('peeling-overhead/update/<str:pk>/', views.PeelingOverheadUpdateView.as_view(), name='peeling_overhead_update'),
    path('peeling-overhead/delete/<str:pk>/', views.PeelingOverheadDeleteView.as_view(), name='peeling_overhead_delete'),

    path('processing-overhead/create/', views.ProcessingOverheadCreateView.as_view(), name='processing_overhead_create'),
    path('processing-overhead/list/', views.ProcessingOverheadListView.as_view(), name='processing_overhead_list'),
    path('processing-overhead/update/<str:pk>/', views.ProcessingOverheadUpdateView.as_view(), name='processing_overhead_update'),
    path('processing-overhead/delete/<str:pk>/', views.ProcessingOverheadDeleteView.as_view(), name='processing_overhead_delete'),

    path('shipment-overhead/create/', views.ShipmentOverheadCreateView.as_view(), name='shipment_overhead_create'),
    path('shipment-overhead/list/', views.ShipmentOverheadListView.as_view(), name='shipment_overhead_list'),
    path('shipment-overhead/update/<str:pk>/', views.ShipmentOverheadUpdateView.as_view(), name='shipment_overhead_update'),
    path('shipment-overhead/delete/<str:pk>/', views.ShipmentOverheadDeleteView.as_view(), name='shipment_overhead_delete'),

    path('list/', views.settings_list, name='settings_list'),
    path('create/', views.settings_create, name='settings_create'),
    path('update/<str:pk>/', views.settings_update, name='settings_update'),
    path('delete/<str:pk>/', views.settings_delete, name='settings_delete'),

    # spot purchase urls.py
    path('spot-purchase/add/', views.create_spot_purchase, name='spot_purchase_add'),
    path('spot-purchases/', views.spot_purchase_list, name='spot_purchase_list'),
    path('spot-purchase/<str:pk>/edit/', views.edit_spot_purchase, name='spot_purchase_edit'),
    path('spot-purchases/<str:pk>/delete/', views.spot_purchase_delete, name='spot_purchase_delete'),
    path('spot-purchases/<str:pk>/', views.spot_purchase_detail, name='spot_purchase_detail'),

   # Local Purchase URLs
    path('local-purchase/create/', views.local_purchase_create, name='local_purchase_create'),
    path('local-purchase/', views.local_purchase_list, name='local_purchase_list'),
    path('local-purchase/<str:pk>/update/', views.local_purchase_update, name='local_purchase_update'),
    path('local-purchase/<str:pk>/delete/', views.local_purchase_delete, name='local_purchase_delete'),
    path('local-purchase/<str:pk>/detail/', views.local_purchase_detail, name='local_purchase_detail'),

    path("spot/purchase/workout/summary/", views.spot_purchase_workout_summary, name="spot_purchase_workout_summary"),
    # Local Purchase Workout
    path("local-purchase-workout/",views.local_purchase_workout_summary ,name="local_purchase_workout_summary"),

    # Peeling Shed Supply
    path('peeling-shed-supply/create/', views.create_peeling_shed_supply, name='create_peeling_shed_supply'),
    path('peeling-shed-supply/', views.PeelingShedSupplyListView.as_view(), name='peeling_shed_supply_list'),
    path('peeling-shed-supply/<int:pk>/delete/', views.PeelingShedSupplyDeleteView.as_view(), name='peeling_shed_supply_delete'),
    path("peeling-shed-supplies/<int:pk>/", views.PeelingShedSupplyDetailView.as_view(),name="peeling_shed_supply_detail"),
    path("peeling-shed-supplies/<int:pk>/update/",views.update_peeling_shed_supply, name="peeling_shed_supply_update"),
    path('ajax/get-spot-purchases/', views.get_spot_purchases_by_date, name='get_spot_purchases_by_date'),
    path('ajax/get-spot-purchase-items/', views.get_spot_purchase_items, name='get_spot_purchase_items'),    
    path('ajax/get-spot-purchase-item-details/', views.get_spot_purchase_item_details, name='get_spot_purchase_item_details'),
    path('ajax/get-peeling-types/', views.get_peeling_charge_by_shed, name='get_peeling_charge_by_shed'),
    path('ajax/get-spot-purchase-item-details-with-balance/', views.get_spot_purchase_item_details_with_balance,name='get_spot_purchase_item_details_with_balance'),
    path('ajax/get-spot-purchase-item-details-with-balance/update/', views.get_spot_purchase_item_details_for_update,name='get_spot_purchase_item_details_for_update'),
    
    #  create freezing entry spot
    path('freezing-entry/create/', views.create_freezing_entry_spot, name='freezing_entry_spot_create'),
    path('freezing-entry/list/', views.freezing_entry_spot_list, name='freezing_entry_spot_list'),
    path('freezing-entry-spot/<str:pk>/', views.FreezingEntrySpotDetailView.as_view(), name='freezing_entry_spot_detail'),
    path("freezing-entry-spot/<str:pk>/update/", views.freezing_entry_spot_update, name="freezing_entry_spot_update"),    
    path('freezing-entry/<str:pk>/delete/', views.delete_freezing_entry_spot, name='freezing_entry_spot_delete'),
    path('ajax/get-spots-by-date/', views.get_spots_by_date, name='get_spots_by_date'),
    path('ajax/get-spot-details/', views.get_spot_details, name='get_spot_details'),
    path('ajax/get-sheds-by-date/', views.get_sheds_by_date, name='get_sheds_by_date'),
    path('ajax/get-unit-details/', views.get_unit_details, name='get_unit_details'),
    path('ajax/get-dollar-rate/', views.get_dollar_rate, name='get_dollar_rate'),
    path("get_spot_purchase_items_by_date/", views.get_spot_purchase_items_by_date, name="get_spot_purchase_items_by_date"),

    #  create freezing entry local
    path('freezing-entry-local/create/', views.create_freezing_entry_local, name='freezing_entry_local_create'),
    path('freezing-entry-local/', views.freezing_entry_local_list, name='freezing_entry_local_list'),
    path('freezing-entry-local/delete/<str:pk>/', views.delete_freezing_entry_local, name='delete_freezing_entry_local'),
    path('freezing-entry-local/<str:pk>/', views.freezing_entry_local_detail, name='freezing_entry_local_detail'),
    path("freezing-entry-local/<str:pk>/edit/", views.freezing_entry_local_update, name="freezing_entry_local_update"),
    path('ajax/get-parties-by-date/', views.get_parties_by_date, name='get_parties_by_date'),
    path('ajax/get-party-details/', views.get_party_details, name='get_party_details'),
    path('ajax/get-unit-details/', views.get_unit_details_local, name='get_unit_details_local'),
    path('ajax/get-item-details/', views.get_items_by_local_date, name='get_items_by_local_date'),
    path('ajax/get-dollar-rate/', views.get_dollar_rate_local, name='get_dollar_rate_local'),
    path("ajax/get-item-qualities/", views.get_item_qualities, name="get_item_qualities"),


    #  Freezing WorkOut View url
    path('freezing-workout/', views.FreezingWorkOutView.as_view(), name='freezing_workout'),

    # pre_shipment_workout_create
    path('get-stock-rate/', views.GetStockRateView.as_view(), name='get_stock_rate'),
    path('create_preshipment_workout/', views.PreShipmentWorkOutView.as_view(), name='create_preshipment_workout'),
    path("preshipment-workouts/", views.PreShipmentWorkOutListView.as_view(), name="preshipment_workout_list"),
    path("preshipment-workout/delete/<int:pk>/", views.PreShipmentWorkOutDeleteView.as_view(), name="preshipment_workout_delete"),
    path('get-species/', views.get_species_for_item, name='get_species_for_item'),
    path("get-peeling/", views.get_peeling_for_item, name="get_peeling_for_item"),
    path("ajax/get-grade-for-species/",views.get_grade_for_species,name="get_grade_for_species"),
    path('get-dollar-rate-pre-workout/', views.get_dollar_rate_pre_workout, name='get_dollar_rate_pre_workout'),
    path("preshipment-workout/<str:pk>/detail/",views.PreShipmentWorkOutDetailView.as_view(),name="preshipment_workout_detail"),



    path("spot/purchase/report/", views.spot_purchase_report, name="spot_purchase_report"),
    # Print version - separate URL (recommended approach)
    path('spot/purchase/report/print/', views.spot_purchase_report_print, name='spot_purchase_report_print'),


    # local purchase report
    path('local-purchase-report/', views.local_purchase_report, name='local_purchase_report'),
    path('local-purchase-report/print/', views.local_purchase_report_print, name='local_purchase_report_print'),



    path('reports/peeling-shed-supply/', views.peeling_shed_supply_report, name='peeling_shed_supply_report'),
    # Dedicated print view (alternative approach)
    path('reports/peeling-shed-supply/print/', views.peeling_shed_supply_report_print, name='peeling_shed_supply_report_print'),
    




    path('reports/freezing/', views.freezing_report, name='freezing_report'),
    
    # Separate print view
    path('reports/freezing/print/', views.freezing_report_print, name='freezing_report_print'),


    # 🔹 Freezing Tenant 
    path("tenant-freezing/", views.tenant_freezing_list, name="list_freezing_entry_tenant"),
    path("tenant-freezing/create/", views.tenant_freezing_create, name="create_freezing_entry_tenant"),
    path("tenant-freezing/<int:pk>/", views.tenant_freezing_detail, name="detail_freezing_entry_tenant"),
    path("tenant-freezing/<int:pk>/update/", views.tenant_freezing_update, name="update_freezing_entry_tenant"),
    path("tenant-freezing/<int:pk>/delete/", views.tenant_freezing_delete, name="delete_freezing_entry_tenant"),

    path('tenant/freezing/<int:pk>/pdf/', views.tenant_freezing_detail_pdf, name='tenant_freezing_detail_pdf'),

    # 🔹 return Tenant
    path("return-tenant/", views.return_tenant_list, name="list_return_tenant"),
    path("return-tenant/create/", views.return_tenant_create, name="create_return_tenant"),
    path("return-tenant/<int:pk>/", views.return_tenant_detail, name="detail_return_tenant"),
    path('return-tenant/<int:pk>/pdf/', views.generate_return_tenant_pdf, name='return_tenant_pdf'),


    

#  Tenant Stock Management URLs
    path('tenant-stock/balance/', views.tenant_stock_balance, name='tenant_stock_balance'),
    path('tenant-stock/summary/', views.tenant_stock_summary, name='tenant_stock_summary'), 
    path('tenant-stock/detail/<int:tenant_id>/', views.tenant_stock_detail, name='tenant_stock_detail'),
    path("ajax/get-tenant-companies/", views.get_tenant_companies, name="get_tenant_companies"),


    
   # -------------------
    # Billing Configs
    # -------------------
    path('bills/', views.bill_list, name='bill_list'),
    path('bills/generate/', views.generate_manual_bill, name='generate_manual_bill'),
    path('bills/<int:bill_id>/', views.view_bill, name='view_bill'),
    path('bills/<int:bill_id>/update-status/', views.update_bill_status, name='update_bill_status'),
    path('bills/<int:bill_id>/delete/', views.delete_bill, name='delete_bill'),
    path('bills/<int:bill_id>/delete-ajax/', views.delete_bill_ajax, name='delete_bill_ajax'),


    # Billing Configs
    path('billing/configs/', views.billing_config_list, name='billing_config_list'),
    path('billing/configs/setup/', views.setup_billing_configuration, name='setup_billing_configuration'),
    path('billing/configs/debug/', views.debug_billing_status, name='debug_billing_status'),
    path('billing/configs/<int:pk>/delete/', views.delete_billing_configuration, name='delete_billing_configuration'), 

    path("ajax/get-last-bill-date/", views.get_last_bill_date, name="get_last_bill_date"),

    path('billing/bill/<int:bill_id>/pdf/', views.bill_pdf, name='bill_pdf'),


    path("bills/draft/", views.bill_list_draft, name="bill_list_draft"),
    # path("bills/finalized/", views.bill_list_finalized, name="bill_list_finalized"),
    # path("bills/sent/", views.bill_list_sent, name="bill_list_sent"),
    # path("bills/paid/", views.bill_list_paid, name="bill_list_paid"),
    # path("bills/cancelled/", views.bill_list_cancelled, name="bill_list_cancelled"),


    path('transfers/', views.StoreTransferListView.as_view(), name='store_transfer_list'),
    path('transfers/create/', views.create_store_transfer, name='create_store_transfer'),
    path('transfers/<int:pk>/', views.transfer_detail, name='transfer_detail'),
    path('api/get-stock-by-store/', views.get_stock_by_store, name='get_stock_by_store'),
    path("transfers/<int:pk>/delete/", views.delete_transfer, name="delete_transfer"),
    path("api/get-stock-details/", views.get_stock_details, name="get_stock_details"),




    path('stock/list/', views.StockListView.as_view(), name='list'),
    path('dashboard/', views.StockDashboardView.as_view(), name='dashboard'),
    path('detail/<int:pk>/', views.StockDetailView.as_view(), name='detail'),

    path('stock/report/list/', views.stock_report, name='report_list'),
    path('stock/report/print/', views.stock_report_print, name='stock_report_print'),

    path('stock/report/amt/list/', views.stock_report_amt, name='stock_report_amt'),
    path('stock/report/amt/print/', views.stock_report_print_amt, name='stock_report_print_amt'),

    path('stock/<int:pk>/delete-direct/', views.delete_stock, name='stock_delete_direct'),
    
    # API endpoints
    path('api/search/', views.stock_search_api, name='search_api'),
    path('api/quick-info/<int:pk>/', views.stock_quick_info, name='quick_info'),


    # --- Spot Agent ---
    path("vouchers/spot-agent/create/", views.create_spot_agent_voucher, name="spotagentvoucher_create"),
    path('spot-agent-voucher/<int:pk>/',views.spot_agent_voucher_detail, name='spot_agent_voucher_detail'),
    path('spot-agent-voucher/<int:pk>/delete/', views.delete_spot_agent_voucher, name='spotagentvoucher_delete'),
    path('spot-agent-voucher/delete/<int:pk>/list/', views.delete_spot_agent_voucher_list, name="spotagentvoucher_delete_list"),
    path("api/get-agent-balance/", views.get_agent_balance, name="get_agent_balance"),

    path('vouchers/spot-agent/list/', views.spotagentvoucher_list_with_summary, name='spotagentvoucher_list'),
    path('spotagentvouchers/summary-pdf/', views.spot_agent_voucher_summary_pdf, name='spot_agent_voucher_summary_pdf'),
    path('spotagentvouchers/agent/<str:agent_id>/statement/', views.spot_agent_statement_pdf, name='spot_agent_statement_pdf'),

    
    
    # --- Supervisor voucher ---
    path('supervisor-vouchers/', views.supervisorvoucher_list_with_summary, name='supervisorvoucher_list'),    
    path('supervisor-vouchers/create/',views.create_supervisor_voucher, name='create_supervisor_voucher'),
    path('supervisor-voucher/<int:pk>/', views.supervisor_voucher_detail, name='supervisorvoucher_detail'),
    path('supervisor-vouchers/<int:voucher_id>/update/', views.update_supervisor_voucher, name='update_supervisor_voucher'),
    path('supervisor-vouchers/<int:voucher_id>/delete/',views.delete_supervisor_voucher,name='delete_supervisor_voucher'),
    path('supervisor-voucher/delete/<int:pk>/list/',views.delete_supervisor_voucher_list,name='supervisorvoucher_delete_list'),

    path('supervisor-vouchers/summary-pdf/', views.supervisor_voucher_summary_pdf, name='supervisor_voucher_summary_pdf'),
    path('supervisor-vouchers/statement-pdf/<int:supervisor_id>/', views.supervisor_statement_pdf, name='supervisor_statement_pdf'),
    path('api/get-supervisor-balance/', views.get_supervisor_balance, name='get_supervisor_balance'),
    
    
    # --- Local Purchase ---
    path("vouchers/local/create/", views.create_local_purchase_voucher, name="localpurchasevoucher_create"),
    path('vouchers/local-purchase/<int:pk>/', views.local_purchase_voucher_detail, name='local_purchase_voucher_detail'),
    path('vouchers/local-purchase/<int:pk>/delete/', views.delete_local_purchase_voucher, name='delete_local_purchase_voucher'),
    path('local-purchase-voucher/delete/<int:pk>/list/',views.delete_localpurchase_voucher_list,name='localpurchasevoucher_delete_list'
),

    path("api/get-party-balance/", views.get_party_balance, name="get_party_balance"),
    path('localpurchasevoucher/', views.localpurchasevoucher_list_with_summary, name='localpurchasevoucher_list'),
    path('localpurchasevoucher/summary/pdf/', views.localpurchase_voucher_summary_pdf, name='localpurchase_voucher_summary_pdf'),
    path('localpurchasevoucher/party/<int:party_id>/statement/pdf/', views.localpurchase_party_statement_pdf, name='localpurchase_party_statement_pdf'),
    


    # --- Peeling Shed ---
    path("vouchers/shed/create/", views.create_peeling_shed_voucher, name="create_peeling_shed_voucher"),
    path('vouchers/peeling-shed/<int:pk>/', views.peeling_shed_voucher_detail, name='peeling_shed_voucher_detail'),
    path('vouchers/peeling-shed/<int:pk>/delete/', views.delete_peeling_shed_voucher, name='delete_peeling_shed_voucher'),
    path('peeling-shed-voucher/delete/<int:pk>/list/',views.delete_peelingshed_voucher_list,name='peelingshedvoucher_delete_list'
),

    path("vouchers/shed/list/", views.peeling_shed_voucher_list_with_summary, name="peeling_shed_voucher_list"),
    path('ajax/shed-calculation-preview/', views.get_shed_calculation_preview, name='get_shed_calculation_preview'),
    # PDF Export URLs
    path('vouchers/shed/summary-pdf/', views.peeling_shed_voucher_summary_pdf, name='peeling_shed_voucher_summary_pdf'),
    path('vouchers/shed/statement/<int:shed_id>/pdf/', views.shed_statement_pdf, name='shed_statement_pdf'),



    # Tenant Voucher URLs
    path('vouchers/tenant/list/', views.tenantvoucher_list_with_summary, name='tenantvoucher_list'),
    path('vouchers/tenant/create/', views.create_tenant_voucher, name='tenantvoucher_create'),
    path('vouchers/tenant/<int:pk>/', views.tenant_voucher_detail, name='tenant_voucher_detail'),
    path('vouchers/tenant/<int:pk>/delete/', views.delete_tenant_voucher, name='delete_tenant_voucher'),
    path('tenant-voucher/delete/<int:pk>/list/',views.delete_tenant_voucher_list,name='tenantvoucher_delete_list'
),

    path('get-tenant-balance/', views.get_tenant_balance, name='get_tenant_balance'),
    
    # PDF Export URLs
    path('vouchers/tenant/summary-pdf/', views.tenant_voucher_summary_pdf, name='tenant_voucher_summary_pdf'),
    path('vouchers/tenant/statement/<int:tenant_id>/pdf/', views.tenant_statement_pdf, name='tenant_statement_pdf'),

    # Add these to your urlpatterns
    path('incomplete-freezing/', views.incomplete_freezing_list, name='incomplete_freezing_list'),


    # Added BY Akhil From Shameer 25/09/2025
    path('stocks/create/', views.create_stock, name='create_stock'),
    path('stocks/<int:pk>/', views.stock_detail, name='stock_detail'),
    path('stocks/<int:pk>/update/', views.update_stock, name='update_stock'),
    
    # AJAX Search
    path('stocks/search/', views.stock_search_ajax, name='stock_search_ajax'),




    path('reports/spot-profit-loss/', views.spot_purchase_profit_loss_report, name='spot_profit_loss_report'),

    path('spot-purchase-profit-loss/print/', views.spot_purchase_profit_loss_report_print, name='spot_purchase_profit_loss_report_print'),


    # Added in 02/10/2025
    
     # Buyers
    path("buyers/", views.buyer_list, name="buyer_list"),
    path("buyers/create/", views.buyer_create, name="buyer_create"),
    path("buyers/<int:pk>/update/", views.buyer_update, name="buyer_update"),
    path("buyers/<int:pk>/delete/", views.buyer_delete, name="buyer_delete"),

    # Shipment Destinations
    path("destinations/", views.destination_list, name="destination_list"),
    path("destinations/create/", views.destination_create, name="destination_create"),
    path("destinations/<int:pk>/update/", views.destination_update, name="destination_update"),
    path("destinations/<int:pk>/delete/", views.destination_delete, name="destination_delete"),





    # Sales Entry URLs
    path('sales-entry/', views.sales_entry_list, name='sales_entry_list'),
    path('sales-entry/create/', views.create_sales_entry, name='sales_entry_create'),
    path('sales-entry/<int:pk>/', views.sales_entry_detail, name='sales_entry_detail'),
    path('sales-entry/<int:pk>/update/', views.update_sales_entry, name='sales_entry_update'),
    path('sales-entry/<int:pk>/delete/', views.delete_sales_entry, name='sales_entry_delete'),
    
    path('sales/entry/<int:pk>/pdf/', views.sales_entry_invoice_pdf, name='sales_entry_invoice_pdf'),






    path('get-item-grades/', views.get_item_grades, name='get_item_grades'),

    path('stock/adjustment/', views.stock_adjustment, name='stock_adjustment'),
    path('get-current-stock/', views.get_current_stock, name='get_current_stock'), 



 
    path('return-tenant/update/<int:pk>/', views.return_tenant_update, name='update_return_tenant'),
    path('return-tenant/delete/<int:pk>/', views.return_tenant_delete, name='delete_return_tenant'),
    path('get-tenant-stock/', views.get_tenant_stock_ajax, name='get_tenant_stock_ajax'),

    
    path('notifications/',views.NotificationListView.as_view(), name='notification_list'),
    path('notifications/unread/',views.UnreadNotificationsView.as_view(), name='notification_unread'),
    path('notifications/<int:pk>/mark-read/',views.mark_notification_read, name='notification_mark_read'),
    path('notifications/mark-all-read/',views.mark_all_notifications_read, name='notification_mark_all_read'),
    path('notifications/delete/<int:pk>/',views.delete_notification, name='notification_delete'),
    path('notifications/ajax/count/',views.get_unread_count_ajax, name='notification_count_ajax'),

    # Tenant Stock Adjustment 
    path('tenant-stock/adjustment/', views.tenant_stock_adjustment, name='tenant_stock_adjustment'),
    path('tenant-stock/get-current/', views.get_current_tenant_stock, name='get_current_tenant_stock'),
    path('tenant-stock/', views.tenant_stock_list, name='tenant_stock_list'),
    path('tenant-stock/delete/<int:pk>/', views.tenant_stock_delete, name='tenant_stock_delete'),

        # Local Purchase Profit/Loss Report URLs
    path('reports/local-purchase-profit-loss/', views.local_purchase_profit_loss_report, name='local_purchase_profit_loss_report'),
    path('reports/local-purchase-profit-loss/print/', views.local_purchase_profit_loss_report_print, name='local_purchase_profit_loss_report_print'),



]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)