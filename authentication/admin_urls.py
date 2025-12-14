# admin_urls.py - URL Configuration for Admin Dashboard

from django.urls import path
from . import admin_views
urlpatterns = [
    # PRIORITY 1: Critical Dashboard Data
    path('dashboard/summary', 
         admin_views.dashboard_summary, 
         name='admin_dashboard_summary'),
    
    # PRIORITY 2: Chart Data
    path('charts/user-growth', 
         admin_views.user_growth_chart, 
         name='admin_user_growth_chart'),
    
    path('charts/top-savers', 
         admin_views.top_savers_chart, 
         name='admin_top_savers_chart'),
    
    path('charts/new-savers', 
         admin_views.new_savers_chart, 
         name='admin_new_savers_chart'),
    
    path('charts/user-metrics', 
         admin_views.user_metrics_chart, 
         name='admin_user_metrics_chart'),
    
    path('charts/financial-history', 
         admin_views.financial_history_chart, 
         name='admin_financial_history_chart'),
    
    # PRIORITY 3: List Data (Paginated)
    path('users/recent', 
         admin_views.recent_signups, 
         name='admin_recent_signups'),
    
    path('users/list', 
         admin_views.all_users_list, 
         name='admin_all_users_list'),
]