from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard_home, name='dashboard_home'),
    path('alerts/latest/', views.api_latest_alerts),
    path('stats/today/', views.api_stats_today),
    path('risk-distribution/', views.api_risk_distribution),
    path('hourly-events/', views.api_hourly_events),
]