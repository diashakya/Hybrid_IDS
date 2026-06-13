"""
from django.contrib import admin

# Register your models here.
from .models import SecurityEvent, BlockedIP   
admin.site.register(SecurityEvent)
admin.site.register(BlockedIP) 
"""
from django.contrib import admin
from ids_engine.models import SecurityEvent, BlockedIP


@admin.register(SecurityEvent)
class SecurityEventAdmin(admin.ModelAdmin):
    list_display = [
        'timestamp', 'event_type', 'ip_address',
        'rule_score', 'ml_anomaly_score', 'risk_score',
        'risk_level', 'action_taken', 'iso_control'
    ]
    list_filter  = ['risk_level', 'action_taken', 'event_type']
    search_fields = ['ip_address', 'rule_name', 'iso_control']
    ordering     = ['-timestamp']

    readonly_fields = [
        'timestamp', 'event_type', 'user', 'ip_address',
        'user_agent', 'session_id', 'endpoint', 'method',
        'status_code', 'request_payload', 'rule_triggered',
        'rule_name', 'rule_score', 'ml_anomaly_score',
        'risk_score', 'risk_level', 'action_taken',
        'iso_control', 'nist_category'
    ]

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(BlockedIP)
class BlockedIPAdmin(admin.ModelAdmin):
    list_display = ['ip_address', 'reason']