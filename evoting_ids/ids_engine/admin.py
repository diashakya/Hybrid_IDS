"""
from django.contrib import admin

# Register your models here.
from .models import SecurityEvent, BlockedIP   
admin.site.register(SecurityEvent)
admin.site.register(BlockedIP) 
"""
from django.contrib import admin
from ids_engine.models import SecurityEvent, BlockedIP


RULE_LABELS = {
    'brute_force_rule':    'Brute Force',
    'duplicate_vote_rule': 'Duplicate Vote',
    'blocked_ip_rule':     'Blocked IP',
    'sql_injection_rule':  'SQL Injection',
    'rapid_request_rule':  'Rapid Requests',
    'admin_abuse_rule':    'Admin Abuse',
    'session_anomaly':     'Session Anomaly',
    'none':                '—',
}

@admin.register(SecurityEvent)
class SecurityEventAdmin(admin.ModelAdmin):
    list_display = [
        'timestamp', 'event_type', 'ip_address',
        'triggered_rule', 'rule_score', 'ml_anomaly_score',
        'risk_score', 'risk_level', 'action_taken', 'iso_control'
    ]
    list_filter  = ['risk_level', 'action_taken', 'event_type', 'rule_triggered']
    search_fields = ['ip_address', 'rule_name', 'iso_control']
    ordering     = ['-timestamp']

    @admin.display(description='Rule Triggered')
    def triggered_rule(self, obj):
        if not obj.rule_triggered:
            return '—'
        return RULE_LABELS.get(obj.rule_name, obj.rule_name)

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