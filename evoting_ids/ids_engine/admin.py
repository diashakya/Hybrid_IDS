from django.contrib import admin
from django.utils.html import format_html
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

ISO_DESCRIPTIONS = {
    'A.9.4.2':  'Secure log-on procedures — Controls to prevent unauthorized access through repeated failed login attempts.',
    'A.12.4.1': 'Event logging — Ensures that user activities, exceptions, and security events are recorded and kept.',
    'A.14.2.5': 'Secure system engineering principles — Requires input validation and protection against injection attacks.',
    'A.9.2.3':  'Management of privileged access rights — Restricts and monitors the use of privileged (admin) accounts.',
    'A.12.6.1': 'Management of technical vulnerabilities — Controls to detect and respond to abnormal or excessive requests.',
    'A.13.1.3': 'Segregation in networks — Blocks communication from untrusted or known-malicious IP addresses.',
    'A.16.1.2': 'Reporting information security events — General obligation to log and report any detected security event.',
}

NIST_DESCRIPTIONS = {
    'PR.AC-7':  'Users and devices are authenticated based on the risk of the transaction (e.g., repeated failed logins).',
    'DE.CM-7':  'Monitoring for unauthorized actions is performed — detects duplicate or fraudulent voting attempts.',
    'PR.IP-12': 'A vulnerability management plan is in place — covers detection and prevention of injection-based attacks.',
    'PR.AC-4':  'Access permissions are managed using least-privilege — monitors for admin accounts exceeding normal access.',
    'DE.CM-1':  'The network is monitored to detect potential cybersecurity events such as unusually high request rates.',
    'PR.AC-3':  'Remote access is managed — unknown or blocked IP addresses are denied access to the system.',
    'DE.AE-2':  'Detected events are analyzed to understand attack targets and methods — applied to all anomaly detections.',
}


@admin.register(SecurityEvent)
class SecurityEventAdmin(admin.ModelAdmin):
    list_display = [
        'timestamp', 'event_type', 'ip_address',
        'triggered_rule', 'rule_score', 'ml_anomaly_score',
        'risk_score', 'risk_level', 'action_taken', 'iso_control'
    ]
    list_filter   = ['risk_level', 'action_taken', 'event_type', 'rule_triggered']
    search_fields = ['ip_address', 'rule_name', 'iso_control']
    ordering      = ['-timestamp']

    readonly_fields = [
        'timestamp', 'event_type', 'user', 'ip_address',
        'user_agent', 'session_id', 'endpoint', 'method',
        'status_code', 'request_payload', 'rule_triggered',
        'triggered_rule', 'rule_score', 'ml_anomaly_score',
        'risk_score', 'risk_level', 'action_taken',
        'iso_control', 'iso_control_detail',
        'nist_category', 'nist_category_detail',
    ]

    fieldsets = [
        ('Request Info', {
            'fields': ('timestamp', 'event_type', 'user', 'ip_address',
                       'user_agent', 'session_id', 'endpoint', 'method',
                       'status_code', 'request_payload')
        }),
        ('Rule Engine Output', {
            'fields': ('rule_triggered', 'triggered_rule', 'rule_score')
        }),
        ('ML Output', {
            'fields': ('ml_anomaly_score',)
        }),
        ('Risk Assessment', {
            'fields': ('risk_score', 'risk_level', 'action_taken')
        }),
        ('Compliance Mapping', {
            'fields': (
                'iso_control', 'iso_control_detail',
                'nist_category', 'nist_category_detail',
            ),
            'description': (
                'ISO 27001 defines information security controls. '
                'NIST CSF defines cybersecurity framework functions. '
                'These codes show which standard is triggered by this event.'
            ),
        }),
    ]

    @admin.display(description='Rule Triggered')
    def triggered_rule(self, obj):
        if not obj.rule_triggered:
            return '—'
        return RULE_LABELS.get(obj.rule_name, obj.rule_name)

    @admin.display(description='ISO 27001 — What this means')
    def iso_control_detail(self, obj):
        if not obj.iso_control:
            return '—'
        desc = ISO_DESCRIPTIONS.get(obj.iso_control, 'No description available.')
        return format_html(
            '<strong>{}</strong><br><span style="color:#555;">{}</span>',
            obj.iso_control, desc
        )

    @admin.display(description='NIST CSF — What this means')
    def nist_category_detail(self, obj):
        if not obj.nist_category:
            return '—'
        desc = NIST_DESCRIPTIONS.get(obj.nist_category, 'No description available.')
        return format_html(
            '<strong>{}</strong><br><span style="color:#555;">{}</span>',
            obj.nist_category, desc
        )

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(BlockedIP)
class BlockedIPAdmin(admin.ModelAdmin):
    list_display = ['ip_address', 'reason']