from django.db import models
from django.conf import settings

# Create your models here.
class SecurityEvent(models.Model):
    EVENT_TYPES = [
        ('LOGIN_SUCCESS', 'Login success'),
        ('LOGIN_FAIL', 'Login failure'),
        ('VOTE_CAST', 'Vote cast'),
        ('VOTE_DUPLICATE', 'Duplicate vote attempt'),
        ('ADMIN_ACTION', 'Admin action'),
        ('ANOMALY', 'ML anomaly detected'),
        ('INJECTION_ATTEMPT', 'Injection attempt'),
        ('BLOCKED_IP', 'Blocked IP access'),
    ]
    RISK_LEVELS = [('LOW','Low'),('MEDIUM','Medium'),('HIGH','High'),('CRITICAL','Critical')]
    ACTIONS = [('ALLOW','Allow'),('ALERT','Alert'),('BLOCK','Block')]

    timestamp         = models.DateTimeField(auto_now_add=True, db_index=True)
    event_type        = models.CharField(max_length=30, choices=EVENT_TYPES)
    user              = models.ForeignKey(settings.AUTH_USER_MODEL,
                                          null=True, blank=True,
                                          on_delete=models.SET_NULL)
    ip_address        = models.GenericIPAddressField()
    user_agent        = models.TextField(blank=True)
    session_id        = models.CharField(max_length=100, blank=True)
    endpoint          = models.CharField(max_length=200)
    method            = models.CharField(max_length=10)
    status_code       = models.IntegerField(null=True, blank=True)
    request_payload   = models.JSONField(null=True, blank=True)

    # Rule engine output
    rule_triggered    = models.BooleanField(default=False)
    rule_name         = models.CharField(max_length=100, blank=True)
    rule_score        = models.IntegerField(default=0)

    # ML output
    ml_anomaly_score  = models.FloatField(null=True, blank=True)  # raw -1 to +0.5

    # Fused output
    risk_score        = models.FloatField(null=True, blank=True)   # 0-100
    risk_level        = models.CharField(max_length=10, choices=RISK_LEVELS,
                                          default='LOW')
    action_taken      = models.CharField(max_length=10, choices=ACTIONS,
                                          default='ALLOW')

    # Compliance
    iso_control       = models.CharField(max_length=20, blank=True)
    nist_category     = models.CharField(max_length=20, blank=True)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['ip_address', 'timestamp']),
            models.Index(fields=['risk_level', 'timestamp']),
        ]

class BlockedIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    blocked_at = models.DateTimeField(auto_now_add=True)
    reason     = models.CharField(max_length=200, blank=True)

    def __str__(self):
        return f"{self.ip_address} blocked at {self.blocked_at} for {self.reason}"