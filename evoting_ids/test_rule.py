import django, os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'evoting_ids.settings')
django.setup()

from ids_engine.models import SecurityEvent
from ids_engine.rule_engine import brute_force_rule

for i in range(12):
      SecurityEvent.objects.create(
          event_type='LOGIN_FAIL',
          ip_address='10.0.0.77',
          user_agent='test-agent',
          session_id=f'fake-session-{i}',
          endpoint='/accounts/login/',
          method='POST',
          status_code=200,
          rule_score=0,
          ml_anomaly_score=0.0,
          risk_score=0.0,
          risk_level='LOW',
          action_taken='ALLOW',
      )

result = brute_force_rule({'ip_address': '10.0.0.77'})
print(result)