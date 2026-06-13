import django
import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'evoting_ids.settings')
django.setup()

from ids_engine.ml_detector import score_event

result = score_event({
    'ip_address': '127.0.0.1',
    'session_id': 'test123',
    'status_code': 200,
})
print("ML score:", result)
print("Type:", type(result))