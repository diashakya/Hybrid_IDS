from ids_engine.models import SecurityEvent


def run_ids_pipeline(request, response):
      ip = (
          request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip()
          or request.META.get('REMOTE_ADDR', '127.0.0.1')
      )

      user = request.user if request.user.is_authenticated else None

      payload = None
      if request.method == 'POST':
          payload = {k: v for k, v in request.POST.items() if k != 'csrfmiddlewaretoken'}
          if 'password' in payload:
              payload['password'] = '***'

      event_type = 'ANOMALY'
      path = request.path
      if '/accounts/login/' in path:
          event_type = 'LOGIN_SUCCESS' if (user and user.is_authenticated) else 'LOGIN_FAIL'
      elif '/vote/' in path:
          event_type = 'VOTE_CAST'
      elif '/admin/' in path:
          event_type = 'ADMIN_ACTION'

      event = SecurityEvent(
          event_type=event_type,
          user=user,
          ip_address=ip,
          user_agent=request.META.get('HTTP_USER_AGENT', ''),
          session_id=request.session.session_key or '',
          endpoint=request.path,
          method=request.method,
          status_code=response.status_code if response else None,
          request_payload=payload,
          rule_triggered=False,
          rule_name='',
          rule_score=0,
          ml_anomaly_score=0.0,
          risk_score=0.0,
          risk_level='LOW',
          action_taken='ALLOW',
          iso_control='',
          nist_category='',
      )
      event.save()

      return event, False
