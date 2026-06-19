def analyse_session(session_id: str, ip_address: str) -> dict:
      if not session_id:
          return {'score': 0, 'flags': []}

      from ids_engine.models import SecurityEvent

      session_events = SecurityEvent.objects.filter(
          session_id=session_id
      ).order_by('timestamp')

      count = session_events.count()
      if count < 3:
          return {'score': 0, 'flags': []}

      score = 0
      flags = []

      # 1. Endpoint enumeration — many unique endpoints = reconnaissance
      endpoints = list(session_events.values_list('endpoint', flat=True))
      unique_endpoints = len(set(endpoints))
      if unique_endpoints > 8:
          score += min(35, (unique_endpoints - 8) * 5)
          flags.append(f'{unique_endpoints} unique endpoints visited in session')

      # 2. Mixed role access — admin + voter actions in same session
      event_types = set(session_events.values_list('event_type', flat=True))
      if 'ADMIN_ACTION' in event_types and 'VOTE_CAST' in event_types:
          score += 40
          flags.append('Admin and voter actions in same session')

      # 3. Failed login followed by sensitive action — account takeover pattern
      events_list = list(session_events.values_list('event_type', flat=True))
      if 'LOGIN_FAIL' in events_list and any(
          e in events_list for e in ('VOTE_CAST', 'ADMIN_ACTION')
      ):
          score += 30
          flags.append('Failed login followed by sensitive action in session')

      # 4. High request volume — bot behaviour
      if count > 50:
          score += min(25, (count - 50) // 5)
          flags.append(f'{count} total requests in session')

      # 5. Very long session duration
      first = session_events.first()
      last  = session_events.last()
      if first and last:
          duration_minutes = (last.timestamp - first.timestamp).total_seconds() / 60
          if duration_minutes > 120:
              score += 20
              flags.append(f'Session active for {int(duration_minutes)} minutes')

      return {
          'score': min(100, score),
          'flags': flags,
      }