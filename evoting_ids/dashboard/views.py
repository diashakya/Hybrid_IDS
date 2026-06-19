from django.shortcuts import render

# Create your views here.
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.utils import timezone
from datetime import timedelta
from ids_engine.models import SecurityEvent


@login_required
def dashboard_home(request):
      return render(request, 'dashboard/index.html')


def api_latest_alerts(request):
      events = SecurityEvent.objects.filter(
          risk_level__in=['HIGH', 'CRITICAL']
      ).order_by('-timestamp')[:20]

      data = []
      for e in events:
          data.append({
              'id': e.id,
              'timestamp': timezone.localtime(e.timestamp).strftime('%Y-%m-%d %H:%M:%S'),
              'event_type': e.event_type,
              'ip_address': e.ip_address,
              'risk_level': e.risk_level,
              'risk_score': e.risk_score,
              'action_taken': e.action_taken,
              'iso_control': e.iso_control,
              'nist_category': e.nist_category,
              'rule_name': e.rule_name,
          })
      return JsonResponse(data, safe=False)


def api_stats_today(request):
      today = timezone.now().date()
      qs = SecurityEvent.objects.filter(timestamp__date=today)

      total = qs.count()
      blocked = qs.filter(action_taken='BLOCK').count()
      alert = qs.filter(action_taken='ALERT').count()
      non_low = qs.exclude(risk_level='LOW').count()
      detection_rate = round((non_low / total * 100), 1) if total > 0 else 0

      return JsonResponse({
          'total_events': total,
          'blocked_count': blocked,
          'alert_count': alert,
          'detection_rate': detection_rate,
          'high_count': qs.filter(risk_level='HIGH').count(),
          'critical_count': qs.filter(risk_level='CRITICAL').count(),
      })


def api_risk_distribution(request):
      today = timezone.now().date()
      qs = SecurityEvent.objects.filter(timestamp__date=today)

      return JsonResponse({
          'LOW': qs.filter(risk_level='LOW').count(),
          'MEDIUM': qs.filter(risk_level='MEDIUM').count(),
          'HIGH': qs.filter(risk_level='HIGH').count(),
          'CRITICAL': qs.filter(risk_level='CRITICAL').count(),
      })


def api_hourly_events(request):
      since = timezone.now() - timedelta(hours=24)
      qs = SecurityEvent.objects.filter(timestamp__gte=since)

      counts = {}
      for e in qs:
          hour = timezone.localtime(e.timestamp).strftime('%H:00')
          counts[hour] = counts.get(hour, 0) + 1

      result = []
      for h in range(24):
          label = f'{h:02d}:00'
          result.append({'hour': label, 'count': counts.get(label, 0)})

      return JsonResponse(result, safe=False)

def api_comparison(request):
      from ids_engine.risk_scorer import get_risk_level
      events = SecurityEvent.objects.exclude(ml_anomaly_score=None)
      total = events.count()

      rule_detected   = 0
      ml_detected     = 0
      hybrid_detected = 0

      for e in events:
          if get_risk_level(e.rule_score) in ('MEDIUM', 'HIGH', 'CRITICAL'):
              rule_detected += 1
          if get_risk_level(e.ml_anomaly_score or 0) in ('MEDIUM', 'HIGH', 'CRITICAL'):
              ml_detected += 1
          if e.risk_level in ('MEDIUM', 'HIGH', 'CRITICAL'):
              hybrid_detected += 1

      return JsonResponse({
          'total': total,
          'rule_detected':   rule_detected,
          'ml_detected':     ml_detected,
          'hybrid_detected': hybrid_detected,
          'rule_rate':    round(rule_detected   / total * 100, 1) if total else 0,
          'ml_rate':      round(ml_detected     / total * 100, 1) if total else 0,
          'hybrid_rate':  round(hybrid_detected / total * 100, 1) if total else 0,
      })


def download_audit_report(request):
      import os
      from django.http import FileResponse, HttpResponse
      output_path = os.path.join(os.getcwd(), 'audit_report.pdf')
      try:
          from django.core.management import call_command
          call_command('generate_audit_report')
      except Exception as e:
          return HttpResponse(f'Report generation failed: {e}', status=500)

      if not os.path.exists(output_path):
          return HttpResponse('Report file not found.', status=404)

      return FileResponse(
          open(output_path, 'rb'),
          as_attachment=True,
          filename='hybrid_ids_audit_report.pdf'
      )

def api_active_users(request):
        from django.contrib.sessions.models import Session
        from accounts.models import CustomUser

        active_sessions = Session.objects.filter(expire_date__gte=timezone.now())

        user_ids = []
        for session in active_sessions:
            data = session.get_decoded()
            uid = data.get('_auth_user_id')
            if uid:
                user_ids.append(int(uid))

        if not user_ids:
            return JsonResponse([], safe=False)

        users = CustomUser.objects.filter(id__in=user_ids)
        threshold = timezone.now() - timedelta(minutes=15)

        result = []
        for user in users:
            last_event = SecurityEvent.objects.filter(user=user).order_by('-timestamp').first()
            if last_event:
                last_activity = timezone.localtime(last_event.timestamp).strftime('%Y-%m-%d %H:%M:%S')
                status = 'ACTIVE' if last_event.timestamp >= threshold else 'IDLE'
            else:
                last_activity = '—'
                status = 'IDLE'

            result.append({
                'username':      user.username,
                'role':          user.role,
                'last_activity': last_activity,
                'status':        status,
            })

        result.sort(key=lambda x: x['status'] != 'ACTIVE')
        return JsonResponse(result, safe=False)