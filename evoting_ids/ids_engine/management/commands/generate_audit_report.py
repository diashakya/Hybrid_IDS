import os
from django.core.management.base import BaseCommand
from django.template.loader import render_to_string
from django.utils import timezone
from ids_engine.models import SecurityEvent


class Command(BaseCommand):
      help = 'Generate a PDF audit report of all IDS activity'

      def handle(self, *args, **options):
          try:
              from xhtml2pdf import pisa
          except ImportError:
              self.stdout.write(self.style.ERROR(
                  'xhtml2pdf is not installed. Run: pip install xhtml2pdf'
              ))
              return

          events = SecurityEvent.objects.all().order_by('-timestamp')
          total  = events.count()

          stats = {
              'total':    total,
              'blocked':  events.filter(action_taken='BLOCK').count(),
              'alerted':  events.filter(action_taken='ALERT').count(),
              'allowed':  events.filter(action_taken='ALLOW').count(),
              'critical': events.filter(risk_level='CRITICAL').count(),
              'high':     events.filter(risk_level='HIGH').count(),
              'medium':   events.filter(risk_level='MEDIUM').count(),
              'low':      events.filter(risk_level='LOW').count(),
          }

          rule_counts = {}
          for e in events.filter(rule_triggered=True):
              name = e.rule_name or 'unknown'
              rule_counts[name] = rule_counts.get(name, 0) + 1

          top_rules = sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)

          # Detection comparison
          rule_detected   = events.filter(rule_score__gt=30).count()
          ml_detected     = events.filter(ml_anomaly_score__gt=30).count()
          hybrid_detected = events.exclude(risk_level='LOW').count()

          comparison = {
              'rule_detected':    rule_detected,
              'ml_detected':      ml_detected,
              'hybrid_detected':  hybrid_detected,
              'rule_rate':    round(rule_detected   / total * 100, 1) if total else 0,
              'ml_rate':      round(ml_detected     / total * 100, 1) if total else 0,
              'hybrid_rate':  round(hybrid_detected / total * 100, 1) if total else 0,
          }

          context = {
              'generated_at': timezone.now().strftime('%Y-%m-%d %H:%M:%S'),
              'stats':        stats,
              'top_rules':    top_rules,
              'comparison':   comparison,
              'recent_events': events[:50],
          }

          html_string = render_to_string('ids_engine/audit_report.html', context)

          output_path = os.path.join(os.getcwd(), 'audit_report.pdf')
          with open(output_path, 'wb') as pdf_file:
              pisa.CreatePDF(html_string, dest=pdf_file)

          self.stdout.write(self.style.SUCCESS(
              f'Audit report saved to: {output_path}'
          ))
