from django.core.management.base import BaseCommand
from ids_engine.models import SecurityEvent
from ids_engine.risk_scorer import fuse_scores, get_risk_level


class Command(BaseCommand):
      help = 'Compare Rule-only vs ML-only vs Hybrid detection'

      def handle(self, *args, **options):
          events = SecurityEvent.objects.exclude(ml_anomaly_score=None)
          total = events.count()

          if total == 0:
              self.stdout.write(self.style.WARNING(
                  'No SecurityEvent records with ML scores found. '
                  'Make sure the IDS pipeline has run and the model is trained.'
              ))
              return

          rule_detected  = 0
          ml_detected    = 0
          hybrid_detected = 0

          for e in events:
              # Rule-only: use rule_score alone, threshold >30 = detected
              rule_level = get_risk_level(e.rule_score)
              if rule_level in ('MEDIUM', 'HIGH', 'CRITICAL'):
                  rule_detected += 1

              # ML-only: use ml_anomaly_score alone
              ml_score = e.ml_anomaly_score if e.ml_anomaly_score is not None else 0.0
              ml_level = get_risk_level(ml_score)
              if ml_level in ('MEDIUM', 'HIGH', 'CRITICAL'):
                  ml_detected += 1

              # Hybrid: the actual stored risk_level
              if e.risk_level in ('MEDIUM', 'HIGH', 'CRITICAL'):
                  hybrid_detected += 1

          rule_rate   = round(rule_detected   / total * 100, 1)
          ml_rate     = round(ml_detected     / total * 100, 1)
          hybrid_rate = round(hybrid_detected / total * 100, 1)

          self.stdout.write('\n' + '=' * 52)
          self.stdout.write('  HYBRID IDS — DETECTION COMPARISON REPORT')
          self.stdout.write('=' * 52)
          self.stdout.write(f'  Total events evaluated : {total}')
          self.stdout.write('-' * 52)
          self.stdout.write(f'  {"Method":<20} {"Detected":>10} {"Rate":>10}')
          self.stdout.write('-' * 52)
          self.stdout.write(f'  {"Rule-only":<20} {rule_detected:>10} {rule_rate:>9}%')
          self.stdout.write(f'  {"ML-only":<20} {ml_detected:>10} {ml_rate:>9}%')
          self.stdout.write(f'  {"Hybrid (combined)":<20} {hybrid_detected:>10} {hybrid_rate:>9}%')
          self.stdout.write('=' * 52)

          if hybrid_rate > rule_rate and hybrid_rate > ml_rate:
              self.stdout.write(self.style.SUCCESS(
                  '\n  RESULT: Hybrid outperforms both individual methods.'
              ))
          else:
              self.stdout.write(self.style.WARNING(
                  '\n  RESULT: Hybrid did not outperform on current data. '
                  'Generate more synthetic attack events and retrain.'
              ))
          self.stdout.write('')