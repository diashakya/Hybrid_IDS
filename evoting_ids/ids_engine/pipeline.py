import logging

from ids_engine.models import SecurityEvent
from ids_engine.rule_engine import run_all_rules
from ids_engine.ml_detector import score_event
from ids_engine.risk_scorer import fuse_scores, get_risk_level
from ids_engine.decision_engine import get_action
from ids_engine.compliance_mapper import map_compliance

logger = logging.getLogger(__name__)


def run_ids_pipeline(request, event_type='GENERIC') -> tuple:
      try:
          forwarded = request.META.get('HTTP_X_FORWARDED_FOR', '')
          ip_address = (
              forwarded.split(',')[0].strip()
              if forwarded
              else request.META.get('REMOTE_ADDR', '127.0.0.1')
          )
          user_agent = request.META.get('HTTP_USER_AGENT', '')
          session_id = request.session.session_key or ''
          endpoint   = request.path
          method     = request.method
          status_code = 200
          user = request.user if request.user.is_authenticated else None

          if request.method == 'POST':
              payload = {k: v for k, v in request.POST.items() if k != 'csrfmiddlewaretoken'}
              if 'password' in payload:
                  payload['password'] = '***'
          else:
              payload = None

          if event_type == 'GENERIC':
              path = request.path
              if '/accounts/login/' in path:
                  event_type = 'LOGIN_SUCCESS' if user else 'LOGIN_FAIL'
              elif '/vote/' in path:
                  event_type = 'VOTE_CAST'
              elif '/admin/' in path:
                  event_type = 'ADMIN_ACTION'
              else:
                  event_type = 'ANOMALY'

          event_data = {
              'ip_address':      ip_address,
              'user_id':         user.id if user else None,
              'election_id':     request.POST.get('election_id'),
              'request_payload': payload,
              'session_id':      session_id,
              'status_code':     status_code,
          }

          rule_result  = run_all_rules(event_data)
          ml_score     = score_event(event_data)
          final_score  = fuse_scores(float(rule_result.score), ml_score)
          risk_level   = get_risk_level(final_score)
          action_taken, should_block = get_action(risk_level)
          iso_control, nist_category = map_compliance(rule_result.rule_name, risk_level)

          event = SecurityEvent(
              event_type       = event_type,
              user             = user,
              ip_address       = ip_address,
              user_agent       = user_agent,
              session_id       = session_id,
              endpoint         = endpoint,
              method           = method,
              status_code      = status_code,
              request_payload  = payload,
              rule_triggered   = rule_result.triggered,
              rule_name        = rule_result.rule_name,
              rule_score       = rule_result.score,
              ml_anomaly_score = ml_score,
              risk_score       = final_score,
              risk_level       = risk_level,
              action_taken     = action_taken,
              iso_control      = iso_control,
              nist_category    = nist_category,
          )
          event.save()

          return event, should_block

      except Exception as exc:
          logger.exception("IDS pipeline error: %s", exc)
          return None, False