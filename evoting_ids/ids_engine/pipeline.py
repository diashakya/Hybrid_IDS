import logging

from ids_engine.models import SecurityEvent
from ids_engine.rule_engine import run_all_rules
from ids_engine.ml_detector import score_event
from ids_engine.risk_scorer import fuse_scores, get_risk_level
from ids_engine.decision_engine import get_action
from ids_engine.compliance_mapper import map_compliance
from ids_engine.session_analyzer import analyse_session

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
              if '/accounts/logout/' in path:
                  event_type = 'LOGOUT'
              elif '/vote/' in path and request.method == 'POST':
                  event_type = 'VOTE_CAST'
              elif '/vote/' in path:
                  event_type = 'PAGE_VIEW'
              elif '/api/' in path:
                  event_type = 'API_REQUEST'
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
              'event_type':      event_type,
          }

          rule_result = run_all_rules(event_data)
          ml_score    = score_event(event_data)
          fused_score = fuse_scores(float(rule_result.score), ml_score)

          # Session-level anomaly analysis
          session_result = analyse_session(session_id, ip_address)
          session_score  = session_result['score']

          # Session score wins if it is the stronger signal
          if session_score > fused_score and session_score > 30:
              final_score        = session_score
              saved_rule_name    = 'session_anomaly'
              saved_rule_triggered = True
              saved_rule_score   = int(session_score)
          else:
              final_score          = fused_score
              saved_rule_name      = rule_result.rule_name
              saved_rule_triggered = rule_result.triggered
              saved_rule_score     = rule_result.score

          risk_level   = get_risk_level(final_score)
          action_taken, should_block = get_action(risk_level)
          iso_control, nist_category = map_compliance(saved_rule_name, risk_level)

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
              rule_triggered   = saved_rule_triggered,
              rule_name        = saved_rule_name,
              rule_score       = saved_rule_score,
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