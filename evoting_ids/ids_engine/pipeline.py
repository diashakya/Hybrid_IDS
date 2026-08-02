# pipeline.py — updated to use corrected ml_detector and risk_scorer
import logging

from ids_engine.models import SecurityEvent
from ids_engine.ml_detector import score_event
from ids_engine.rule_engine import run_all_rules
from ids_engine.risk_scorer import fuse_scores, get_risk_level, get_action
from ids_engine.compliance_mapper import map_compliance

logger = logging.getLogger(__name__)


def score_pipeline(event_data: dict) -> dict:
    """
    Core IDS scoring — rule engine + ML detector + risk fusion + compliance.
    Pure function: takes an event_data dict, has no Django request or
    database-write dependency.
    """
    # ── Step 1: Rule engine ──────────────────────────────────────────
    # run_all_rules() already returns the single highest-scoring rule
    # (or a non-triggered placeholder) — it does its own aggregation.
    try:
        best_rule      = run_all_rules(event_data)
        rule_score     = best_rule.score if best_rule.triggered else 0
        rule_name      = best_rule.rule_name if best_rule.triggered else ''
        rule_triggered = best_rule.triggered
    except Exception as e:
        logger.error(f"Rule engine error: {e}")
        rule_score     = 0
        rule_name      = ''
        rule_triggered = False

    # ── Step 2: ML anomaly detector ─────────────────────────────────
    try:
        ml_score = score_event(event_data)
    except Exception as e:
        logger.error(f"ML detector error: {e}")
        ml_score = 0.0

    # ── Step 3: Risk scorer ──────────────────────────────────────────
    final_score = fuse_scores(rule_score, ml_score)
    risk_level  = get_risk_level(final_score)
    action, should_block = get_action(risk_level)

    # ── Step 4: Compliance mapper (returns an (iso, nist) tuple) ─────
    try:
        iso_control, nist_category = map_compliance(rule_name, risk_level)
    except Exception as e:
        logger.error(f"Compliance mapper error: {e}")
        iso_control   = 'A.16.1.2'
        nist_category = 'DE.AE-2'

    return {
        'rule_triggered':   rule_triggered,
        'rule_name':        rule_name,
        'rule_score':       rule_score,
        'ml_anomaly_score': ml_score,
        'risk_score':       final_score,
        'risk_level':       risk_level,
        'action_taken':     action,
        'should_block':     should_block,
        'iso_control':      iso_control,
        'nist_category':    nist_category,
    }


def run_ids_pipeline(request, event_type='GENERIC') -> tuple:
    """
    Called by LoggingMiddleware for every intercepted request.
    Builds event_data from the Django request, runs score_pipeline(),
    saves the resulting SecurityEvent, and returns (event, should_block).
    """
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

        result = score_pipeline(event_data)

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
            rule_triggered   = result['rule_triggered'],
            rule_name        = result['rule_name'],
            rule_score       = result['rule_score'],
            ml_anomaly_score = result['ml_anomaly_score'],
            risk_score       = result['risk_score'],
            risk_level       = result['risk_level'],
            action_taken     = result['action_taken'],
            iso_control      = result['iso_control'],
            nist_category    = result['nist_category'],
        )
        event.save()

        return event, result['should_block']

    except Exception as exc:
        logger.exception("IDS pipeline error: %s", exc)
        return None, False
