import os
import numpy as np
import joblib
from django.utils import timezone
from datetime import timedelta

FEATURES = [
    'failed_logins_last_60s',
    'requests_per_minute',
    'votes_in_session',
    'hour_of_day',
    'is_new_ip',
    'session_duration_seconds',
    'admin_actions_per_session',
    'status_is_error',
]

MODEL_PATH  = 'ml_models/isolation_forest.joblib'
SCALER_PATH = 'ml_models/scaler.joblib'

_model  = None
_scaler = None


def _load_model():
    global _model, _scaler
    if _model is None or _scaler is None:
        if not os.path.exists(MODEL_PATH) or not os.path.exists(SCALER_PATH):
            return None, None
        _model  = joblib.load(MODEL_PATH)
        _scaler = joblib.load(SCALER_PATH)
    return _model, _scaler


def extract_features(event_data: dict) -> np.ndarray:
    from ids_engine.models import SecurityEvent

    ip      = event_data.get('ip_address', '')
    session = event_data.get('session_id', '')
    now     = timezone.now()

    failed_logins = SecurityEvent.objects.filter(
        ip_address=ip,
        event_type='LOGIN_FAIL',
        timestamp__gte=now - timedelta(seconds=60)
    ).count()

    requests_per_minute = SecurityEvent.objects.filter(
        ip_address=ip,
        timestamp__gte=now - timedelta(seconds=60)
    ).count()

    votes_in_session = SecurityEvent.objects.filter(
        ip_address=ip,
        event_type='VOTE_CAST',
        timestamp__gte=now - timedelta(minutes=30)
    ).count()

    hour_of_day = now.hour

    seen_before = SecurityEvent.objects.filter(
        ip_address=ip,
        timestamp__gte=now - timedelta(days=7)
    ).exists()
    is_new_ip = 0 if seen_before else 1

    first_event = SecurityEvent.objects.filter(
        session_id=session
    ).order_by('timestamp').first()
    if first_event:
        session_duration = max(
            0, (now - first_event.timestamp).total_seconds()
        )
    else:
        session_duration = 0

    admin_actions = SecurityEvent.objects.filter(
        ip_address=ip,
        event_type='ADMIN_ACTION',
        timestamp__gte=now - timedelta(minutes=30)
    ).count()

    status_code = event_data.get('status_code', 200)
    status_is_error = 1 if status_code >= 400 else 0

    vector = np.array([[
        failed_logins,
        requests_per_minute,
        votes_in_session,
        hour_of_day,
        is_new_ip,
        session_duration,
        admin_actions,
        status_is_error,
    ]], dtype=float)

    return vector


def normalise_score(raw: float) -> float:
    clipped = max(-0.8, min(0.5, raw))
    return round((0.5 - clipped) / 1.3 * 100, 1)


def score_event(event_data: dict) -> float:
    model, scaler = _load_model()
    if model is None or scaler is None:
        return 0.0
    features        = extract_features(event_data)
    features_scaled = scaler.transform(features)
    raw_score       = model.score_samples(features_scaled)[0]
    return normalise_score(raw_score)