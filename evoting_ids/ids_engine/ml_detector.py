# ml_detector.py — updated to match Colab fixed pipeline
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

# Features that are near-constant/binary in NSL-KDD normal class —
# StandardScaler is unstable on these (std near 0 amplifies rare
# nonzero values into extreme outliers). Leave them raw.
FLAG_FEATURES = [
    'failed_logins_last_60s',
    'votes_in_session',
    'is_new_ip',
    'status_is_error',
    'admin_actions_per_session',
]

# Genuinely continuous features — safe and correct to z-score
CONTINUOUS_FEATURES = [f for f in FEATURES if f not in FLAG_FEATURES]

# Calibrated score range from final Colab training run (Cell 16)
# These values come from model.score_samples() on the 9,000
# normal training records — do NOT hardcode -0.8/+0.5 here
SCORE_MIN = -0.7917
SCORE_MAX = -0.4091



BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH  = os.path.join(BASE_DIR, 'ml_models', 'isolation_forest.joblib')
SCALER_PATH = os.path.join(BASE_DIR, 'ml_models', 'scaler.joblib')


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


def extract_features(event_data: dict) -> dict:
    """
    Extract the 8 raw feature values from the live database.
    Returns a plain dict — scaling is handled separately in score_event().
    """
    from ids_engine.models import SecurityEvent
    import math

    ip      = event_data.get('ip_address', '')
    session = event_data.get('session_id', '')
    now     = timezone.now()

    failed_logins = SecurityEvent.objects.filter(
        ip_address=ip,
        event_type='LOGIN_FAIL',
        timestamp__gte=now - timedelta(seconds=60)
    ).count()

    requests_count = SecurityEvent.objects.filter(
        ip_address=ip,
        timestamp__gte=now - timedelta(seconds=60)
    ).count()
    # Apply same log1p transform used during Colab training
    requests_per_minute = math.log1p(requests_count)

    votes_in_session = SecurityEvent.objects.filter(
        ip_address=ip,
        event_type='VOTE_CAST',
        timestamp__gte=now - timedelta(minutes=30)
    ).count()

    hour_of_day = float(now.hour)

    seen_before = SecurityEvent.objects.filter(
        ip_address=ip,
        timestamp__gte=now - timedelta(days=7)
    ).exists()
    is_new_ip = 0.0 if seen_before else 1.0

    first_event = SecurityEvent.objects.filter(
        session_id=session
    ).order_by('timestamp').first()
    if first_event:
        raw_duration = max(0, (now - first_event.timestamp).total_seconds())
    else:
        raw_duration = 0.0
    # Apply same log1p transform used during Colab training
    session_duration_seconds = math.log1p(raw_duration)

    admin_actions = SecurityEvent.objects.filter(
        ip_address=ip,
        event_type='ADMIN_ACTION',
        timestamp__gte=now - timedelta(minutes=30)
    ).count()

    status_code = event_data.get('status_code', 200)
    status_is_error = 1.0 if int(status_code) >= 400 else 0.0

    return {
        'failed_logins_last_60s':    float(failed_logins),
        'requests_per_minute':        float(requests_per_minute),
        'votes_in_session':           float(votes_in_session),
        'hour_of_day':                float(hour_of_day),
        'is_new_ip':                  float(is_new_ip),
        'session_duration_seconds':   float(session_duration_seconds),
        'admin_actions_per_session':  float(admin_actions),
        'status_is_error':            float(status_is_error),
    }


def normalise_score(raw: float) -> float:
    """
    Calibrated normalisation using the actual score range observed
    during training — NOT hardcoded -0.8/+0.5 constants.

    SCORE_MIN = most anomalous raw score seen on training data
    SCORE_MAX = most normal raw score seen on training data
    Maps to 0 (very normal) -> 100 (very anomalous)
    """
    clipped = max(SCORE_MIN, min(SCORE_MAX, raw))
    return round((SCORE_MAX - clipped) / (SCORE_MAX - SCORE_MIN) * 100, 1)


def score_event(event_data: dict) -> float:
    """
    Main entry point — called by pipeline.py for every request.
    Returns ml_anomaly_score as a float 0.0 to 100.0.
    """
    model, scaler = _load_model()
    if model is None or scaler is None:
        return 0.0

    # Step 1 — extract raw feature values from database
    feature_dict = extract_features(event_data)

    # Step 2 — build DataFrame-like structure preserving column order
    import pandas as pd
    row_df = pd.DataFrame([feature_dict])[FEATURES]

    # Step 3 — selective scaling: ONLY continuous features go through scaler
    # Flag features stay raw — StandardScaler is unstable on near-constant cols
    row_df[CONTINUOUS_FEATURES] = scaler.transform(row_df[CONTINUOUS_FEATURES])

    # Step 4 — convert to numpy in exact FEATURES column order
    X = row_df[FEATURES].values

    # Step 5 — get raw Isolation Forest score and normalise
    raw_score = model.score_samples(X)[0]
    return normalise_score(raw_score)