# risk_scorer.py — updated to match final Colab weighting (0.3/0.7)
# Weighting confirmed by sensitivity analysis (Table 5.2 in report):
#   0.3 rule / 0.7 ML gives highest F1-score (55.8%) across all
#   tested configurations, with FPR reduced 62% vs ML-only baseline.

# ML decision threshold — recalibrated from empirical percentile
# analysis on the actual score distribution (not an assumed 50).
# Set at the 95th percentile of normal traffic scores on NSL-KDD
# evaluation set. Value confirmed from Colab Cell 12b output.
ML_THRESHOLD = 15


def fuse_scores(rule_score: float, ml_score: float) -> float:
    """
    Combine rule engine and ML anomaly scores using final
    validated weighting: 30% rule, 70% ML.
    """
    return round((0.3 * rule_score) + (0.7 * ml_score), 1)


def get_risk_level(final_score: float) -> str:
    """
    Classify fused score into 4 risk levels.
    Thresholds match the decision boundaries evaluated in Table 5.1.
    """
    if final_score > 85:
        return 'CRITICAL'
    elif final_score > 60:
        return 'HIGH'
    elif final_score > 30:
        return 'MEDIUM'
    return 'LOW'


def get_action(risk_level: str) -> tuple:
    """
    Map risk level to (action, should_block) tuple.
    CRITICAL -> BLOCK (HTTP 403, view never executes)
    HIGH/MEDIUM -> ALERT (request proceeds, SOC notified)
    LOW -> ALLOW (normal flow)
    """
    if risk_level == 'CRITICAL':
        return 'BLOCK', True
    elif risk_level in ('HIGH', 'MEDIUM'):
        return 'ALERT', False
    return 'ALLOW', False