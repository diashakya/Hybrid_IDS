def fuse_scores(rule_score: float, ml_score: float) -> float:
      return round((0.6 * rule_score) + (0.4 * ml_score), 1)


def get_risk_level(final_score: float) -> str:
      if final_score > 85:
          return 'CRITICAL'
      elif final_score > 60:
          return 'HIGH'
      elif final_score > 30:
          return 'MEDIUM'
      return 'LOW'