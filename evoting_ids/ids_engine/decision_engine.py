def get_action(risk_level: str) -> tuple:
      mapping = {
          'CRITICAL': ('BLOCK', True),
          'HIGH':     ('ALERT', False),
          'MEDIUM':   ('ALERT', False),
          'LOW':      ('ALLOW', False),
      }
      return mapping.get(risk_level, ('ALLOW', False))
