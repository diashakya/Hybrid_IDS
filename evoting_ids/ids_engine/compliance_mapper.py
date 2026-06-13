COMPLIANCE_MAP = {
      ('brute_force_rule',    'HIGH'):     ('A.9.4.2',  'PR.AC-7'),
      ('brute_force_rule',    'CRITICAL'): ('A.9.4.2',  'PR.AC-7'),
      ('duplicate_vote_rule', 'CRITICAL'): ('A.12.4.1', 'DE.CM-7'),
      ('sql_injection_rule',  'HIGH'):     ('A.14.2.5', 'PR.IP-12'),
      ('admin_abuse_rule',    'HIGH'):     ('A.9.2.3',  'PR.AC-4'),
      ('rapid_request_rule',  'MEDIUM'):   ('A.12.6.1', 'DE.CM-1'),
      ('blocked_ip_rule',     'CRITICAL'): ('A.13.1.3', 'PR.AC-3'),
  }

FALLBACK = ('A.16.1.2', 'DE.AE-2')


def map_compliance(rule_name: str, risk_level: str) -> tuple:
      return COMPLIANCE_MAP.get((rule_name, risk_level), FALLBACK)
