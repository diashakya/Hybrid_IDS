import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from django.db.models import Count


@dataclass
class RuleResult:
      triggered: bool
      severity: str
      score: int
      rule_name: str
      description: str


def brute_force_rule(event_data: dict, db_session=None) -> RuleResult:
      from ids_engine.models import SecurityEvent
      current_type = event_data.get('event_type', '')
      if current_type not in ('LOGIN_FAIL', 'LOGIN_SUCCESS'):
          return RuleResult(False, 'HIGH', 0, 'brute_force_rule', 'Not a login event')
      cutoff = datetime.now(tz=timezone.utc) - timedelta(seconds=60)
      count = SecurityEvent.objects.filter(
          ip_address=event_data['ip_address'],
          event_type='LOGIN_FAIL',
          timestamp__gte=cutoff,
      ).count()
      triggered = count > 5
      return RuleResult(
          triggered=triggered,
          severity='HIGH',
          score=80 if triggered else 0,
          rule_name='brute_force_rule',
          description=f'{count} failed logins from {event_data["ip_address"]} in last 60s',
      )


def duplicate_vote_rule(event_data: dict, db_session=None) -> RuleResult:
      from voting.models import Vote
      user_id = event_data.get('user_id')
      election_id = event_data.get('election_id')
      if not user_id or not election_id:
          return RuleResult(False, 'CRITICAL', 0, 'duplicate_vote_rule', 'No user/election context')
      exists = Vote.objects.filter(voter_id=user_id, election_id=election_id).exists()
      return RuleResult(
          triggered=exists,
          severity='CRITICAL',
          score=100 if exists else 0,
          rule_name='duplicate_vote_rule',
          description=f'User {user_id} already voted in election {election_id}',
      )


def blocked_ip_rule(event_data: dict, db_session=None) -> RuleResult:
      from ids_engine.models import BlockedIP
      is_blocked = BlockedIP.objects.filter(ip_address=event_data['ip_address']).exists()
      return RuleResult(
          triggered=is_blocked,
          severity='CRITICAL',
          score=95 if is_blocked else 0,
          rule_name='blocked_ip_rule',
          description=f'IP {event_data["ip_address"]} is on the blocklist',
      )


def sql_injection_rule(event_data: dict, db_session=None) -> RuleResult:
      pattern = re.compile(
          r"(OR\s+1=1|UNION\s+SELECT|DROP\s+TABLE|SELECT\s+\*|INSERT\s+INTO|DELETE\s+FROM)",
          re.IGNORECASE,
      )
      payload = event_data.get('request_payload') or {}
      payload_str = str(payload)
      triggered = bool(pattern.search(payload_str))
      return RuleResult(
          triggered=triggered,
          severity='HIGH',
          score=75 if triggered else 0,
          rule_name='sql_injection_rule',
          description='SQL injection pattern detected in request payload',
      )


def rapid_request_rule(event_data: dict, db_session=None) -> RuleResult:
      from ids_engine.models import SecurityEvent
      cutoff = datetime.now(tz=timezone.utc) - timedelta(seconds=60)
      count = SecurityEvent.objects.filter(
          ip_address=event_data['ip_address'],
          timestamp__gte=cutoff,
      ).count()
      triggered = count > 30
      return RuleResult(
          triggered=triggered,
          severity='MEDIUM',
          score=50 if triggered else 0,
          rule_name='rapid_request_rule',
          description=f'{count} requests/min from {event_data["ip_address"]}',
      )


def admin_abuse_rule(event_data: dict, db_session=None) -> RuleResult:
      from ids_engine.models import SecurityEvent
      session_id = event_data.get('session_id', '')
      if not session_id:
          return RuleResult(False, 'HIGH', 0, 'admin_abuse_rule', 'No session context')
      count = SecurityEvent.objects.filter(
          session_id=session_id,
          event_type='ADMIN_ACTION',
      ).count()
      triggered = count > 20
      return RuleResult(
          triggered=triggered,
          severity='HIGH',
          score=70 if triggered else 0,
          rule_name='admin_abuse_rule',
          description=f'Admin performed {count} actions in this session',
      )


def aggregate_rules(results: list) -> RuleResult:
      triggered = [r for r in results if r.triggered]
      if not triggered:
          return RuleResult(False, 'LOW', 0, 'none', 'No rules triggered')
      return max(triggered, key=lambda r: r.score)


def run_all_rules(event_data: dict) -> RuleResult:
      results = [
          brute_force_rule(event_data),
          duplicate_vote_rule(event_data),
          blocked_ip_rule(event_data),
          sql_injection_rule(event_data),
          rapid_request_rule(event_data),
          admin_abuse_rule(event_data),
      ]
      return aggregate_rules(results)
