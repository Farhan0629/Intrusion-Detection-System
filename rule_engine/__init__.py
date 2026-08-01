"""Rule Engine — Stage 2 of the IDS project."""

from .interfaces import AlertHandler
from .models import Alert, Rule, Severity
from .rule_engine import RuleEngine, rule_matches
from .rule_parser import RuleParseError, parse_rules_file, parse_rules_text

__all__ = [
    "AlertHandler",
    "Alert",
    "Rule",
    "Severity",
    "RuleEngine",
    "rule_matches",
    "RuleParseError",
    "parse_rules_file",
    "parse_rules_text",
]
