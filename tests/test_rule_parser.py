import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from rule_engine.models import Severity
from rule_engine.rule_parser import RuleParseError, parse_rules_text


def test_parse_single_rule_all_fields():
    text = """
    rule Test_SSH
        protocol tcp
        src_ip any
        dst_ip 10.0.0.5
        src_port any
        dst_port 22
        flags SYN
        severity high
        message "test message"
        enabled true
    end
    """
    rules = parse_rules_text(text)
    assert len(rules) == 1
    r = rules[0]
    assert r.name == "Test_SSH"
    assert r.protocol == "tcp"
    assert r.dst_ip == "10.0.0.5"
    assert r.dst_port == "22"
    assert r.flags == ["SYN"]
    assert r.severity == Severity.HIGH
    assert r.message == "test message"
    assert r.enabled is True


def test_parse_defaults_when_fields_omitted():
    text = """
    rule Minimal_Rule
    end
    """
    rules = parse_rules_text(text)
    r = rules[0]
    assert r.protocol == "any"
    assert r.src_ip == "any"
    assert r.severity == Severity.MEDIUM
    assert r.enabled is True


def test_parse_multiple_rules():
    text = """
    rule First
        protocol tcp
    end

    rule Second
        protocol udp
    end
    """
    rules = parse_rules_text(text)
    assert [r.name for r in rules] == ["First", "Second"]


def test_parse_comments_and_blank_lines_ignored():
    text = """
    # this is a comment
    rule Commented
        # inline comment style not required, but blank lines should be fine

        protocol tcp
    end
    """
    rules = parse_rules_text(text)
    assert len(rules) == 1


def test_parse_flags_list():
    text = """
    rule Multi_Flag
        protocol tcp
        flags SYN,ACK
    end
    """
    rules = parse_rules_text(text)
    assert rules[0].flags == ["SYN", "ACK"]


def test_parse_flags_none_sentinel():
    text = """
    rule Null_Scan
        protocol tcp
        flags none
    end
    """
    rules = parse_rules_text(text)
    assert rules[0].flags == ["NONE"]


def test_parse_disabled_rule():
    text = """
    rule Disabled_Rule
        enabled false
    end
    """
    rules = parse_rules_text(text)
    assert rules[0].enabled is False


def test_unterminated_rule_raises():
    text = """
    rule Unterminated
        protocol tcp
    """
    with pytest.raises(RuleParseError):
        parse_rules_text(text)


def test_nested_rule_raises():
    text = """
    rule Outer
        rule Inner
        end
    end
    """
    with pytest.raises(RuleParseError):
        parse_rules_text(text)


def test_unknown_field_raises():
    text = """
    rule Bad_Field
        not_a_real_field foo
    end
    """
    with pytest.raises(RuleParseError):
        parse_rules_text(text)


def test_invalid_severity_raises():
    text = """
    rule Bad_Severity
        severity extreme
    end
    """
    with pytest.raises(RuleParseError):
        parse_rules_text(text)


def test_field_outside_rule_raises():
    text = """
    protocol tcp
    """
    with pytest.raises(RuleParseError):
        parse_rules_text(text)


# -- Stage 5: payload_regex --------------------------------------------------

def test_parse_payload_regex_field():
    text = """
    rule SQLi_Probe
        protocol tcp
        payload_regex "1' OR '1'='1"
        severity high
        message "SQLi probe"
    end
    """
    rules = parse_rules_text(text)
    r = rules[0]
    assert r.payload_regex == "1' OR '1'='1"
    assert r.is_payload_rule is True
    # Regex is pre-compiled (bytes-compiled) by the parser.
    import re as _re
    assert isinstance(r._compiled_regex, _re.Pattern)
    assert r._compiled_regex.pattern == b"1' OR '1'='1"


def test_parse_rule_without_payload_regex_is_not_a_payload_rule():
    text = """
    rule Plain
        protocol tcp
        dst_port 22
    end
    """
    rules = parse_rules_text(text)
    assert rules[0].payload_regex is None
    assert rules[0].is_payload_rule is False
    assert rules[0]._compiled_regex is None


def test_parse_invalid_payload_regex_raises():
    """Unbalanced bracket in a payload_regex must raise RuleParseError."""
    text = """
    rule BadRegex
        protocol tcp
        payload_regex "(unclosed"
    end
    """
    with pytest.raises(RuleParseError):
        parse_rules_text(text)
