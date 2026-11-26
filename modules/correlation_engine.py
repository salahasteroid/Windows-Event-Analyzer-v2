from modules.rules_engine import evaluate_rules, findings_from


def correlate_events(events, rule_matches=None):
    """Plain-language findings. Rules are defined in database/rules.json."""

    if rule_matches is None:
        rule_matches = evaluate_rules(events)

    return findings_from(rule_matches)
