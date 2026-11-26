from modules.rules_engine import evaluate_rules, recommendations_from


def build_recommendations(events, rule_matches=None):
    """Priority actions. Rules are defined in database/rules.json."""

    if rule_matches is None:
        rule_matches = evaluate_rules(events)

    return recommendations_from(rule_matches)
