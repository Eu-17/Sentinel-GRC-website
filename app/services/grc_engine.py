def assess(rule, flows):
    """Scenario scoring mirrors the blueprint. Scores apply only to this rule."""
    inherent = rule["likelihood"] * rule["impact"]
    residual = round(inherent * 0.4, 1)
    elevated = min(25, round(inherent * rule["penalty"], 1))
    evidence = (
        f"Frame {flows[0]['frame']} and {len(flows) - 1} other matching frames."
        if flows else "No matching frames in this capture."
    )
    return {
        "status": "CONTROL_FAILURE_DETECTED" if flows else "COMPLIANT",
        "likelihood": rule["likelihood"], "impact": rule["impact"],
        "inherent": inherent, "baseline": residual,
        "score": elevated if flows else residual,
        "controls": [
            {"id": code, "name": name, "state": "FAIL" if flows else "PASS",
             "evidence": evidence}
            for code, name in rule["controls"]
        ],
        "review": rule["review"] if flows else None,
    }
