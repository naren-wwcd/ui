"""Deterministic risk score 0-100 (plain code, not the LLM).
 score = 30 x severity + 25 x threat-confidence + 20 x asset criticality + 25 x attack stage
Each factor is scaled to 0..1 first. The LLM only supplies the verdict/confidence input."""
from app import intel

W_SEVERITY, W_CONFIDENCE, W_ASSET, W_STAGE = 30, 25, 20, 25

LEVEL4 = {"low": 1, "medium": 2, "high": 3, "critical": 4}
# How far along the attack a MITRE tactic is (1 = early, 4 = damage done)
TACTIC_STAGE = {"Credential Access": 1, "Initial Access": 2, "Execution": 2, "Persistence": 3,
                "Privilege Escalation": 3, "Defense Evasion": 3, "Lateral Movement": 3, "Collection": 3, "Exfiltration": 4, "Impact": 4}
STAGE_MAX = 4


def _level(score: int) -> str:
    return "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 40 else "low"


def score(inc: dict, investigation: dict | None, hosts: list[str]) -> dict:
    # 1) severity of the worst alert
    sev = LEVEL4[inc["severity"]]

    # 2) how likely this is a real attack, according to the agent (0.5 = unknown until it has run)
    if investigation is None:
        conf, conf_text = 0.5, "the agent has not weighed in yet"
    else:
        c, verdict = float(investigation["confidence"]), investigation["verdict"]
        if verdict == "true_positive":
            conf, conf_text = c, f"the agent is {c:.0%} sure it is a real attack"
        elif verdict == "false_positive":
            conf, conf_text = 1 - c, f"the agent is {c:.0%} sure it is a false alarm"
        else:
            conf, conf_text = 0.5, "the agent wants a human to review it"

    # 3) most critical asset involved
    assets = [(LEVEL4.get(intel.get_asset(h).get("criticality"), 2), h) for h in hosts] or [(2, None)]
    crit, crit_host = max(assets)
    crit_name = {v: k for k, v in LEVEL4.items()}[crit]

    # 4) furthest attack stage reached
    tactics = [t["mitre_tactic"].split(" (")[0] for t in inc["timeline"]]
    stage = max([TACTIC_STAGE.get(t, 1) for t in tactics] or [1])
    stage_name = next((t for t in tactics if TACTIC_STAGE.get(t, 1) == stage), "early activity")

    total = round(W_SEVERITY * sev / 4 + W_CONFIDENCE * conf + W_ASSET * crit / 4 + W_STAGE * stage / STAGE_MAX)
    total = max(0, min(100, total))
    asset_text = f"involves a {crit_name}-criticality asset ({crit_host})" if crit_host else "no asset info"

    raw_factors = [
        ("severity", inc["severity"], W_SEVERITY * sev / 4),
        ("agent confidence", f"{conf:.0%}", W_CONFIDENCE * conf),
        ("asset criticality", crit_name, W_ASSET * crit / 4),
        ("attack stage", stage_name, W_STAGE * stage / STAGE_MAX),
    ]
    rounded_pts = [int(round(r[2])) for r in raw_factors]
    diff = total - sum(rounded_pts)
    if diff != 0:
        residuals = [(abs(raw_factors[idx][2] - rounded_pts[idx]), idx) for idx in range(len(raw_factors))]
        residuals.sort(reverse=True)
        step = 1 if diff > 0 else -1
        for i in range(abs(diff)):
            idx = residuals[i % len(residuals)][1]
            rounded_pts[idx] += step

    breakdown = [
        {"factor": raw_factors[i][0], "value": raw_factors[i][1], "points": rounded_pts[i]}
        for i in range(len(raw_factors))
    ]
    llm_pts = rounded_pts[1]
    llm_note = f"{llm_pts} points come from agent confidence"

    return {
        "score": total, "level": _level(total), "final": investigation is not None,
        "justification": (f"{inc['severity'].title()} severity; {conf_text}; {asset_text}; "
                          f"furthest stage reached: {stage_name}."),
        "factors": {"severity": sev, "confidence": round(conf, 2), "asset_criticality": crit, "stage": stage},
        "breakdown": breakdown,
        "llm_influence": llm_note,
        "llm_influence_points": llm_pts,
    }
