"""MITRE ATT&CK mapping module.
One table mapping each detection rule to tactic, technique ID, and technique name.

NOTE: All technique and tactic IDs should be checked and verified against https://attack.mitre.org.
NOTE on large_data_transfer: We map large_data_transfer to T1567 (Exfiltration Over Web Service)
rather than T1041 (Exfiltration Over C2 Channel) because simulated data egress models bulk transfer
over web/cloud endpoints (e.g., S3 get object, bulk download).
"""

# Mapping table: rule name -> MITRE ATT&CK information
# Check against attack.mitre.org for official tactic and technique definitions.
RULE_MITRE_MAP = {
    "brute_force": {
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "technique_id": "T1110",
        "technique_name": "Brute Force",
    },
    "password_spraying": {
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "technique_id": "T1110.003",
        "technique_name": "Password Spraying",
    },
    "new_country_login": {
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
    },
    "impossible_travel": {
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
    },
    "off_hours_login": {
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
    },
    "privilege_escalation": {
        "tactic": "Privilege Escalation",
        "tactic_id": "TA0004",
        "technique_id": "T1098",
        "technique_name": "Account Manipulation",
    },
    "defense_evasion": {
        "tactic": "Defense Evasion",
        "tactic_id": "TA0005",
        "technique_id": "T1562",
        "technique_name": "Impair Defenses",
    },
    "large_data_transfer": {
        "tactic": "Exfiltration",
        "tactic_id": "TA0010",
        "technique_id": "T1567",
        "technique_name": "Exfiltration Over Web Service",
    },
    "cryptominer": {
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "technique_id": "T1496",
        "technique_name": "Resource Hijacking",
    },
}

_DEFAULT = {
    "tactic": "Initial Access",
    "tactic_id": "TA0001",
    "technique_id": "T1078",
    "technique_name": "Valid Accounts",
}


def get_mitre(rule_name: str) -> dict:
    """Return MITRE mapping dict for a detection rule."""
    mapping = RULE_MITRE_MAP.get(rule_name, _DEFAULT)
    tactic = mapping["tactic"]
    tactic_id = mapping["tactic_id"]
    technique_id = mapping["technique_id"]
    technique_name = mapping["technique_name"]
    return {
        "tactic": tactic,
        "tactic_id": tactic_id,
        "technique_id": technique_id,
        "technique_name": technique_name,
        "formatted_tactic": f"{tactic} ({tactic_id})",
        "formatted_technique": f"{technique_id} {technique_name}",
    }
