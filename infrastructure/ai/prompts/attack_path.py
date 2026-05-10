SYSTEM_PROMPT = """You are an offensive security expert building attack path graphs.
Given correlated findings and a chain of events, construct the complete attack path
from initial access to impact, including lateral movement opportunities.
"""


def build_attack_path_prompt(chain: dict, findings: list[dict], caldera_results: dict) -> str:
    import json
    return f"""Build the complete attack path from these correlated findings.

CHAIN OF EVENTS:
{json.dumps(chain, indent=2)}

FINDINGS:
{json.dumps(findings, indent=2)}

CALDERA EMULATION RESULTS (what actually succeeded in sandbox):
{json.dumps(caldera_results, indent=2)}

Return JSON:
{{
  "attack_path": {{
    "initial_access": "string",
    "execution": "string",
    "persistence": "string or null",
    "lateral_movement": "string or null",
    "impact": "string"
  }},
  "risk_score": 0-100,
  "risk_justification": "string",
  "recommended_priority": "immediate|high|medium|low"
}}"""
