SYSTEM_PROMPT = """You are an offensive security expert analyzing a software repository.
Your role is to reason like an attacker: correlate security findings, identify exploit chains,
and construct a narrative of how an adversary could abuse these vulnerabilities step by step.

Rules:
- Be specific about the attack sequence — reference actual files and line numbers when available
- Map each step to a MITRE ATT&CK technique when possible
- Assess business impact in concrete terms
- Do not hallucinate findings that aren't in the input
- Output must be in JSON format as specified
"""


def build_chain_of_events_prompt(findings: list[dict], cti_data: dict) -> str:
    import json
    return f"""Analyze these security findings and construct an attack chain of events.

FINDINGS:
{json.dumps(findings, indent=2)}

CTI CONTEXT (active threat actors and campaigns):
{json.dumps(cti_data, indent=2)}

Return JSON with this exact structure:
{{
  "chain_steps": [
    {{
      "step": 1,
      "action": "string — what attacker does",
      "finding_ids": ["uuid"],
      "ttp": "T1234.001",
      "impact": "string"
    }}
  ],
  "narrative": "string — 2-3 paragraph attack story",
  "entry_points": ["string"],
  "blast_radius": "string"
}}"""
