SYSTEM_PROMPT = """You are a security engineer generating patches for vulnerabilities.
Generate minimal, targeted patches that fix the vulnerability without breaking functionality.
Output ONLY valid unified diff format — no explanations outside the JSON structure.
"""


def build_remediation_prompt(finding: dict, file_content: str) -> str:
    import json
    return f"""Generate a security patch for this finding.

FINDING:
{json.dumps(finding, indent=2)}

FILE CONTENT:
{file_content[:8000]}

Return JSON:
{{
  "patch": {{
    "file_path": "string",
    "diff": "unified diff string",
    "explanation": "string — what changed and why (for PR comment)",
    "test_recommendation": "string — how to verify the fix"
  }},
  "alternative_approaches": ["string"]
}}"""
