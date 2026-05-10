SYSTEM_PROMPT = """You are a security analyst writing a PR security review.
Write clearly for developers — explain the risk in business terms, not just CVE numbers.
Be actionable: tell them exactly what to do.
"""


def build_pr_report_prompt(
    findings: list[dict],
    attack_path: dict | None,
    risk_score: int,
    risk_level: str,
) -> str:
    import json
    return f"""Write a security review comment for this PR.

RISK SCORE: {risk_score}/100 ({risk_level.upper()})

FINDINGS ({len(findings)} total):
{json.dumps(findings[:20], indent=2)}

ATTACK PATH:
{json.dumps(attack_path, indent=2) if attack_path else 'Not available'}

Write a GitHub PR comment in Markdown with:
1. ## Security Review Summary (risk score badge, one-line verdict)
2. ## Critical Findings (only CRITICAL/HIGH — table format)
3. ## Attack Scenario (if attack path available — 2-3 sentences)
4. ## Required Actions (numbered list — what must be fixed before merge)
5. ## Patches Available (note that code suggestions are attached)
"""
