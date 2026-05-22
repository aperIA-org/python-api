import re


def extract_changed_files(diff_text: str) -> list[str]:
    files = re.findall(r"^\+\+\+ b/(.+)$", diff_text, re.MULTILINE)
    safe: list[str] = []
    for f in files:
        normalized = f.strip()
        if ".." in normalized or normalized.startswith("/"):
            continue
        safe.append(normalized)
    return safe
