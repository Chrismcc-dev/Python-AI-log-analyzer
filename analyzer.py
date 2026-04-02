import re
from collections import Counter


ERROR_PATTERNS = {
    "timeout": r"timeout|timed out",
    "connection_error": r"connection refused|connection reset",
    "auth_failure": r"unauthorized|authentication failed",
    "server_error": r"\b500\b|\b503\b|\b502\b",
    "not_found": r"\b404\b|not found",
    "rate_limit": r"\b429\b|rate limit",
}


def analyze_log(file_path):

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    results = Counter()

    for line in lines:
        for label, pattern in ERROR_PATTERNS.items():
            if re.search(pattern, line, re.IGNORECASE):
                results[label] += 1

    return results


def generate_report(results):

    output = "Log Analysis Results\n\n"

    if not results:
        output += "No common issues detected."
        return output

    for issue, count in results.items():
        output += f"{issue} : {count}\n"

    return output