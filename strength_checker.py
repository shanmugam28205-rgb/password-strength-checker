"""
strength_checker.py
Core logic for evaluating password strength.
"""

import re
import math
import os

COMMON_PASSWORDS_FILE = os.path.join(os.path.dirname(__file__), "common_passwords.txt")


def load_common_passwords():
    """Load the blocklist of common/leaked passwords into a set for fast lookup."""
    try:
        with open(COMMON_PASSWORDS_FILE, "r", encoding="utf-8") as f:
            return set(line.strip().lower() for line in f if line.strip())
    except FileNotFoundError:
        return set()


COMMON_PASSWORDS = load_common_passwords()


def check_length(password):
    """Return points based on password length."""
    length = len(password)
    if length >= 12:
        return 2
    elif length >= 8:
        return 1
    return 0


def check_character_variety(password):
    """Return points based on character type diversity."""
    score = 0
    if re.search(r"[a-z]", password):
        score += 1
    if re.search(r"[A-Z]", password):
        score += 1
    if re.search(r"[0-9]", password):
        score += 1
    if re.search(r"[^a-zA-Z0-9]", password):
        score += 1
    return score


def check_common_password(password):
    """Return True if password is found in the common/leaked password list."""
    return password.lower() in COMMON_PASSWORDS


def check_patterns(password):
    """Detect weak patterns: repeated chars, sequences, keyboard walks."""
    issues = []

    # Repeated characters, e.g. "aaaa" or "1111"
    if re.search(r"(.)\1{2,}", password):
        issues.append("Avoid repeating the same character multiple times")

    # Sequential numbers or letters, e.g. "1234", "abcd"
    sequences = ["0123456789", "abcdefghijklmnopqrstuvwxyz"]
    lowered = password.lower()
    for seq in sequences:
        for i in range(len(seq) - 3):
            if seq[i:i + 4] in lowered:
                issues.append("Avoid sequential characters like '1234' or 'abcd'")
                break

    # Common keyboard walks
    keyboard_patterns = ["qwerty", "asdf", "zxcv", "qazwsx"]
    for pattern in keyboard_patterns:
        if pattern in lowered:
            issues.append("Avoid common keyboard patterns like 'qwerty'")
            break

    return issues


def calculate_entropy(password):
    """Estimate entropy (bits) based on character pool size and length."""
    pool_size = 0
    if re.search(r"[a-z]", password):
        pool_size += 26
    if re.search(r"[A-Z]", password):
        pool_size += 26
    if re.search(r"[0-9]", password):
        pool_size += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool_size += 32

    if pool_size == 0 or len(password) == 0:
        return 0

    entropy = len(password) * math.log2(pool_size)
    return round(entropy, 2)


def estimate_crack_time(entropy_bits):
    """Very rough crack-time estimate assuming 1 billion guesses/sec."""
    guesses_per_second = 1_000_000_000
    seconds = (2 ** entropy_bits) / guesses_per_second

    if seconds < 1:
        return "Instantly"
    elif seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        return f"{seconds / 60:.1f} minutes"
    elif seconds < 86400:
        return f"{seconds / 3600:.1f} hours"
    elif seconds < 31536000:
        return f"{seconds / 86400:.1f} days"
    else:
        years = seconds / 31536000
        if years > 1e6:
            return "Millions of years"
        return f"{years:.1f} years"


def get_strength_score(password):
    """
    Master function: runs all checks and returns a full result dict.
    """
    if not password:
        return {
            "score": 0,
            "label": "No password entered",
            "entropy": 0,
            "crack_time": "N/A",
            "tips": ["Enter a password to check its strength"]
        }

    score = 0
    tips = []

    score += check_length(password)
    score += check_character_variety(password)

    if check_common_password(password):
        score -= 3
        tips.append("This password appears in common/leaked password lists. Avoid it.")

    pattern_issues = check_patterns(password)
    if pattern_issues:
        score -= len(pattern_issues)
        tips.extend(pattern_issues)

    if len(password) < 8:
        tips.append("Use at least 8 characters (12+ recommended)")
    if not re.search(r"[A-Z]", password):
        tips.append("Add an uppercase letter")
    if not re.search(r"[0-9]", password):
        tips.append("Add a number")
    if not re.search(r"[^a-zA-Z0-9]", password):
        tips.append("Add a special character (e.g. !, @, #, $)")

    score = max(0, score)
    entropy = calculate_entropy(password)
    crack_time = estimate_crack_time(entropy)

    if score <= 2:
        label = "Weak"
    elif score <= 4:
        label = "Medium"
    else:
        label = "Strong"

    return {
        "score": score,
        "label": label,
        "entropy": entropy,
        "crack_time": crack_time,
        "tips": tips if tips else ["Great password!"]
    }


if __name__ == "__main__":
    # Quick manual test when run directly
    test_passwords = ["123456", "password1", "Tr0ub4dor&3", "Xk9#mP2$vL8qR!"]
    for pw in test_passwords:
        result = get_strength_score(pw)
        print(f"{pw} -> {result}")
