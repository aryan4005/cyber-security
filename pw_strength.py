#!/usr/bin/env python3
"""
     # Pw Strength Static
Password Strength Analyzer
Checks length, entropy, dictionary words, and common patterns.

Usage:
    python pw_strength.py

Optional:
    - Place a wordlist file (e.g., rockyou.txt) and pass its path to Analyzer(load_wordlist=...)
"""

import math
import re
from collections import Counter
from typing import List, Optional, Tuple

# ---------- Configuration ----------
COMMON_PASSWORDS = {
    # small built-in list; you should add rockyou.txt or other lists for production use
    "123456", "password", "12345678", "qwerty", "abc123", "football", "letmein",
    "monkey", "iloveyou", "admin", "welcome", "login", "princess", "solo"
}

SEQUENTIAL_PATTERNS = [
    "abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "0123456789",
    "`1234567890-=",
    "qwertyuiop[]\\",
    "asdfghjkl;'",
    "zxcvbnm,./"
]


# ---------- Utility checks ----------
def shannon_entropy(password: str) -> float:
    """Compute Shannon entropy (bits) of the password string."""
    if not password:
        return 0.0
    freq = Counter(password)
    length = len(password)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    # entropy is bits-per-character; total bits = entropy * length
    return entropy * length


def char_classes(password: str) -> dict:
    return {
        "lower": bool(re.search(r"[a-z]", password)),
        "upper": bool(re.search(r"[A-Z]", password)),
        "digits": bool(re.search(r"[0-9]", password)),
        "symbols": bool(re.search(r"[^a-zA-Z0-9]", password)),
    }


def has_repeated_chars(password: str, threshold: int = 3) -> bool:
    """Return True if there is a run of 'threshold' or more repeated chars."""
    return bool(re.search(r"(.)\1{" + str(threshold - 1) + r",}", password))


def has_repeated_pattern(password: str, min_len: int = 2) -> bool:
    """Detect repeated substrings like 'ababab' or '123123'."""
    n = len(password)
    for l in range(min_len, n // 2 + 1):
        for i in range(0, n - 2 * l + 1):
            if password[i:i + l] == password[i + l:i + 2 * l]:
                return True
    return False


def has_sequential(password: str, seq_len: int = 3) -> bool:
    """Detect ascending or descending sequences of characters (abc, 321)."""
    pw = password
    # check for sequences in any of the known sequences, forward or backward
    for base in SEQUENTIAL_PATTERNS:
        for i in range(len(base) - seq_len + 1):
            s = base[i:i + seq_len]
            if s in pw or s[::-1] in pw:
                return True
    # also check for sequences across unicode codepoints (letters/digits)
    for i in range(len(pw) - seq_len + 1):
        chunk = pw[i:i + seq_len]
        # convert to ord differences
        diffs = [ord(chunk[j+1]) - ord(chunk[j]) for j in range(len(chunk)-1)]
        # check if all diffs are 1 (ascending) or -1 (descending)
        if all(d == 1 for d in diffs) or all(d == -1 for d in diffs):
            return True
    return False


def contains_dictionary_word(password: str, wordlist: Optional[set], min_len: int = 4) -> Optional[str]:
    """Return a matched dictionary word (lowercase) if found as substring; else None.
       Only checks words >= min_len."""
    if not wordlist:
        return None
    lower_pw = password.lower()
    for word in wordlist:
        if len(word) < min_len:
            continue
        if word in lower_pw:
            return word
    return None


# ---------- Analyzer ----------
class PasswordAnalysis:
    def __init__(self, password: str, wordlist: Optional[set] = None, common_passwords: Optional[set] = None):
        self.password = password or ""
        self.wordlist = wordlist
        self.common_passwords = common_passwords or COMMON_PASSWORDS

        # computed fields
        self.length = len(self.password)
        self.entropy_bits = shannon_entropy(self.password)
        self.char_classes = char_classes(self.password)
        self.repeated_chars = has_repeated_chars(self.password)
        self.repeated_pattern = has_repeated_pattern(self.password)
        self.sequential = has_sequential(self.password)
        self.common_password = self.password.lower() in self.common_passwords
        self.dict_word = contains_dictionary_word(self.password, self.wordlist)

    def score(self) -> Tuple[int, List[str]]:
        """Compute a heuristic score from 0..100 and return suggestions list."""
        score = 0
        suggestions = []

        # Base scoring by length
        if self.length == 0:
            suggestions.append("Password is empty.")
            return 0, suggestions

        # length buckets
        if self.length >= 16:
            score += 30
        elif self.length >= 12:
            score += 20
        elif self.length >= 8:
            score += 10
        else:
            score += 0
            suggestions.append("Make it longer: aim for at least 12 characters.")

        # character variety
        classes_true = sum(self.char_classes.values())
        score += (classes_true - 1) * 10  # 0..30-ish
        if classes_true < 3:
            suggestions.append("Use a mix of lowercase, uppercase, digits, and symbols.")

        # entropy contribution (normalize: target ~60 bits for strong total)
        # clamp entropy contribution to 30 points
        entropy_goal = 60.0
        entropy_points = min(30, int((self.entropy_bits / entropy_goal) * 30))
        score += entropy_points

        # negative checks
        if self.common_password:
            score = max(0, score - 50)
            suggestions.append("This is a very common password — don't use common passwords.")
        if self.dict_word:
            score = max(0, score - 20)
            suggestions.append(f"Contains dictionary word or substring: '{self.dict_word}'. Avoid real words or use leetspeak/length.")
        if self.repeated_chars:
            score = max(0, score - 10)
            suggestions.append("Avoid long runs of the same character (e.g., 'aaaa').")
        if self.repeated_pattern:
            score = max(0, score - 8)
            suggestions.append("Avoid repeated patterns (e.g., 'abcabc' or '123123').")
        if self.sequential:
            score = max(0, score - 8)
            suggestions.append("Avoid predictable sequences like 'abcd' or '1234' or keyboard patterns like 'qwerty'.")

        # final clamp
        score = max(0, min(100, int(score)))

        # polish suggestions: if score high, fewer suggestions
        if score >= 80:
            suggestions = ["Strong password. Consider using a password manager to create & store unique passwords."]
        return score, suggestions

    def summary(self) -> dict:
        score, suggestions = self.score()
        # map score to category
        if score >= 90:
            category = "Excellent"
        elif score >= 75:
            category = "Strong"
        elif score >= 50:
            category = "Moderate"
        elif score >= 25:
            category = "Weak"
        else:
            category = "Very Weak"

        return {
            "password": self.password,
            "length": self.length,
            "entropy_bits": round(self.entropy_bits, 2),
            "char_classes": self.char_classes,
            "common_password": self.common_password,
            "dictionary_word": self.dict_word,
            "repeated_chars": self.repeated_chars,
            "repeated_pattern": self.repeated_pattern,
            "sequential": self.sequential,
            "score": score,
            "category": category,
            "suggestions": suggestions,
        }


# ---------- Wordlist loader ----------
def load_wordlist(path: str, max_words: Optional[int] = 200000) -> set:
    s = set()
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f):
                if max_words and i >= max_words:
                    break
                w = line.strip().lower()
                if w:
                    s.add(w)
    except FileNotFoundError:
        raise
    return s


# ---------- Demo / CLI ----------
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Password Strength Analyzer")
    parser.add_argument("--wordlist", "-w", type=str, default=None,
                        help="Optional path to a wordlist file (one word per line) for dictionary checks.")
    parser.add_argument("--password", "-p", type=str, default=None,
                        help="Password to analyze. If omitted, runs demo on a few examples.")
    args = parser.parse_args()

    wl = None
    if args.wordlist:
        print(f"Loading wordlist from {args.wordlist} (this may take a while)...")
        try:
            wl = load_wordlist(args.wordlist)
            print(f"Loaded {len(wl)} words.")
        except FileNotFoundError:
            print("Wordlist file not found. Continuing without dictionary checks.")
            wl = None

    examples = []
    if args.password is not None:
        examples = [args.password]
    else:
        examples = [
            "Aryan@3188",
            "Aryan@4005",
            "Aryan@2611",
            "aryan4005",
            "aryan3188",
            "aryan2611"
           
        ]

    for pw in examples:
        a = PasswordAnalysis(pw, wordlist=wl)
        s = a.summary()
        print("-" * 60)
        print(f"Password: {s['password']!r}")
        print(f"Length: {s['length']}, Entropy bits: {s['entropy_bits']}")
        print("Char classes:", ", ".join(k for k, v in s["char_classes"].items() if v))
        print("Common password:", s["common_password"])
        print("Contains dictionary substring:", s["dictionary_word"])
        print("Repeated chars:", s["repeated_chars"])
        print("Repeated pattern:", s["repeated_pattern"])
        print("Sequential pattern:", s["sequential"])
        print(f"Score: {s['score']} / 100  => {s['category']}")
        print("Suggestions:")
        for sug in s['suggestions']:
            print("  -", sug)
    print("-" * 60)
