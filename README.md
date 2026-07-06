# cyber-security

# Password Strength Analyzer

A command-line tool that analyzes password strength using entropy, character 
diversity, dictionary checks, and common pattern detection — not just length rules.

## Features
- Shannon entropy calculation
- Character class detection (lower/upper/digits/symbols)
- Common password blacklist check
- Optional dictionary substring matching (bring your own wordlist, e.g. rockyou.txt)
- Detects repeated characters, repeated patterns (e.g. `abcabc`), and sequential 
  patterns (e.g. `1234`, `qwerty`)
- Weighted 0–100 scoring with category (Very Weak → Excellent) and actionable suggestions

## Usage
\`\`\`bash
# Run built-in demo examples
python pw_strength.py

# Check a specific password
python pw_strength.py -p "MyPassword123"

# Include a wordlist for dictionary checks
python pw_strength.py -p "MyPassword123" -w rockyou.txt
\`\`\`

## How Scoring Works
- Length: up to 30 points (16+ chars = max)
- Character variety: up to ~30 points (lower/upper/digit/symbol mix)
- Entropy: up to 30 points (normalized against a 60-bit target)
- Penalties: common passwords (-50), dictionary words (-20), repeated chars (-10), 
  repeated patterns (-8), sequential patterns (-8)

## Tech Stack
Python 3, standard library only (no external dependencies)

## Motivation
Built to demonstrate practical understanding of password security principles 
(entropy, common attack patterns, dictionary attacks) relevant to cybersecurity 
and secure development roles.
