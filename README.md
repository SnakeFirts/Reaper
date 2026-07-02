# <span style="color:#00ff00;">REAPER</span> - <span style="color:#ff6b6b;">Password Security Analysis Tool</span>

<span style="color:#ffd93d;">A comprehensive password security analysis tool that evaluates password strength using multiple criteria including dictionary attacks, breach databases, pattern detection, and variant analysis.</span>

## <span style="color:#6bcfff;">Features</span>

- <span style="color:#ffd93d;">**Multi-dictionary checking**</span>: Tests passwords against multiple wordlists including:
  - <span style="color:#6bcfff;">Common passwords</span>
  - <span style="color:#6bcfff;">RockYou dataset</span>
  - <span style="color:#6bcfff;">Xato 10-million password list</span>
  - <span style="color:#6bcfff;">NCSC top 100k passwords</span>
  - <span style="color:#6bcfff;">DarkWeb 2017 top 10000 passwords</span>

- <span style="color:#ffd93d;">**Breach database integration**</span>: Checks against Have I Been Pwned (HIBP) API to detect if password has been exposed in data breaches

- <span style="color:#ffd93d;">**Variant detection**</span>: Identifies common leetspeak substitutions (e.g., "p@ssw0rd" -> "password")

- <span style="color:#ffd93d;">**Pattern recognition**</span>: Detects common human patterns:
  - <span style="color:#6bcfff;">Character repetition</span>
  - <span style="color:#6bcfff;">Sequential patterns (123, abc)</span>
  - <span style="color:#6bcfff;">Common prefixes/suffixes</span>

- <span style="color:#ffd93d;">**Weighted scoring system**</span>: Calculates security score based on:
  - <span style="color:#6bcfff;">Password length</span>
  - <span style="color:#6bcfff;">Dictionary hits (with weighted values)</span>
  - <span style="color:#6bcfff;">Breach occurrences</span>
  - <span style="color:#6bcfff;">Pattern detection</span>
  - <span style="color:#6bcfff;">Variant modifications</span>

- <span style="color:#ffd93d;">**Classification system**</span>: Categorizes passwords into:
  - <span style="color:#ff6b6b;">CRITICAL: 0-20 points</span>
  - <span style="color:#ffa94d;">WEAK: 21-40 points</span>
  - <span style="color:#ffd93d;">MODERATE: 41-70 points</span>
  - <span style="color:#6bcfff;">STRONG: 71-90 points</span>
  - <span style="color:#00ff00;">REAPER-CLASS: 91-100 points</span>

- <span style="color:#ffd93d;">**Visual report**</span>: Generates detailed MGS-style reports with all analysis results

## <span style="color:#6bcfff;">Installation</span>

### <span style="color:#ffd93d;">Prerequisites</span>

- <span style="color:#6bcfff;">Python 3.6 or higher</span>
- <span style="color:#6bcfff;">pip package manager</span>

### <span style="color:#ffd93d;">Required Dependencies</span>

```bash
pip install zxcvbn requests
```

### <span style="color:#ffd93d;">Directory Structure</span>

Create the following directory structure for wordlists:

```
<span style="color:#6bcfff;">project/</span>
├── <span style="color:#6bcfff;">wordlists/</span>
│   ├── <span style="color:#ffd93d;">common.txt</span>
│   ├── <span style="color:#ffd93d;">rockyou.txt</span>
│   ├── <span style="color:#ffd93d;">xato-net-10-million-passwords.txt</span>
│   └── <span style="color:#6bcfff;">seclists/</span>
│       ├── <span style="color:#ffd93d;">100k-most-used-passwords-NCSC.txt</span>
│       └── <span style="color:#ffd93d;">darkweb2017_top-10000.txt</span>
└── <span style="color:#00ff00;">reaper.py</span>
```

## <span style="color:#6bcfff;">Usage</span>

### <span style="color:#ffd93d;">Basic Usage</span>

Run the script and enter the password when prompted:

```bash
python reaper.py
Enter password to analyze: your_password_here
```

### <span style="color:#ffd93d;">Programmatic Usage</span>

```python
from reaper import analizar_password

# Analyze a password
analizar_password("my_secure_password")
```

## <span style="color:#6bcfff;">Wordlist Setup</span>

The tool requires wordlist files to perform dictionary checks. You can obtain these from:

- <span style="color:#ffd93d;">**common.txt**</span>: Common password lists
- <span style="color:#ffd93d;">**rockyou.txt**</span>: Available from the RockYou dataset
- <span style="color:#ffd93d;">**xato-net-10-million-passwords.txt**</span>: Available from Xato's password list
- <span style="color:#ffd93d;">**NCSC list**</span>: UK National Cyber Security Centre's top 100k passwords
- <span style="color:#ffd93d;">**DarkWeb 2017**</span>: Darkweb credential dumps

### <span style="color:#ffd93d;">Custom Dictionary Configuration</span>

You can modify the dictionary weights in the `DICTIONARY_WEIGHTS` dictionary:

```python
<span style="color:#6bcfff;">DICTIONARY_WEIGHTS = {
    "common": 5,
    "rockyou": 15,
    "xato": 10,
    "ncsc": 12,
    "darkweb": 20
}</span>
```

## <span style="color:#6bcfff;">Report Example</span>

```
  <span style="color:#00ff00;">██████  ███████  █████  ██████  ███████ ██████</span>
  <span style="color:#00ff00;">██   ██ ██      ██   ██ ██   ██ ██      ██   ██</span>
  <span style="color:#00ff00;">██████  █████   ███████ ██████  █████   ██████</span>
  <span style="color:#00ff00;">██   ██ ██      ██   ██ ██      ██      ██   ██</span>
  <span style="color:#00ff00;">██   ██ ███████ ██   ██ ██      ███████ ██   ██</span>

  <span style="color:#6bcfff;">[PASSWORD SECURITY ANALYSIS - v2.0]</span>
  <span style="color:#6bcfff;">[CODENAME: REAPER]</span>

<span style="color:#ffd93d;">------------------------------------------------------------</span>

  <span style="color:#6bcfff;">[TARGET]</span>            password123
  <span style="color:#6bcfff;">[NORMALIZED]</span>        password123

<span style="color:#ffd93d;">------------------------------------------------------------</span>

  <span style="color:#6bcfff;">[SCORE]</span>             <span style="color:#ffa94d;">35/100</span>
  <span style="color:#6bcfff;">[STATUS]</span>            <span style="color:#ffa94d;">WEAK</span>

<span style="color:#ffd93d;">------------------------------------------------------------</span>

  <span style="color:#6bcfff;">[BREACH DATABASE]</span>   <span style="color:#ff6b6b;">157 occurrences</span>
  <span style="color:#6bcfff;">[DICTIONARY HITS]</span>   <span style="color:#ffa94d;">2 hit(s)</span>
                     - common
                     - rockyou
  <span style="color:#6bcfff;">[VARIANT DETECTION]</span> <span style="color:#00ff00;">NEGATIVE</span>
  <span style="color:#6bcfff;">[HUMAN PATTERNS]</span>    <span style="color:#ffa94d;">2 detected</span>
                     - Character repetition
                     - Common suffix

<span style="color:#ffd93d;">------------------------------------------------------------</span>

  <span style="color:#ffa94d;">[!] WEAK PASSWORD</span>
  <span style="color:#ffa94d;">Recommendation: Use a stronger password</span>
  <span style="color:#ffa94d;">Avoid common words and patterns.</span>

<span style="color:#ffd93d;">------------------------------------------------------------</span>
  <span style="color:#6bcfff;">[END OF REPORT]</span>
```

## <span style="color:#6bcfff;">Security Considerations</span>

- <span style="color:#ffd93d;">The tool sends password hashes (first 5 characters only) to the HIBP API</span>
- <span style="color:#00ff00;">Full passwords are never transmitted over the network</span>
- <span style="color:#00ff00;">All analysis is performed locally except the HIBP check</span>
- <span style="color:#ffd93d;">Wordlist files should be stored securely</span>

## <span style="color:#6bcfff;">Limitations</span>

- <span style="color:#ffa94d;">Requires internet connection for HIBP checks</span>
- <span style="color:#ffa94d;">Relies on wordlist quality for dictionary detection</span>
- <span style="color:#ffa94d;">Performance depends on wordlist file sizes</span>
- <span style="color:#ffa94d;">Does not check for context-specific weaknesses (e.g., personal information)</span>

## <span style="color:#6bcfff;">Contributing</span>

<span style="color:#ffd93d;">Contributions are welcome. Please ensure your code maintains the existing style and includes appropriate documentation.</span>

## <span style="color:#6bcfff;">License</span>

<span style="color:#ffd93d;">This project is licensed under the MIT License - see the LICENSE file for details.</span>

## <span style="color:#6bcfff;">Disclaimer</span>

<span style="color:#ffa94d;">This tool is for educational and security assessment purposes only. It is intended to help users understand password security and make informed decisions about their password choices. The tool does not store or transmit passwords (except for the HIBP hash prefix check).</span>

## <span style="color:#6bcfff;">Author</span>

<span style="color:#ffd93d;">[Your Name]</span>

## <span style="color:#6bcfff;">Acknowledgments</span>

- <span style="color:#6bcfff;">Have I Been Pwned team for the breach database API</span>
- <span style="color:#6bcfff;">zxcvbn library for additional password strength metrics</span>
- <span style="color:#6bcfff;">Various wordlist maintainers for providing comprehensive password datasets</span>

---

## <span style="color:#6bcfff;">Color Legend</span>

- <span style="color:#ff6b6b;">🔴 Red: Critical/Weak passwords</span>
- <span style="color:#ffa94d;">🟡 Yellow: Moderate warnings</span>
- <span style="color:#00ff00;">🟢 Green: Strong/REAPER-CLASS passwords</span>
- <span style="color:#6bcfff;">🔵 Blue: Information and status</span>
- <span style="color:#ff6bcb;">🟣 Magenta: Highlights and emphasis</span>