from zxcvbn import zxcvbn
import re
import hashlib
import requests
import time

DICTIONARY_WEIGHTS = {
    "common": 5,
    "rockyou": 15,
    "xato": 10,
    "ncsc": 12,
    "darkweb": 20
}

def load_dictionary(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return set(line.strip().lower() for line in f if line.strip())
    except FileNotFoundError:
        print(f"[!] DICTIONARY NOT FOUND: {path}")
        return set()

def check_dictionary(password, dictionaries):
    password = password.lower()
    hits = []
    for name, dic in dictionaries.items():
        if password in dic:
            hits.append(name)
    return hits

def normalize(password):
    replacements = {
        "4": "a", "@": "a",
        "3": "e",
        "1": "i", "!": "i",
        "0": "o",
        "$": "s",
        "5": "s",
    }
    result = password.lower()
    for k, v in replacements.items():
        result = result.replace(k, v)
    return result

def check_variants(password, dictionaries):
    normalized = normalize(password)
    for name, dic in dictionaries.items():
        if normalized in dic:
            return True, normalized, name
    return False, normalized, None

def detect_human_patterns(password):
    patterns = []
    if re.search(r"(.)\1{2,}", password):
        patterns.append("Character repetition (aaa, 111)")
    if re.search(r"(123|234|345|abc|bcd|cde)", password.lower()):
        patterns.append("Simple sequence")
    if password.lower().startswith(("admin", "user", "root")):
        patterns.append("Common system prefix")
    if password.lower().endswith(("123", "2024", "2025", "!", "1234")):
        patterns.append("Common suffix")
    return patterns

def check_hibp(password):
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code != 200:
            return 0
        hashes = response.text.splitlines()
        for line in hashes:
            h, count = line.split(":")
            if h == suffix:
                return int(count)
    except:
        pass
    return 0

def calculate_score(password, dictionary_hits, hibp_count, patterns, is_variant):
    score = 100
    if len(password) < 8:
        score -= 25
    elif len(password) < 12:
        score -= 10
    dictionary_penalty = 0
    for hit in dictionary_hits:
        weight = DICTIONARY_WEIGHTS.get(hit, 5)
        if hit == "darkweb":
            weight += 5
        dictionary_penalty += weight
    score -= dictionary_penalty
    if is_variant:
        score -= 20
    if hibp_count > 0:
        score -= 40
    score -= len(patterns) * 10
    return max(score, 0)

def classify(score):
    if score <= 20:
        return "CRITICAL"
    elif score <= 40:
        return "WEAK"
    elif score <= 70:
        return "MODERATE"
    elif score <= 90:
        return "STRONG"
    else:
        return "REAPER-CLASS"

def print_mgs_separator():
    print("-" * 60)

def print_mgs_label(label, value, indent=2):
    print(" " * indent + f"[{label}]".ljust(18) + f" {value}")

def generate_report(password, score, classification, hibp_count, dictionary_hits, patterns, normalized, variant_source):
    print("\n")
    print("  ██████  ███████  █████  ██████  ███████ ██████")
    print("  ██   ██ ██      ██   ██ ██   ██ ██      ██   ██")
    print("  ██████  █████   ███████ ██████  █████   ██████")
    print("  ██   ██ ██      ██   ██ ██      ██      ██   ██")
    print("  ██   ██ ███████ ██   ██ ██      ███████ ██   ██")
    print("")
    print("  [PASSWORD SECURITY ANALYSIS - v2.0]")
    print("  [CODENAME: REAPER]")
    print("")
    print_mgs_separator()
    print("")
    
    print("  [TARGET]".ljust(18) + f" {password}")
    print("  [NORMALIZED]".ljust(18) + f" {normalized}")
    print("")
    print_mgs_separator()
    print("")
    
    print("  [SCORE]".ljust(18) + f" {score}/100")
    print("  [STATUS]".ljust(18) + f" {classification}")
    print("")
    print_mgs_separator()
    print("")
    
    print("  [BREACH DATABASE]".ljust(18), end="")
    if hibp_count > 0:
        print(f" {hibp_count} occurrences")
    else:
        print(" NOT FOUND")
    print("")
    
    print("  [DICTIONARY HITS]".ljust(18), end="")
    if dictionary_hits:
        print(f" {len(dictionary_hits)} hit(s)")
        for d in dictionary_hits:
            print(f"                     - {d}")
    else:
        print(" CLEAR")
    print("")
    
    print("  [VARIANT DETECTION]".ljust(18), end="")
    if variant_source:
        print(f" {variant_source.upper()}")
    else:
        print(" NEGATIVE")
    print("")
    
    print("  [HUMAN PATTERNS]".ljust(18), end="")
    if patterns:
        print(f" {len(patterns)} detected")
        for p in patterns:
            print(f"                     - {p}")
    else:
        print(" NONE")
    print("")
    
    print_mgs_separator()
    print("")
    
    if classification == "CRITICAL":
        print("  !!! CRITICAL THREAT DETECTED !!!")
        print("  Recommendation: CHANGE IMMEDIATELY")
        print("  This password is compromised.")
    elif classification == "WEAK":
        print("  [!] WEAK PASSWORD")
        print("  Recommendation: Use a stronger password")
        print("  Avoid common words and patterns.")
    elif classification == "MODERATE":
        print("  [~] MODERATE SECURITY")
        print("  Recommendation: Consider strengthening")
        print("  with more complexity and length.")
    elif classification == "STRONG":
        print("  [OK] STRONG PASSWORD")
        print("  This password provides good security.")
    else:
        print("  [+] REAPER-CLASS SECURITY")
        print("  Maximum security level achieved.")
        print("  Your password is among the strongest.")
    
    print("")
    print_mgs_separator()
    print("  [END OF REPORT]")
    print("")

def analizar_password(password):
    print("\033[2J\033[H")
    
    dictionaries = {
        "common": load_dictionary("wordlists/common.txt"),
        "rockyou": load_dictionary("wordlists/rockyou.txt"),
        "xato": load_dictionary("wordlists/xato-net-10-million-passwords.txt"),
        "ncsc": load_dictionary("wordlists/seclists/100k-most-used-passwords-NCSC.txt"),
        "darkweb": load_dictionary("wordlists/seclists/darkweb2017_top-10000.txt"),
    }
    
    dictionary_hits = check_dictionary(password, dictionaries)
    is_variant, normalized, variant_source = check_variants(password, dictionaries)
    patterns = detect_human_patterns(password)
    hibp_count = check_hibp(password)
    score = calculate_score(password, dictionary_hits, hibp_count, patterns, is_variant)
    classification = classify(score)
    
    generate_report(password, score, classification, hibp_count, dictionary_hits, patterns, normalized, variant_source)

if __name__ == "__main__":
    password = input("Enter password to analyze: ")
    analizar_password(password)