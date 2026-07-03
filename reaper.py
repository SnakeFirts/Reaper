from pathlib import Path
import sqlite3
import math
from zxcvbn import zxcvbn
import re
import hashlib
import requests
import typer

app = typer.Typer(add_completion=False)

BASE_DIR = Path(__file__).resolve().parent
WORDLISTS_DIR = BASE_DIR / "wordlists"
DB_PATH = WORDLISTS_DIR / "wordlists.db"

DICTIONARY_WEIGHTS = {
    "common": 5,
    "rockyou": 15,
    "xato": 10,
    "ncsc": 12,
    "darkweb": 20
}

LEGACY_SOURCES = [
    ("common", "common.txt"),
    ("rockyou", "rockyou.txt"),
    ("xato", "xato-net-10-million-passwords.txt"),
    ("ncsc", "seclists/100k-most-used-passwords-NCSC.txt"),
    ("darkweb", "seclists/darkweb2017_top-10000.txt"),
]


def get_db_connection():
    """
    Devuelve una conexion a wordlists.db, o None si no existe.
    La base se construye una sola vez con scripts/build_wordlist_db.py
    en vez de cargar millones de lineas a memoria en cada ejecucion.
    """
    if not DB_PATH.exists():
        return None
    return sqlite3.connect(DB_PATH)


def load_dictionary(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return set(line.strip().lower() for line in f if line.strip())
    except FileNotFoundError:
        print(f"[!] DICTIONARY NOT FOUND: {path}")
        return set()


def load_legacy_dictionaries():
    """Fallback lento (carga todo a RAM) si no existe wordlists.db."""
    dictionaries = {}
    for name, relative_path in LEGACY_SOURCES:
        dictionaries[name] = load_dictionary(str(WORDLISTS_DIR / relative_path))
    return dictionaries


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


def normalize_core(password):
    """
    Igual que normalize(), pero preservando el sufijo numerico como
    sufijo en vez de tratarlo como leetspeak.

    Bug que arregla: normalize() sustituye digitos en CUALQUIER
    posicion, asi que "P4ssw0rd123" queda como "passwordi2e" (el "1"
    y el "3" del sufijo se convierten en letras), y nunca hace match
    con "password123" en el diccionario. Aqui separamos el sufijo
    numerico final ANTES de sustituir, y lo dejamos intacto:
    "P4ssw0rd123" -> core="P4ssw0rd", sufijo="123"
                   -> normalize("P4ssw0rd") + "123" = "password123"
    """
    match = re.match(r"^(.*?)(\d+)$", password)
    if match and match.group(1):
        core, suffix = match.group(1), match.group(2)
        return normalize(core) + suffix
    return normalize(password)


def lookup_word_db(conn, word):
    """Devuelve la lista de fuentes (dictionaries) en las que aparece `word`."""
    rows = conn.execute(
        "SELECT DISTINCT source FROM words WHERE word = ?", (word,)
    ).fetchall()
    return [row[0] for row in rows]


def check_dictionary(password, conn=None, dictionaries=None):
    password = password.lower()
    if conn is not None:
        return lookup_word_db(conn, password)
    return [name for name, dic in dictionaries.items() if password in dic]


def _lookup_sources(candidate, conn, dictionaries):
    if conn is not None:
        return lookup_word_db(conn, candidate)
    return [name for name, dic in dictionaries.items() if candidate in dic]


def check_variants(password, conn=None, dictionaries=None):
    full = normalize(password)
    core = normalize_core(password)
    
    for candidate in (core, full) if core != full else (full,):
        sources = _lookup_sources(candidate, conn, dictionaries)
        if sources:
            return True, candidate, sources[0]
    return False, full, None


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
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"[!] HIBP lookup failed: {e}")
        return None

    for line in response.text.splitlines():
        h, count = line.split(":")
        if h == suffix:
            return int(count)
    return 0


def run_zxcvbn(password):
    result = zxcvbn(password)
    return {
        "score": result["score"],
        "crack_time_display": result["crack_times_display"]["offline_slow_hashing_1e4_per_second"],
        "warning": result["feedback"]["warning"],
        "suggestions": result["feedback"]["suggestions"],
    }


def calculate_score(dictionary_hits, hibp_count, patterns, is_variant, zx_score):
    score = zx_score * 25
    
    dictionary_penalty = sum(
        DICTIONARY_WEIGHTS.get(hit, 5) + (5 if hit == "darkweb" else 0)
        for hit in dictionary_hits
    )
    score -= dictionary_penalty

    if is_variant:
        score -= 15

    if hibp_count is not None and hibp_count > 0:
        hibp_penalty = min(85, 30 + 15 * math.log10(hibp_count + 1))
        score -= hibp_penalty

    score -= len(patterns) * 5

    return max(0, min(100, round(score)))


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


def mask_password(password):
    if len(password) <= 2:
        return "*" * len(password)
    return password[0] + "*" * (len(password) - 2) + password[-1]


def print_separator():
    print("-" * 50)


def print_label(label, value):
    print("  " + f"[{label}]".ljust(20) + f" {value}")


def print_list_label(label, items, empty_text):
    if items:
        print_label(label, f"{len(items)} detectado(s)" if items else "")
        for item in items:
            print(f"                       - {item}")
    else:
        print_label(label, empty_text)


def generate_report(display_password, score, classification, hibp_count,
                     dictionary_hits, patterns, normalized, variant_source, zx, masked=True):
    print("\n")
    print("  ██████  ███████  █████  ██████  ███████ ██████")
    print("  ██   ██ ██      ██   ██ ██   ██ ██      ██   ██")
    print("  ██████  █████   ███████ ██████  █████   ██████")
    print("  ██   ██ ██      ██   ██ ██      ██      ██   ██")
    print("  ██   ██ ███████ ██   ██ ██      ███████ ██   ██")
    print("")
    print("  [PASSWORD SECURITY ANALYSIS - v2.3]")
    print("  [CODENAME: REAPER]")
    print("")
    print_separator()
    print("")

    display_normalized = mask_password(normalized) if masked else normalized

    print_label("TARGET", display_password)
    print_label("NORMALIZED", display_normalized)
    print("")
    print_separator()
    print("")

    print_label("SCORE", f"{score}/100")
    print_label("STATUS", classification)
    print_label("EST. CRACK TIME", zx["crack_time_display"])
    print("")
    print_separator()
    print("")

    print_label(
        "BREACH DATABASE",
        f"{hibp_count} occurrences" if hibp_count else
        ("UNKNOWN (lookup failed)" if hibp_count is None else "NOT FOUND")
    )
    print("")

    print_list_label("DICTIONARY HITS", dictionary_hits, "CLEAR")
    print("")

    print_label("VARIANT DETECTION", variant_source.upper() if variant_source else "NEGATIVE")
    print("")

    print_list_label("HUMAN PATTERNS", patterns, "NONE")
    print("")

    if zx["warning"] or zx["suggestions"]:
        print_separator()
        print("")
        print_label("ZXCVBN FEEDBACK", zx["warning"] or "-")
        for s in zx["suggestions"]:
            print(f"                       - {s}")
        print("")

    print_separator()
    print("")

    messages = {
        "CRITICAL": ("!!! CRITICAL THREAT DETECTED !!!",
                     "Recommendation: CHANGE IMMEDIATELY",
                     "This password is compromised."),
        "WEAK": ("[!] WEAK PASSWORD",
                 "Recommendation: Use a stronger password",
                 "Avoid common words and patterns."),
        "MODERATE": ("[~] MODERATE SECURITY",
                      "Recommendation: Consider strengthening",
                      "with more complexity and length."),
        "STRONG": ("[OK] STRONG PASSWORD",
                    "This password provides good security.",
                    ""),
        "REAPER-CLASS": ("[+] REAPER-CLASS SECURITY",
                          "Maximum security level achieved.",
                          "Your password is among the strongest."),
    }
    for line in messages[classification]:
        if line:
            print(f"  {line}")

    print("")
    print_separator()
    print("  [END OF REPORT]")
    print("")


def analizar_password(password, mask=True, use_hibp=True):
    conn = get_db_connection()
    dictionaries = None
    if conn is None:
        print("[!] wordlists.db no encontrado. Usando modo lento (carga completa en RAM).")
        print("[!] Corre 'python3 scripts/build_wordlist_db.py' para acelerar futuras ejecuciones.\n")
        dictionaries = load_legacy_dictionaries()

    try:
        dictionary_hits = check_dictionary(password, conn=conn, dictionaries=dictionaries)
        is_variant, normalized, variant_source = check_variants(password, conn=conn, dictionaries=dictionaries)
    finally:
        if conn is not None:
            conn.close()

    patterns = detect_human_patterns(password)
    zx = run_zxcvbn(password)
    hibp_count = check_hibp(password) if use_hibp else None

    score = calculate_score(dictionary_hits, hibp_count, patterns, is_variant, zx["score"])
    classification = classify(score)

    display_password = mask_password(password) if mask else password

    generate_report(display_password, score, classification, hibp_count,
                     dictionary_hits, patterns, normalized, variant_source, zx, masked=mask)


@app.command()
def main(
    password: str = typer.Option(
        None, "--password", "-p",
        help="Contraseña a analizar. Si no se da, se pide de forma interactiva (sin eco en pantalla)."
    ),
    mask: bool = typer.Option(
        True, "--mask/--no-mask",
        help="Enmascarar la contraseña en el reporte final."
    ),
    hibp: bool = typer.Option(
        True, "--hibp/--no-hibp",
        help="Consultar Have I Been Pwned (requiere conexión a internet)."
    ),
):
    if password is None:
        password = typer.prompt("Enter password to analyze", hide_input=True)
    analizar_password(password, mask=mask, use_hibp=hibp)


if __name__ == "__main__":
    app()