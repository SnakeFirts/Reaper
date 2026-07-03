"""
Construye wordlists/wordlists.db a partir de los archivos .txt de wordlists/.

Antes, reaper.py cargaba cada wordlist completo (hasta 47MB / 5.2M lineas)
en un set() de Python EN CADA EJECUCION, solo para analizar una contrasena.
Esto tomaba varios segundos y bastante RAM.

Con este script se construye, UNA SOLA VEZ, una base SQLite indexada.
reaper.py despues hace queries puntuales (O(log n)) en vez de cargar
todo a memoria. Se corre de nuevo solo si agregas/cambias wordlists.

Uso:
    python3 scripts/build_wordlist_db.py
"""

import sqlite3
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
WORDLISTS_DIR = BASE_DIR / "wordlists"
DB_PATH = WORDLISTS_DIR / "wordlists.db"

# (nombre_fuente, ruta relativa a wordlists/)
SOURCES = [
    ("common", "common.txt"),
    ("rockyou", "rockyou.txt"),
    ("xato", "xato-net-10-million-passwords.txt"),
    ("ncsc", "seclists/100k-most-used-passwords-NCSC.txt"),
    ("darkweb", "seclists/darkweb2017_top-10000.txt"),
]

BATCH_SIZE = 100_000


def build():
    if DB_PATH.exists():
        DB_PATH.unlink()

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("PRAGMA journal_mode = OFF")
    cur.execute("PRAGMA synchronous = OFF")
    cur.execute(
        """
        CREATE TABLE words (
            word TEXT NOT NULL,
            source TEXT NOT NULL
        )
        """
    )

    total_inserted = 0
    start = time.time()

    for source, relative_path in SOURCES:
        path = WORDLISTS_DIR / relative_path
        if not path.exists():
            print(f"[!] Omitido (no encontrado): {relative_path}")
            continue

        print(f"[*] Procesando {source} ({relative_path})...")
        batch = []
        count = 0
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                word = line.strip().lower()
                if not word:
                    continue
                batch.append((word, source))
                count += 1
                if len(batch) >= BATCH_SIZE:
                    cur.executemany(
                        "INSERT INTO words (word, source) VALUES (?, ?)", batch
                    )
                    batch.clear()
        if batch:
            cur.executemany("INSERT INTO words (word, source) VALUES (?, ?)", batch)

        conn.commit()
        total_inserted += count
        print(f"    -> {count:,} palabras insertadas")

    print("[*] Creando indice (esto puede tardar unos segundos)...")
    cur.execute("CREATE INDEX idx_word ON words (word)")
    conn.commit()
    conn.close()

    elapsed = time.time() - start
    size_mb = DB_PATH.stat().st_size / (1024 * 1024)
    print(f"\n[+] Listo: {total_inserted:,} palabras totales")
    print(f"[+] Base de datos: {DB_PATH} ({size_mb:.1f} MB)")
    print(f"[+] Tiempo de construccion: {elapsed:.1f}s")


if __name__ == "__main__":
    try:
        build()
    except KeyboardInterrupt:
        print("\n[!] Cancelado")
        sys.exit(1)
