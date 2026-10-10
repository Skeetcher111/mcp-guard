"""Офлайн-базы угроз: сверка приложений без лимитов и ключей (фаза 11).

Три открытых источника скачиваются раз в сутки в локальную SQLite
(`threatdb.sqlite` рядом с сервисом) и при каждом скане сверяются с
хешами APK и именами пакетов:

- MalwareBazaar (abuse.ch) — SHA-256 известных вредоносных файлов, в том
  числе Android-APK. Совпадение хеша — точная детекция.
- stalkerware-indicators (AssoEchap, GitHub) — имена пакетов приложений
  для слежки за телефоном.
- MVT indicators (Amnesty / mvt-project, GitHub) — пакеты и хеши файлов
  коммерческого шпионского ПО (Pegasus, Predator и др.).

Совпадение хеша — точная детекция (critical). Совпадение только имени
пакета — сильный сигнал (high): имя может совпасть случайно или его может
повторить обычное приложение.

Обновление: `venv/bin/python -m app.threatdb update` (systemd-таймер
mcp-guard-threatdb.timer, раз в сутки). База собирается во временный
файл и подменяется атомарно — сканы во время обновления не ломаются.
"""

from __future__ import annotations

import io
import json
import logging
import os
import re
import sqlite3
import sys
import zipfile
from pathlib import Path

import httpx
import yaml

logger = logging.getLogger("mcp-guard.threatdb")

DB_PATH = Path("threatdb.sqlite")

MALWAREBAZAAR_URL = "https://bazaar.abuse.ch/export/txt/sha256/full/"
STALKERWARE_URL = "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/ioc.yaml"
MVT_INDEX_URL = "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/indicators.yaml"

SOURCE_LABELS = {
    "malwarebazaar": "MalwareBazaar",
    "stalkerware": "Stalkerware-indicators",
    "mvt": "MVT (Amnesty)",
}

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_STIX_VALUE_RE = re.compile(r"=\s*'([^']+)'")


# ------------------------------------------------------------------ загрузка


def _fetch(client: httpx.Client, url: str) -> bytes:
    response = client.get(url, timeout=120, follow_redirects=True)
    response.raise_for_status()
    return response.content


def _load_malwarebazaar(client: httpx.Client) -> list[tuple[str, str, str]]:
    archive = zipfile.ZipFile(io.BytesIO(_fetch(client, MALWAREBAZAAR_URL)))
    text = archive.read(archive.namelist()[0]).decode("ascii", "replace")
    hashes = []
    for line in text.splitlines():
        value = line.strip().lower()
        if _SHA256_RE.match(value):
            hashes.append((value, "malwarebazaar", ""))
    return hashes


def _load_stalkerware(client: httpx.Client) -> list[tuple[str, str, str]]:
    entries = yaml.safe_load(_fetch(client, STALKERWARE_URL)) or []
    packages = []
    for entry in entries:
        family = entry.get("name", "")
        for name in entry.get("packages") or []:
            packages.append((str(name).strip(), "stalkerware", family))
    return packages


def _load_mvt(client: httpx.Client) -> tuple[list, list]:
    index = yaml.safe_load(_fetch(client, MVT_INDEX_URL)) or {}
    packages, hashes = [], []
    for item in index.get("indicators", []):
        gh = item.get("github") or {}
        if not gh:
            continue
        url = (
            f"https://raw.githubusercontent.com/{gh['owner']}/{gh['repo']}/"
            f"{gh['branch']}/{gh['path']}"
        )
        family = item.get("name", "")
        try:
            bundle = json.loads(_fetch(client, url))
        except Exception as error:  # noqa: BLE001 — один файл не должен валить обновление
            logger.warning("MVT: не удалось скачать %s: %s", gh.get("path"), error)
            continue
        for obj in bundle.get("objects", []):
            if obj.get("type") != "indicator":
                continue
            pattern = obj.get("pattern", "")
            match = _STIX_VALUE_RE.search(pattern)
            if not match:
                continue
            value = match.group(1).strip()
            if pattern.startswith("[app:id"):
                packages.append((value, "mvt", family))
            elif pattern.startswith("[file:hashes.sha256") and _SHA256_RE.match(value.lower()):
                hashes.append((value.lower(), "mvt", family))
    return packages, hashes


def update() -> dict:
    """Скачивает все три базы и атомарно подменяет threatdb.sqlite."""
    tmp_path = DB_PATH.with_suffix(".tmp")
    tmp_path.unlink(missing_ok=True)
    counts = {}

    with httpx.Client(headers={"User-Agent": "mcp-guard-threatdb/1.0"}) as client:
        hashes, packages = [], []
        loaders = {
            "malwarebazaar": lambda: (_load_malwarebazaar(client), []),
            "stalkerware": lambda: ([], _load_stalkerware(client)),
            "mvt": lambda: tuple(reversed(_load_mvt(client))),
        }
        for source, load in loaders.items():
            try:
                source_hashes, source_packages = load()
            except Exception as error:  # noqa: BLE001
                logger.error("База %s не обновлена: %s", source, error)
                continue
            hashes += source_hashes
            packages += source_packages
            counts[source] = len(source_hashes) + len(source_packages)

    if not counts:
        raise RuntimeError("ни одна база не скачалась — старая база оставлена")

    conn = sqlite3.connect(tmp_path)
    conn.executescript(
        """
        CREATE TABLE hashes (sha256 TEXT PRIMARY KEY, source TEXT, family TEXT) WITHOUT ROWID;
        CREATE TABLE packages (name TEXT PRIMARY KEY, source TEXT, family TEXT) WITHOUT ROWID;
        CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
        """
    )
    # MVT и stalkerware пересекаются — первая запись выигрывает.
    conn.executemany("INSERT OR IGNORE INTO hashes VALUES (?, ?, ?)", hashes)
    conn.executemany("INSERT OR IGNORE INTO packages VALUES (?, ?, ?)", packages)
    conn.execute("INSERT INTO meta VALUES ('counts', ?)", (json.dumps(counts),))
    conn.execute("INSERT INTO meta VALUES ('updated', datetime('now'))")
    conn.commit()
    conn.close()
    os.replace(tmp_path, DB_PATH)
    logger.info("Базы угроз обновлены: %s", counts)
    return counts


# ------------------------------------------------------------------ поиск


def info() -> dict | None:
    if not DB_PATH.exists():
        return None
    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
    try:
        meta = dict(conn.execute("SELECT key, value FROM meta").fetchall())
    finally:
        conn.close()
    return {"updated": meta.get("updated"), "counts": json.loads(meta.get("counts", "{}"))}


def lookup(rows: list[dict]) -> dict[str, dict]:
    """rows: [{package, apk_sha256}] -> {package: {kind, source, family}}.

    kind = "hash" (точная детекция) или "package" (совпало имя пакета).
    Совпадение по хешу важнее, если есть оба.
    """
    if not DB_PATH.exists():
        logger.info("Базы угроз ещё не скачаны — сверка пропущена")
        return {}

    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
    results: dict[str, dict] = {}
    try:
        for row in rows:
            sha = (row.get("apk_sha256") or "").lower()
            hit = None
            if sha:
                found = conn.execute(
                    "SELECT source, family FROM hashes WHERE sha256 = ? LIMIT 1", (sha,)
                ).fetchone()
                if found:
                    hit = {"kind": "hash", "source": found[0], "family": found[1]}
            if hit is None:
                found = conn.execute(
                    "SELECT source, family FROM packages WHERE name = ? LIMIT 1", (row["package"],)
                ).fetchone()
                if found:
                    hit = {"kind": "package", "source": found[0], "family": found[1]}
            if hit:
                results[row["package"]] = hit
    finally:
        conn.close()

    if results:
        logger.warning("Совпадения с базами угроз: %s", {k: v["source"] for k, v in results.items()})
    return results


def describe(hit: dict | None) -> str:
    """Короткая строка для отчёта."""
    if not hit:
        return ""
    source = SOURCE_LABELS.get(hit["source"], hit["source"])
    what = "хеш APK" if hit["kind"] == "hash" else "имя пакета"
    family = f": {hit['family']}" if hit.get("family") else ""
    return f"{source} ({what}){family}"


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if len(sys.argv) > 1 and sys.argv[1] == "update":
        print(json.dumps(update(), ensure_ascii=False))
    else:
        print(json.dumps(info(), ensure_ascii=False))
