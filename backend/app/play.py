"""Карточка приложения в Google Play по имени пакета (фаза 15).

Сервер открывает https://play.google.com/store/apps/details?id=<пакет> и
вынимает название, разработчика, число скачиваний, возраст, «Есть реклама»
и категорию. Нет карточки — тоже сигнал (приложение не из Play или убрано).
Кэш — play_cache.sqlite рядом с сервисом, неделя на запись: телефоны людей повторяются, Play не дёргаем лишний раз.
"""

from __future__ import annotations

import html
import json
import logging
import re
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx

logger = logging.getLogger("mcp-guard.play")

CACHE_PATH = Path("play_cache.sqlite")
TTL = 7 * 86400
_lock = threading.Lock()

_INSTALLS_RE = re.compile(r"\|([\d\s ,.]+\s?(?:тыс\.|млн|млрд)?\+)\|\(количество скачиваний\)")
_UNITS = {"тыс.": 1_000, "млн": 1_000_000, "млрд": 1_000_000_000}


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(CACHE_PATH, timeout=10)
    conn.execute("CREATE TABLE IF NOT EXISTS play_cache (pkg TEXT PRIMARY KEY, ts REAL, data TEXT)")
    return conn


def parse_installs(text: str) -> int:
    """'1 тыс.+' -> 1000, '10 млн+' -> 10_000_000, '500+' -> 500."""
    text = text.replace(" ", " ").replace("+", "").strip()
    mult = 1
    for unit, value in _UNITS.items():
        if text.endswith(unit):
            mult, text = value, text[: -len(unit)]
    digits = re.sub(r"[^\d,.]", "", text).replace(",", ".")
    try:
        return int(float(digits) * mult)
    except ValueError:
        return 0


def parse_page(page: str) -> dict:
    title = re.search(r'og:title" content="(?:Приложения в Google Play – )?([^"]*)"', page)
    dev = re.search(r'"author":\{[^}]*"name":"([^"]*)"', page)
    cat = re.search(r'"applicationCategory":"([^"]*)"', page)
    age = re.search(r'"contentRating":"([^"]*)"', page)
    text = re.sub(r"<script.*?</script>|<style.*?</style>", "", page, flags=re.S)
    text = re.sub(r"\|+", "|", re.sub(r"<[^>]+>", "|", text))
    installs = _INSTALLS_RE.search(text)
    return {
        "found": True,
        "title": html.unescape(title.group(1)) if title else "",
        "developer": html.unescape(dev.group(1)) if dev else "",
        "category": cat.group(1) if cat else "",
        "age": age.group(1) if age else "",
        "ads": "Есть реклама" in text,
        "installs": parse_installs(installs.group(1)) if installs else 0,
    }


def _fetch(client: httpx.Client, pkg: str) -> dict | None:
    try:
        r = client.get(
            "https://play.google.com/store/apps/details",
            # gl=us: в российской выдаче нет ВК и других убранных из Play в РФ.
            params={"id": pkg, "hl": "ru", "gl": "us"},
            timeout=10,
        )
    except httpx.HTTPError as error:
        logger.info("Play %s: %s", pkg, error)
        return None  # сеть — не кэшируем, попробуем в следующий раз
    if r.status_code == 404:
        return {"found": False}
    if r.status_code != 200:
        return None
    return parse_page(r.text)


def lookup(packages: list[str]) -> dict[str, dict]:
    """{пакет: карточка}. Пакеты без ответа Play (сеть) в словарь не попадают."""
    now = time.time()
    result: dict[str, dict] = {}
    with _lock, _db() as conn:
        for pkg in packages:
            row = conn.execute("SELECT ts, data FROM play_cache WHERE pkg=?", (pkg,)).fetchone()
            if row and now - row[0] < TTL:
                result[pkg] = json.loads(row[1])
    missing = [p for p in packages if p not in result]
    if missing:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130 Safari/537.36"}
        with httpx.Client(headers=headers, follow_redirects=True) as client, ThreadPoolExecutor(6) as pool:
            fetched = dict(zip(missing, pool.map(lambda p: _fetch(client, p), missing)))
        with _lock, _db() as conn:
            for pkg, data in fetched.items():
                if data is not None:
                    result[pkg] = data
                    conn.execute("INSERT OR REPLACE INTO play_cache VALUES (?,?,?)", (pkg, now, json.dumps(data)))
    return result


if __name__ == "__main__":
    assert parse_installs("1 тыс.+") == 1000
    assert parse_installs("10 млн+") == 10_000_000
    assert parse_installs("500+") == 500
    import sys
    print(json.dumps(lookup(sys.argv[1:]), ensure_ascii=False, indent=1))
