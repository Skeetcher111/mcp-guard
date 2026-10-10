"""Подключение нового ПК по одноразовому 6-значному коду.

Владелец (через SSH) создаёт код: `venv/bin/python -m app.pairing` — код
печатается один раз, на диск кладётся только его хеш со сроком жизни
10 минут. Клиент шлёт код на POST /pair и получает API-токен. Код
одноразовый, после 5 неверных попыток сгорает — перебор 10^6 вариантов
за 5 попыток бессмыслен. Так токен не нужно ни вшивать в публичный
установщик, ни вбивать руками.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from pathlib import Path

PAIRING_FILE = Path("pairing.json")
TTL_SECONDS = 600
MAX_ATTEMPTS = 5


def _hash(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


def create_code() -> str:
    code = f"{secrets.randbelow(10**6):06d}"
    PAIRING_FILE.write_text(
        json.dumps({"hash": _hash(code), "expires": time.time() + TTL_SECONDS, "attempts": 0})
    )
    PAIRING_FILE.chmod(0o600)
    return code


def redeem(code: str) -> bool:
    """True, если код верный. Любой исход кроме неверной попытки сжигает код."""
    try:
        state = json.loads(PAIRING_FILE.read_text())
    except (OSError, ValueError):
        return False
    if time.time() > state.get("expires", 0):
        PAIRING_FILE.unlink(missing_ok=True)
        return False
    if hmac.compare_digest(_hash(code.strip()), state.get("hash", "")):
        PAIRING_FILE.unlink(missing_ok=True)
        return True
    state["attempts"] = state.get("attempts", 0) + 1
    if state["attempts"] >= MAX_ATTEMPTS:
        PAIRING_FILE.unlink(missing_ok=True)
    else:
        PAIRING_FILE.write_text(json.dumps(state))
    return False


if __name__ == "__main__":
    print(create_code())
