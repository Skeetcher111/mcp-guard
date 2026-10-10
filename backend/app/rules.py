"""Оценка приложений без ИИ: локальные правила + карточка Google Play (фаза 15).

Для публичной версии: ИИ по подписке владельца раздавать нельзя, поэтому
сервер сам считает score 0-100 и понятную человеку причину по фактам:
разрешения, откуда установлено, карточка в Play (есть ли, сколько скачиваний,
реклама, детская ли), подделка известного детского бренда и «конвейерный»
издатель (много однотипных приложений одного разработчика на телефоне).

Результат совместим с ИИ-оценкой ({score, reason}) плюс kind:
- scam  — скам/мусорная игра, предлагаем удалить (не вирус);
- ""    — обычная оценка риска.
"""

from __future__ import annotations

import re
from collections import Counter

STORES = {
    "com.android.vending", "ru.vk.store", "com.huawei.appmarket", "com.xiaomi.market",
    "com.xiaomi.mipicks", "com.sec.android.app.samsungapps", "com.heytap.market",
    "com.oppo.market", "com.bbk.appstore", "com.amazon.venezia",
}

# Детские бренды, которые массово клонируют. Значение — префиксы настоящих пакетов.
BRANDS = {
    r"toca": ("com.tocaboca.",),
    r"roblox|obby": ("com.roblox.",),
    r"minecraft|mcpe|craft": ("com.mojang.",),
    r"sprunki|incredibox": ("com.sozbit.",),
    r"skibidi|brainrot|tralalero": (),
    r"prank": (),
    r"poppy|huggy|playtime": ("com.mobentertainment.",),
    r"banban": ("com.euphoricbrothers.",),
    r"fnaf|freddy": ("com.scottgames.", "com.clickteam."),
    r"among.?us|impostor": ("com.innersloth.",),
    r"talking.?tom|angela": ("com.outfit7.",),
    r"subway.?surf": ("com.kiloo.",),
    r"brawl|clash": ("com.supercell.",),
    r"stumble": ("com.kitkagames.",),
}
_BRAND_RES = [(re.compile(pat, re.I), official) for pat, official in BRANDS.items()]

# Крупные компании: много приложений одного издателя на телефоне — это нормально.
BIG_PUBLISHERS = re.compile(
    r"^(com\.google|com\.android|com\.yandex|ru\.yandex|com\.vkontakte|com\.vk|ru\.vk|ru\.mail|"
    r"ru\.sberbank|ru\.sberbankmobile|ru\.tinkoff|com\.idamob|com\.samsung|com\.sec|com\.miui|"
    r"com\.xiaomi|com\.huawei|com\.microsoft|com\.facebook|org\.telegram|ru\.ozon|com\.avito|"
    r"ru\.mts|ru\.megafon|ru\.beeline|com\.wildberries|ru\.rostel|ru\.gosuslugi)"
)

SMS = {"android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.SEND_SMS"}
SPY = {"android.permission.READ_CALL_LOG", "android.permission.READ_CONTACTS",
       "android.permission.RECORD_AUDIO", "android.permission.ACCESS_FINE_LOCATION"}
MESSENGER = re.compile(r"sms|messag|messeng|telegram|whatsapp|viber|dialer|phone|contacts|bank|sber|tinkoff", re.I)

CLUSTER_MIN = 4


def _publisher(row: dict) -> str:
    play = row.get("play") or {}
    if play.get("developer"):
        return play["developer"]
    parts = row["package"].split(".")
    return ".".join(parts[:2])


def _kids_game(play: dict) -> bool:
    return play.get("category", "").startswith("GAME") or play.get("age", "") in ("0+", "3+", "6+")


def score_package(row: dict, publishers: Counter) -> dict:
    pkg = row["package"]
    perms = set(row.get("permissions") or [])
    play = row.get("play")
    installer = row.get("installer") or ""
    from_store = installer in STORES
    score, reasons, scam = 5, [], 0

    # Популярное или известная компания (Сбер и банки убраны из Play — их узнаём по имени).
    big = bool(BIG_PUBLISHERS.match(pkg)) or bool(
        play and play.get("found") and play.get("installs", 0) >= 10_000_000)

    # --- подделка детского бренда
    name = f"{pkg} {(play or {}).get('title', '')}"
    for brand_re, official in _BRAND_RES:
        m = brand_re.search(name)
        if m and not pkg.startswith(official or ("\0",)):
            scam += 35
            reasons.append(f"похоже на подделку «{m.group(0)}» от стороннего разработчика")
            break

    # --- конвейерный издатель
    pub = _publisher(row)
    if publishers[pub] >= CLUSTER_MIN and not BIG_PUBLISHERS.match(pkg):
        scam += 25
        reasons.append(f"{publishers[pub]} однотипных приложений одного разработчика ({pub})")

    # --- карточка Google Play
    if play is not None:
        if not play.get("found"):
            if not from_store:
                score += 20
                reasons.append("нет в Google Play и установлено не из магазина")
            else:
                scam += 10
                reasons.append("карточки в Google Play больше нет")
        elif not big:
            installs = play.get("installs", 0)
            if installs < 50_000 and play.get("ads") and _kids_game(play):
                scam += 25
                reasons.append(f"малоизвестная детская игра с рекламой ({installs:,} скачиваний)".replace(",", " "))
    elif not from_store:
        score += 10
        reasons.append("установлено не из магазина приложений")

    # --- разрешения, не нужные для назначения
    if perms & SMS and not MESSENGER.search(name) and not big:
        score += 30
        reasons.append("читает или отправляет СМС")
    spy = perms & SPY
    if len(spy) >= 3 and not from_store and not big:
        score += 20
        reasons.append("просит звонки, контакты, микрофон или геолокацию")
    if {"android.permission.SYSTEM_ALERT_WINDOW", "android.permission.REQUEST_INSTALL_PACKAGES"} <= perms and not big:
        score += 15
        reasons.append("может рисовать поверх окон и ставить другие приложения")

    if scam >= 35:
        score = max(score, min(90, 30 + scam))
    if big and not row.get("control"):
        score = min(score, 15)
    score = max(0, min(100, score))

    if big and not row.get("control"):
        reasons = [r for r in reasons if "Google Play" not in r and "магазина" not in r]
    if not reasons:
        reasons.append(
            "популярное приложение из магазина" if big and from_store
            else "приложение известной компании" if big
            else "установлено из магазина, явных признаков угрозы нет" if from_store
            else "явных признаков угрозы нет")
    reason = "; ".join(reasons)
    return {"score": score, "reason": reason[:1].upper() + reason[1:] + ".",
            "kind": "scam" if scam >= 35 else ""}


def analyze(rows: list[dict]) -> dict[str, dict]:
    """rows: [{package, installer, permissions, control, play}] -> {package: {score, reason, kind}}."""
    publishers = Counter(_publisher(r) for r in rows)
    return {r["package"]: score_package(r, publishers) for r in rows}


if __name__ == "__main__":
    fake = [{"package": f"com.fusionmind.game{i}", "installer": "com.android.vending", "permissions": [],
             "play": {"found": True, "developer": "FusionMind", "installs": 5000, "ads": True,
                      "category": "GAME_CASUAL", "age": "3+", "title": "Game"}} for i in range(4)]
    fake.append({"package": "com.fusionmind.tocaworld", "installer": "com.android.vending", "permissions": [],
                 "play": {"found": True, "developer": "FusionMind", "installs": 1000, "ads": True,
                          "category": "GAME_PUZZLE", "age": "3+", "title": "Toca World"}})
    fake.append({"package": "com.vkontakte.android", "installer": "com.android.vending", "permissions": list(SMS),
                 "play": {"found": True, "developer": "VK", "installs": 100_000_000, "title": "ВКонтакте"}})
    fake.append({"package": "com.flash.light", "installer": "com.google.android.packageinstaller",
                 "permissions": list(SMS | SPY), "play": {"found": False}})
    out = analyze(fake)
    assert out["com.fusionmind.tocaworld"]["kind"] == "scam" and out["com.fusionmind.tocaworld"]["score"] >= 80
    assert out["com.fusionmind.game0"]["kind"] == "scam"
    assert out["com.vkontakte.android"]["score"] <= 15
    assert out["com.flash.light"]["score"] >= 50, out["com.flash.light"]
    sber = analyze([{"package": "ru.sberbankmobile", "installer": "", "permissions": list(SMS), "play": {"found": False}}])
    assert sber["ru.sberbankmobile"]["reason"] == "Приложение известной компании.", sber
    for k, v in out.items():
        print(k, v)
