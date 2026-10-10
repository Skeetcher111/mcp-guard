"""Сведение сигналов в итоговый уровень риска.

Три источника, и они неравноценны (CLAUDE.md, раздел 3):

- Офлайн-базы угроз (фаза 11) — реальная детекция: хеш APK или имя пакета
  найдены в MalwareBazaar / stalkerware-indicators / MVT. Перебивает ИИ.
- Поведение на телефоне (фаза 12) — факты с устройства: администратор,
  спецвозможности, установка других приложений, скрытый значок.
- ИИ-эвристика — догадка по имени пакета, источнику установки, разрешениям
  и поведению. Полезна там, где сигнатур нет, но вердиктом не является.

Итог — худший из сигналов. «Нет в базе» НЕ снижает ИИ-оценку: отсутствие
в базе значит лишь «сигнатура неизвестна» — ровно тот случай, ради
которого эвристика и нужна.
"""

AI_THRESHOLDS = ((80, "critical"), (50, "high"), (25, "medium"), (0, "low"))

RISK_ORDER = {"unknown": -1, "low": 0, "medium": 1, "high": 2, "critical": 3}

# Вес признаков «захвата телефона». Админ, спецвозможности и установка
# чужих приложений — прямые рычаги управления; скрытый значок и оверлей
# сами по себе бывают у нормальных приложений (клавиатуры, плагины),
# поэтому весят меньше.
CONTROL_WEIGHTS = {
    "device_admin": 3,
    "accessibility": 3,
    "installs_apps": 3,
    "can_install": 1,
    "overlay": 1,
    "hidden_icon": 1,
    "notification_listener": 1,
    "home_launcher": 1,
}


def risk_from_ai_score(score: int | None) -> str:
    if score is None:
        return "unknown"
    for threshold, level in AI_THRESHOLDS:
        if score >= threshold:
            return level
    return "low"


def risk_from_control(flags: list[str] | None) -> str:
    score = sum(CONTROL_WEIGHTS.get(flag, 0) for flag in flags or [])
    if score >= 6:
        return "critical"
    if score >= 3:
        return "high"
    if score >= 2:
        return "medium"
    return "unknown"


def combine(
    ai_score: int | None,
    db_hit: dict | None = None,
    control_flags: list[str] | None = None,
) -> tuple[str, str]:
    """-> (risk, verdict_source).

    verdict_source говорит, какой сигнал определил итог: database, behavior,
    ai, both (сработали база и ИИ) или none.
    """
    risk = risk_from_ai_score(ai_score)
    source = "ai" if risk != "unknown" else "none"

    if db_hit:
        # Совпадение хеша — точная детекция, имени пакета — сильный сигнал.
        db_risk = "critical" if db_hit.get("kind") == "hash" else "high"
        if RISK_ORDER[db_risk] >= RISK_ORDER[risk]:
            risk, source = db_risk, "database"
        else:
            source = "both"

    control_risk = risk_from_control(control_flags)
    if control_risk != "unknown" and RISK_ORDER[control_risk] > RISK_ORDER[risk]:
        risk, source = control_risk, "behavior"

    return risk, source
