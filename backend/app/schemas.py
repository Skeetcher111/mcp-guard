from datetime import datetime

from pydantic import BaseModel, Field

# Текст, который обязан присутствовать и в ответе API, и в UI: оценка —
# эвристика, а не вердикт антивирусной базы сигнатур (CLAUDE.md, раздел 3).
HEURISTIC_DISCLAIMER = (
    "Оценка по признакам (разрешения, откуда установлено, карточка в магазине), "
    "а не вердикт антивируса. Совпадение с базой угроз и права управлять "
    "телефоном важнее оценки."
)


class DeviceIn(BaseModel):
    model: str = ""
    android_version: str = ""
    serial: str = ""


class PackageIn(BaseModel):
    # Имя поля в клиенте — `package`; принимаем оба варианта.
    package_name: str = Field(validation_alias="package", serialization_alias="package")
    label: str = ""
    installer: str = ""
    permissions: list[str] = Field(default_factory=list)
    apk_sha256: str | None = Field(default=None, validation_alias="hash")
    # Оценка по правилам (поле называется ai_* ради совместимости с клиентами 1.3.x).
    ai_score: int | None = Field(default=None, ge=0, le=100)
    ai_reason: str = ""
    # Фаза 12: признаки управления телефоном (админ, спецвозможности, ...).
    control_flags: list[str] = Field(default_factory=list)
    control_text: str = ""

    model_config = {"populate_by_name": True}


class ScanIn(BaseModel):
    device: DeviceIn = Field(default_factory=DeviceIn)
    packages: list[PackageIn] = Field(default_factory=list)


class PackageReport(BaseModel):
    package: str
    label: str = ""
    installer: str = ""
    permission_count: int = 0
    permissions: list[str] = Field(default_factory=list)
    apk_sha256: str = ""

    ai_score: int | None = None
    ai_reason: str = ""


    db_match: str = ""
    control_text: str = ""

    risk: str = "unknown"
    verdict_source: str = "none"

    # Фаза 15: название из Google Play, тип находки и группа для экрана:
    # danger — опасное, junk — мусор/скам-игра, check — проверьте сами, ok.
    title: str = ""
    kind: str = ""
    category: str = "ok"


class ScanReport(BaseModel):
    scan_id: int
    created_at: datetime
    status: str
    analysis: str
    disclaimer: str = HEURISTIC_DISCLAIMER
    package_count: int
    packages: list[PackageReport]
