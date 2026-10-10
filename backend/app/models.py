from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Scan(Base):
    """Один скан одного телефона."""

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    device_model: Mapped[str] = mapped_column(String(200), default="")
    android_version: Mapped[str] = mapped_column(String(50), default="")
    device_serial: Mapped[str] = mapped_column(String(200), default="")
    package_count: Mapped[int] = mapped_column(Integer, default=0)
    # pending | analyzed | stub
    status: Mapped[str] = mapped_column(String(32), default="pending")
    # Чей скан: "owner" или токен установки (чужие сканы не отдаём).
    client: Mapped[str] = mapped_column(String(64), default="")

    packages: Mapped[list["ScannedPackage"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class ScannedPackage(Base):
    """Одно приложение внутри скана + результаты анализа."""

    __tablename__ = "scanned_packages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)

    package_name: Mapped[str] = mapped_column(String(300), index=True)
    label: Mapped[str] = mapped_column(String(300), default="")
    installer: Mapped[str] = mapped_column(String(200), default="")
    permissions: Mapped[str] = mapped_column(Text, default="")  # JSON-массив
    permission_count: Mapped[int] = mapped_column(Integer, default=0)
    apk_sha256: Mapped[str] = mapped_column(String(64), default="")

    # Фаза 5 — эвристика Anthropic.
    ai_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    ai_reason: Mapped[str] = mapped_column(Text, default="")

    # Фаза 6 — VirusTotal по хешу APK. Больше не используется (убран по
    # решению владельца 2026-09-23); колонки оставлены ради старых сканов.
    vt_malicious: Mapped[int | None] = mapped_column(Integer, nullable=True)
    vt_suspicious: Mapped[int | None] = mapped_column(Integer, nullable=True)
    vt_total: Mapped[int | None] = mapped_column(Integer, nullable=True)
    vt_status: Mapped[str] = mapped_column(String(32), default="skipped")

    # Фаза 11 — офлайн-базы угроз (MalwareBazaar, stalkerware, MVT).
    db_match: Mapped[str] = mapped_column(Text, default="")

    # Фаза 12 — признаки управления телефоном (JSON-список кодов + текст).
    control_flags: Mapped[str] = mapped_column(Text, default="")
    control_text: Mapped[str] = mapped_column(Text, default="")

    # Фаза 15 — название из Google Play и тип находки правил (scam = мусорная/скам-игра).
    title: Mapped[str] = mapped_column(String(300), default="")
    kind: Mapped[str] = mapped_column(String(16), default="")

    # Итог: low | medium | high | critical | unknown
    risk: Mapped[str] = mapped_column(String(16), default="unknown")
    verdict_source: Mapped[str] = mapped_column(String(32), default="none")

    scan: Mapped["Scan"] = relationship(back_populates="packages")


class Install(Base):
    """Установка публичной программы: случайный токен вместо вшитого (фаза 15)."""

    __tablename__ = "installs"

    token: Mapped[str] = mapped_column(String(64), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    ip: Mapped[str] = mapped_column(String(64), default="")
