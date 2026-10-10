"""MCP Guard API — личный backend-сервис анализа Android-приложений.

Отдельный сервис: свой порт, свой каталог, своя SQLite-база.
"""

import json
import logging
import secrets
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor

from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app import pairing, play, rules, threatdb, verdict
from app.config import settings
from app.database import Base, engine, get_db
from app.models import Install, Scan, ScannedPackage
from app.schemas import DeviceIn, HEURISTIC_DISCLAIMER, PackageIn, PackageReport, ScanIn, ScanReport
from app.security import require_token

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [mcp-guard] %(message)s",
)
logger = logging.getLogger("mcp-guard")

Base.metadata.create_all(bind=engine)

# create_all не добавляет колонки в уже существующие таблицы — докидываем
# вручную то, что появилось в поздних фазах.
with engine.begin() as _conn:
    _cols = {row[1] for row in _conn.exec_driver_sql("PRAGMA table_info(scanned_packages)")}
    for _col in ("db_match", "control_flags", "control_text", "title", "kind"):
        if _col not in _cols:
            _conn.exec_driver_sql(f"ALTER TABLE scanned_packages ADD COLUMN {_col} TEXT DEFAULT ''")
    if "client" not in {row[1] for row in _conn.exec_driver_sql("PRAGMA table_info(scans)")}:
        _conn.exec_driver_sql("ALTER TABLE scans ADD COLUMN client TEXT DEFAULT ''")

app = FastAPI(title="MCP Guard API", version="0.17.0")


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "service": "mcp-guard-api",
        "version": app.version,
        # Для публичных установок — правила + Google Play (фаза 15); ИИ
        # по подписке владельца только с его токеном.
        "ai_analysis": "none",
        "analysis": "server-rules",
        "threat_db": threatdb.info(),
    }


class PairIn(BaseModel):
    code: str


@app.post("/pair")
def pair(payload: PairIn) -> dict:
    """Одноразовый код подключения нового ПК → API-токен (см. app/pairing.py)."""
    if not settings.api_token or not pairing.redeem(payload.code):
        raise HTTPException(status_code=403, detail="Код неверный или устарел")
    return {"api_token": settings.api_token}


# Регистраций с одного IP в сутки — чтобы токены не штамповали ради обхода лимита.
REGISTER_PER_IP_DAY = 20
_registers: dict[str, deque] = {}


@app.post("/register")
def register(request: Request, db: Session = Depends(get_db)) -> dict:
    """Публичная программа при первом запуске получает свой токен."""
    ip = request.headers.get("x-real-ip") or (request.client.host if request.client else "")
    _hit(_registers.setdefault(ip, deque()), REGISTER_PER_IP_DAY, 86400, "Слишком много регистраций")
    token = secrets.token_urlsafe(32)
    db.add(Install(token=token, ip=ip))
    db.commit()
    return {"api_token": token}


@app.get("/auth/check", dependencies=[Depends(require_token)])
def auth_check() -> dict:
    """Клиент дёргает это из «Настроек», чтобы проверить адрес + токен."""
    return {"status": "ok", "authorized": True}


def _store_scan(db: Session, payload: ScanIn, client: str) -> Scan:
    scan = Scan(
        client=client,
        device_model=payload.device.model,
        android_version=payload.device.android_version,
        device_serial=payload.device.serial,
        package_count=len(payload.packages),
        status="stored",
    )
    db.add(scan)
    db.flush()

    for item in payload.packages:
        db.add(
            ScannedPackage(
                scan_id=scan.id,
                package_name=item.package_name,
                label=item.label or "",
                installer=item.installer or "",
                permissions=json.dumps(item.permissions, ensure_ascii=False),
                permission_count=len(item.permissions),
                apk_sha256=(item.apk_sha256 or ""),
                ai_score=item.ai_score,
                ai_reason=item.ai_reason,
                control_flags=json.dumps(item.control_flags),
                control_text=item.control_text,
            )
        )

    db.commit()
    db.refresh(scan)
    return scan


def _analysis_mode(scan: Scan) -> str:
    """Какие сигналы реально отработали на этом скане.

    Важно отражать факт, а не настройки: ключ может быть задан, но запрос
    провалиться (например, на балансе Anthropic нет средств) — тогда в
    отчёте не должно быть написано, что ИИ-анализ выполнялся.
    """
    modes = []
    if any(row.ai_score is not None for row in scan.packages):
        modes.append("rules")
    if threatdb.info() is not None:
        modes.append("threat-db")
    return "+".join(modes) if modes else "stub"


def _run_analysis(db: Session, scan: Scan, owner: bool = False) -> None:
    """Прогоняет сохранённый скан через доступные сигналы и пишет вердикты."""
    rows = [
        {
            "package": row.package_name,
            "installer": row.installer,
            "permissions": json.loads(row.permissions or "[]"),
            "apk_sha256": row.apk_sha256,
            "control": row.control_text or "",
        }
        for row in scan.packages
    ]

    # Фаза 16: ИИ на сервере нет. Оценка — правила + карточка Google Play + базы угроз;
    # клиент 1.4+ считает то же самое у себя и ходит сюда только за карточками (/play).
    ai_results: dict[str, dict] = {}
    db_results = threatdb.lookup(rows)

    cards = play.lookup([r["package"] for r in rows])
    for r in rows:
        r["play"] = cards.get(r["package"])
    rule_results = rules.analyze(rows)

    for row in scan.packages:
        ai = ai_results.get(row.package_name) or (
            None if row.ai_score is not None else rule_results.get(row.package_name)
        )
        if ai is not None:
            row.ai_score = ai["score"]
            row.ai_reason = ai["reason"]
        row.kind = (rule_results.get(row.package_name) or {}).get("kind", "")
        row.title = (cards.get(row.package_name) or {}).get("title", "")

        db_hit = db_results.get(row.package_name)
        row.db_match = threatdb.describe(db_hit)

        flags = json.loads(row.control_flags or "[]")
        row.risk, row.verdict_source = verdict.combine(row.ai_score, db_hit, flags)

    scan.status = "analyzed"
    db.commit()
    db.refresh(scan)


def _category(row: ScannedPackage) -> str:
    if row.db_match or row.verdict_source == "behavior" or (row.risk in ("high", "critical") and row.kind != "scam"):
        return "danger"
    if row.kind == "scam":
        return "junk"
    return "check" if row.risk == "medium" else "ok"


def _to_report(scan: Scan) -> ScanReport:
    packages = [
        PackageReport(
            package=row.package_name,
            label=row.label,
            installer=row.installer,
            permission_count=row.permission_count,
            permissions=json.loads(row.permissions or "[]"),
            apk_sha256=row.apk_sha256,
            ai_score=row.ai_score,
            ai_reason=row.ai_reason,
            db_match=row.db_match or "",
            control_text=row.control_text or "",
            risk=row.risk,
            verdict_source=row.verdict_source,
            title=row.title or "",
            kind=row.kind or "",
            category=_category(row),
        )
        for row in scan.packages
    ]
    return ScanReport(
        scan_id=scan.id,
        created_at=scan.created_at,
        status=scan.status,
        analysis=_analysis_mode(scan),
        disclaimer=HEURISTIC_DISCLAIMER,
        package_count=scan.package_count,
        packages=packages,
    )


# Частота сканов: на установку, у владельца (тратит подписку) и общий потолок.
SCANS_PER_HOUR = {"owner": 40, "install": 6}
SCANS_PER_HOUR_TOTAL = 300
_recent_scans: dict[str, deque] = {}
_all_scans: deque = deque()


def _hit(log: deque, limit: int, window: int, detail: str) -> None:
    now = time.time()
    while log and now - log[0] > window:
        log.popleft()
    if len(log) >= limit:
        raise HTTPException(status_code=429, detail=f"{detail}, попробуйте позже")
    log.append(now)


def _check_rate_limit(client: str) -> None:
    # ponytail: лимиты в памяти процесса, обнуляются при рестарте; хватит на один uvicorn.
    limit = SCANS_PER_HOUR["owner" if client == "owner" else "install"]
    _hit(_recent_scans.setdefault(client, deque()), limit, 3600, "Слишком много проверок за час")
    _hit(_all_scans, SCANS_PER_HOUR_TOTAL, 3600, "Сервер перегружен")


def _own_scan(db: Session, scan_id: int, client: str) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None or (client != "owner" and scan.client != client):
        raise HTTPException(status_code=404, detail="Скан не найден")
    return scan


@app.post("/scan", response_model=ScanReport)
def create_scan(payload: ScanIn, db: Session = Depends(get_db), client: str = Depends(require_token)) -> ScanReport:
    """Принимает выгрузку с телефона, сохраняет её, анализирует и отдаёт отчёт.

    ИИ-оценка — эвристика, а не антивирусный вердикт: об этом говорит поле
    `disclaimer` в каждом ответе (CLAUDE.md, раздел 3).
    """
    _check_rate_limit(client)
    scan = _store_scan(db, payload, client)
    logger.info(
        "scan %s stored: %s packages from %s (Android %s)",
        scan.id,
        scan.package_count,
        scan.device_model or "?",
        scan.android_version or "?",
    )
    _run_analysis(db, scan, owner=client == "owner")
    return _to_report(scan)


@app.get("/scan/{scan_id}", response_model=ScanReport)
def get_scan(scan_id: int, db: Session = Depends(get_db), client: str = Depends(require_token)) -> ScanReport:
    return _to_report(_own_scan(db, scan_id, client))


# ---------------------------------------------------------------- карточки Google Play
#
# Фаза 16: клиент оценивает приложения сам, сервер отдаёт только карточки магазина
# (название, издатель, скачивания, реклама) из кэша play.py. Пустой ответ — не ошибка.

PLAY_MAX = 400


class PlayIn(BaseModel):
    packages: list[str]


@app.post("/play")
def play_cards(payload: PlayIn, client: str = Depends(require_token)) -> dict:
    _check_rate_limit(client)
    names = [p for p in payload.packages if isinstance(p, str) and 0 < len(p) <= 200][:PLAY_MAX]
    try:
        cards = play.lookup(names)
    except Exception as error:  # noqa: BLE001 — магазин недоступен, клиент посчитает без карточек
        logger.warning("/play: %s", error)
        cards = {}
    return {"cards": cards}


# ---------------------------------------------------------------- потоковый скан
#
# Клиент шлёт приложения по мере чтения телефона: /scan/start → несколько
# /scan/{id}/packages → /scan/{id}/finish. Оставлен для клиентов 1.3.x:
# пачки лишь прогреваются карточками Google Play, оценка идёт в /finish.

BATCH_SIZE = 25
_STREAM_TTL = 3600
_streams: dict[int, dict] = {}
_streams_lock = threading.Lock()


class PackagesIn(BaseModel):
    packages: list[PackageIn]


def _stream(scan_id: int, client: str) -> dict:
    with _streams_lock:
        stream = _streams.get(scan_id)
    if stream is None or stream["client"] != client:
        raise HTTPException(status_code=404, detail="Потоковый скан не найден или устарел")
    return stream


def _submit_batch(stream: dict, batch: list[dict]) -> None:
    if batch:
        record = {"size": len(batch), "started": None, "finished": None}

        def run(rows=batch, record=record):
            record["started"] = time.time()
            try:
                play.lookup([r["package"] for r in rows])  # прогрев кэша карточек
                return {}
            finally:
                record["finished"] = time.time()

        future = stream["executor"].submit(run)
        record["future"] = future
        stream["futures"].append(future)
        stream["batches"].append(record)


@app.post("/scan/start")
def scan_start(device: DeviceIn, db: Session = Depends(get_db), client: str = Depends(require_token)) -> dict:
    _check_rate_limit(client)
    now = time.time()
    with _streams_lock:
        for stale_id in [k for k, v in _streams.items() if now - v["created"] > _STREAM_TTL]:
            _streams.pop(stale_id)["executor"].shutdown(wait=False, cancel_futures=True)

    scan = Scan(
        device_model=device.model,
        android_version=device.android_version,
        device_serial=device.serial,
        package_count=0,
        status="streaming",
        client=client,
    )
    db.add(scan)
    db.commit()
    with _streams_lock:
        _streams[scan.id] = {
            "created": now,
            "client": client,
            "executor": ThreadPoolExecutor(max_workers=1),
            "pending": [],
            "futures": [],
            "batches": [],
            "received": 0,
            "db_hits": 0,
            "lock": threading.Lock(),
        }
    logger.info("scan %s: потоковый приём начат (%s)", scan.id, device.model or "?")
    return {"scan_id": scan.id}


@app.post("/scan/{scan_id}/packages")
def scan_packages(
    scan_id: int, payload: PackagesIn, db: Session = Depends(get_db), client: str = Depends(require_token)
) -> dict:
    stream = _stream(scan_id, client)
    rows = []
    for item in payload.packages:
        db.add(
            ScannedPackage(
                scan_id=scan_id,
                package_name=item.package_name,
                label=item.label or "",
                installer=item.installer or "",
                permissions=json.dumps(item.permissions, ensure_ascii=False),
                permission_count=len(item.permissions),
                apk_sha256=(item.apk_sha256 or ""),
                ai_score=item.ai_score,
                ai_reason=item.ai_reason,
                control_flags=json.dumps(item.control_flags),
                control_text=item.control_text,
            )
        )
        if item.ai_score is None and client == "owner":
            rows.append(
                {
                    "package": item.package_name,
                    "installer": item.installer or "",
                    "permissions": item.permissions,
                    "apk_sha256": item.apk_sha256 or "",
                    "control": item.control_text,
                }
            )
    db.commit()

    hits = threatdb.lookup(
        [{"package": i.package_name, "apk_sha256": i.apk_sha256 or ""} for i in payload.packages]
    )
    with stream["lock"]:
        stream["received"] += len(payload.packages)
        stream["db_hits"] += len(hits)
        stream["pending"].extend(rows)
        while len(stream["pending"]) >= BATCH_SIZE:
            batch = stream["pending"][:BATCH_SIZE]
            stream["pending"] = stream["pending"][BATCH_SIZE:]
            _submit_batch(stream, batch)
    return {"received": len(payload.packages)}


@app.get("/scan/{scan_id}/progress")
def scan_progress(scan_id: int, client: str = Depends(require_token)) -> dict:
    """Сколько приложений уже проверено — для полосы прогресса в программе."""
    stream = _stream(scan_id, client)
    with stream["lock"]:
        batches = []
        for batch in stream["batches"]:
            future = batch["future"]
            state = "done" if future.done() else ("running" if future.running() else "waiting")
            item = {"size": batch["size"], "state": state}
            if batch["started"]:
                item["seconds"] = round((batch["finished"] or time.time()) - batch["started"], 1)
            batches.append(item)
        analyzed = sum(b["size"] for b in batches if b["state"] == "done")
        return {
            "received": stream["received"],
            "pending": len(stream["pending"]),
            "analyzed": analyzed,
            "batches": batches,
            "batch_size": BATCH_SIZE,
            "db_hits": stream["db_hits"],
        }


@app.post("/scan/{scan_id}/finish", response_model=ScanReport)
def scan_finish(scan_id: int, db: Session = Depends(get_db), client: str = Depends(require_token)) -> ScanReport:
    stream = _stream(scan_id, client)
    with stream["lock"]:
        _submit_batch(stream, stream["pending"])
        stream["pending"] = []
    ai_results: dict[str, dict] = {}
    for future in stream["futures"]:
        try:
            ai_results.update(future.result(timeout=900))
        except Exception as error:  # noqa: BLE001 — пачка без оценки не валит отчёт
            logger.warning("scan %s: пачка не прошла: %s", scan_id, error)
    stream["executor"].shutdown(wait=False)
    with _streams_lock:
        _streams.pop(scan_id, None)

    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Скан не найден")
    for row in scan.packages:
        ai = ai_results.get(row.package_name)
        if ai is not None and row.ai_score is None:
            row.ai_score = ai["score"]
            row.ai_reason = ai["reason"]
    scan.package_count = len(scan.packages)
    db.commit()
    db.refresh(scan)

    logger.info("scan %s: приём завершён, %s приложений", scan_id, scan.package_count)
    _run_analysis(db, scan, owner=client == "owner")
    return _to_report(scan)
