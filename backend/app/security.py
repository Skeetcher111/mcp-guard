"""Авторизация: bearer-токен владельца или токен установки.

Токен владельца приходит в сервис через `API_TOKEN` (.env) — с ним работает ИИ-оценка. Публичная программа
при первом запуске получает свой случайный токен через POST /register
(таблица installs) — с ним оценка только правилами (фаза 15).
"""

import hmac

from fastapi import Header, HTTPException, status

from app.config import settings
from app.database import SessionLocal
from app.models import Install


def require_token(authorization: str = Header(default="")) -> str:
    """-> "owner" или токен установки."""
    scheme, _, value = authorization.partition(" ")
    if scheme.lower() != "bearer" or not value:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Нужен заголовок Authorization: Bearer <token>",
            headers={"WWW-Authenticate": "Bearer"},
        )

    value = value.strip()
    if settings.api_token and hmac.compare_digest(value, settings.api_token):
        return "owner"
    with SessionLocal() as db:
        if len(value) <= 64 and db.get(Install, value) is not None:
            return value
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Неверный токен",
        headers={"WWW-Authenticate": "Bearer"},
    )
