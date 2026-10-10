"""Настройки backend-сервиса MCP Guard.

Значения читаются из окружения или из `.env` рядом с рабочим каталогом
сервиса (на VPS — `/opt/mcp-guard-api/.env`). Секреты в git не попадают:
в репозитории лежит только `.env.example`.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Собственная БД сервиса.
    database_url: str = "sqlite:///./mcpguard.db"

    # Единственный статический токен (личное использование, один владелец).
    # Клиент шлёт его как `Authorization: Bearer <token>`.
    # Значение задаётся в .env (API_TOKEN).
    api_token: str = ""

    # Фаза 16: ИИ-анализа на сервере нет. Старые ключи ANTHROPIC_*/CLAUDE_* в .env
    # игнорируются (extra="ignore" в model_config).



settings = Settings()
