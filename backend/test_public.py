"""Проверка сервера (фазы 15–16): регистрация, свой токен, правила без ИИ, /play,
чужой скан не виден, лимит. Запуск: .venv/Scripts/python test_public.py (БД — временная)."""

import os
import tempfile

os.chdir(tempfile.mkdtemp())
os.environ.update(DATABASE_URL="sqlite:///./t.db", API_TOKEN="owner-secret", CLAUDE_CODE_OAUTH_TOKEN="")

from fastapi.testclient import TestClient  # noqa: E402

from app import main, play  # noqa: E402

play.lookup = lambda pkgs: {
    "com.fusionmind.tocaworld": {"found": True, "title": "Toca World", "developer": "X", "installs": 1000,
                                 "ads": True, "category": "GAME_PUZZLE", "age": "3+"},
    "com.vkontakte.android": {"found": True, "title": "ВКонтакте", "developer": "VK", "installs": 10**8},
}
c = TestClient(main.app)
assert c.get("/health").json()["ai_analysis"] == "none"
assert c.post("/scan/start", json={}).status_code == 401
tok = c.post("/register").json()["api_token"]
h = {"Authorization": f"Bearer {tok}"}
sid = c.post("/scan/start", json={"model": "Pixel"}, headers=h).json()["scan_id"]
pk = [{"package": "com.fusionmind.tocaworld", "installer": "com.android.vending"},
      {"package": "com.vkontakte.android", "installer": "com.android.vending",
       "permissions": ["android.permission.READ_SMS"]},
      {"package": "com.flash.light", "installer": "", "control_flags": ["device_admin", "accessibility"],
       "control_text": "администратор"}]
assert c.post(f"/scan/{sid}/packages", json={"packages": pk}, headers=h).status_code == 200
rep = c.post(f"/scan/{sid}/finish", headers=h).json()
cat = {p["package"]: (p["category"], p["title"], p["ai_score"]) for p in rep["packages"]}
print(cat)
assert cat["com.fusionmind.tocaworld"][0] == "junk" and cat["com.fusionmind.tocaworld"][1] == "Toca World"
assert cat["com.vkontakte.android"][0] == "ok"
assert cat["com.flash.light"][0] == "danger"

cards = c.post("/play", json={"packages": ["com.vkontakte.android", "com.nope.app"]}, headers=h).json()["cards"]
assert cards["com.vkontakte.android"]["title"] == "ВКонтакте" and "com.nope.app" not in cards
assert c.post("/play", json={"packages": ["x"]}).status_code == 401

other = {"Authorization": "Bearer " + c.post("/register").json()["api_token"]}
assert c.get(f"/scan/{sid}", headers=other).status_code == 404
assert c.get(f"/scan/{sid}", headers={"Authorization": "Bearer owner-secret"}).status_code == 200
codes = [c.post("/scan/start", json={}, headers=h).status_code for _ in range(6)]
assert codes[-1] == 429, codes
print("OK")
