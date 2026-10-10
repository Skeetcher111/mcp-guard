#!/usr/bin/env python3
"""Сборка локальных баз для MCP Guard (оценка приложений без сервера и без ИИ).

Пишет в src/data/:
  uad.json               — пакеты UAD-ng: {"<package>": [<list>, <removal>]}
  trackers.json          — трекеры Exodus: [{"name", "cat": [...], "sig": [...]}]
  malware-packages.json  — {"packages": {pkg: семейство}, "hashes": {sha256: семейство},
                            "watchware": {pkg: семейство}}
  apk-hashes.bin         — отсортированные SHA-256 вредоносных APK (по 32 байта подряд)
  data-meta.json         — дата, источники, счётчики, лицензии, ошибки

Только stdlib. Каждый источник собирается независимо: упал один — остальные
пишутся, по упавшему печатается предупреждение, старый файл остаётся.

Переменные окружения (необязательно):
  MB_ZIP      — путь к уже скачанному zip MalwareBazaar (не качать 200+ МБ заново)
  MB_AUTH_KEY — Auth-Key abuse.ch для запасного пути через API
"""
import csv
import io
import json
import os
import re
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "src", "data")
UA = "mcp-guard-build-data/1.0 (+https://github.com/Skeetcher111)"

SRC = {
    "uad": "https://raw.githubusercontent.com/Universal-Debloater-Alliance/"
           "universal-android-debloater-next-generation/main/resources/assets/uad_lists.json",
    "exodus": "https://reports.exodus-privacy.eu.org/api/trackers",
    "stalkerware_ioc": "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/ioc.yaml",
    "stalkerware_watchware": "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/watchware.yaml",
    "stalkerware_samples": "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/samples.csv",
    "mvt": "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/indicators.yaml",
    "malwarebazaar": "https://bazaar.abuse.ch/export/csv/full/",
    "malwarebazaar_api": "https://mb-api.abuse.ch/api/v1/",
}

# Лицензии — как они написаны в источниках (проверено 2026-10-09).
LICENSES = {
    "uad": "GPL-3.0 (репозиторий UAD-ng). Берём только имена пакетов, список и уровень удаления; "
           "описания не копируем.",
    "exodus": "Код εxodus — AGPL-3.0; база и результаты API — Open Database License (ODbL 1.0), "
              "содержимое — Database Contents License (DbCL 1.0). Нужна ссылка на источник.",
    "stalkerware": "CC-BY 4.0 (README stalkerware-indicators; файла LICENSE в репо нет). Нужна ссылка на источник.",
    "mvt": "MIT (mvt-indicators). Сами STIX-бандлы — у своих авторов (Amnesty International и др.).",
    "malwarebazaar": "abuse.ch Terms of Use: данные бесплатны по принципам fair use; коммерческое использование API может требовать подписки — в программе API не вызывается, вшит разовый экспорт (https://bazaar.abuse.ch/faq/#tos).",
}

MB_TIME_BUDGET = 600  # секунд на скачивание полного CSV
HASH_RE = re.compile(r"^[0-9a-f]{64}$")

# Русские print-ы в Git Bash / cmd иначе выходят в cp1251 и выглядят кракозябрами.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass


# ---------------------------------------------------------------- утилиты --

def log(msg):
    print(msg, flush=True)


def fetch(url, timeout=120):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def fetch_json(url, timeout=120):
    return json.loads(fetch(url, timeout).decode("utf-8"))


def fetch_to_file(url, path, budget=MB_TIME_BUDGET):
    """Потоковое скачивание в файл с лимитом времени. Возвращает размер."""
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    start = time.time()
    done = 0
    with urllib.request.urlopen(req, timeout=60) as r, open(path, "wb") as f:
        total = int(r.headers.get("Content-Length") or 0)
        last = 0
        while True:
            chunk = r.read(1 << 20)
            if not chunk:
                break
            f.write(chunk)
            done += len(chunk)
            if done - last >= 50 << 20:
                last = done
                log(f"    ... {done >> 20} МБ" + (f" из {total >> 20}" if total else ""))
            if time.time() - start > budget:
                raise TimeoutError(f"скачивание дольше {budget} с, остановлено на {done >> 20} МБ")
    return done


def write_json(name, data):
    os.makedirs(OUT, exist_ok=True)
    path = os.path.join(OUT, name)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    os.replace(tmp, path)
    return os.path.getsize(path)


def write_bytes(name, data):
    os.makedirs(OUT, exist_ok=True)
    path = os.path.join(OUT, name)
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)
    return os.path.getsize(path)


def mb(n):
    return f"{n / 1048576:.2f} МБ" if n >= 1048576 else f"{n / 1024:.1f} КБ"


# ------------------------------------------------------------ простой yaml --

def parse_yaml_entries(text):
    """Разбор списков вида:
        - name: X
          packages:
          - com.foo
          other:
          - ...
    Возвращает [{"name": X, "<ключ>": [элементы...]}]. Скалярные поля — строкой.
    Без вложенных словарей (их содержимое игнорируется)."""
    entries = []
    cur = None
    key = None
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        body = line.strip()
        if indent == 0 and body.startswith("- "):
            cur = {}
            entries.append(cur)
            key = None
            body = body[2:].strip()
            m = re.match(r"^([\w-]+):\s*(.*)$", body)
            if m:
                cur[m.group(1)] = m.group(2).strip().strip("'\"")
            continue
        if cur is None:
            continue
        if indent == 2 and body.startswith("- "):
            # элемент списка под текущим ключом (стиль "  - item")
            if key is not None:
                cur.setdefault(key, [])
                if isinstance(cur[key], list):
                    cur[key].append(body[2:].strip().strip("'\""))
            continue
        if indent == 2:
            m = re.match(r"^([\w-]+):\s*(.*)$", body)
            if m:
                key = m.group(1)
                val = m.group(2).strip()
                if val == "":
                    cur[key] = []
                elif val.startswith("["):
                    cur[key] = [x.strip().strip("'\"") for x in val.strip("[]").split(",") if x.strip()]
                else:
                    cur[key] = val.strip("'\"")
            continue
        if indent == 4 and body.startswith("- ") and key is not None and isinstance(cur.get(key), list):
            cur[key].append(body[2:].strip().strip("'\""))
    return entries


def parse_mvt_indicators(text):
    """indicators.yaml MVT:
        indicators:
          -
            type: github
            name: ...
            github:
              owner: ...
              repo: ...
              branch: ...
              path: ...
    """
    out = []
    cur = None
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        body = line.strip()
        if indent == 2 and body.startswith("-"):
            cur = {}
            out.append(cur)
            body = body[1:].strip()
            if not body:
                continue
        if cur is None:
            continue
        m = re.match(r"^([\w-]+):\s*(.*)$", body)
        if not m:
            continue
        k, v = m.group(1), m.group(2).strip().strip("'\"")
        if k in ("type", "name") and indent == 4:
            cur[k] = v
        elif k in ("owner", "repo", "branch", "path") and indent == 6:
            cur[k] = v
    return [e for e in out if e.get("owner") and e.get("repo") and e.get("path")]


# ------------------------------------------------------------------ шаги --

def build_uad():
    data = fetch_json(SRC["uad"])
    if not isinstance(data, dict):
        raise ValueError("uad_lists.json: ожидался объект {package: {...}}")
    out = {}
    for pkg, info in data.items():
        if not isinstance(info, dict):
            continue
        lst = info.get("list")
        rem = info.get("removal")
        if not pkg or not lst or not rem:
            continue
        out[pkg] = [lst, rem]
    if len(out) < 1000:
        raise ValueError(f"uad: подозрительно мало записей ({len(out)})")
    size = write_json("uad.json", out)
    log(f"  uad.json: {len(out)} пакетов, {mb(size)}")
    return {"records": len(out), "bytes": size}


def build_trackers():
    data = fetch_json(SRC["exodus"])
    trackers = data.get("trackers") if isinstance(data, dict) else None
    if not isinstance(trackers, dict):
        raise ValueError("exodus: ожидался {'trackers': {...}}")
    out = []
    dropped = 0
    for t in trackers.values():
        name = (t.get("name") or "").strip()
        sigs = []
        for s in (t.get("code_signature") or "").split("|"):
            s = s.strip()
            if len(s) < 8:
                continue
            s = s.replace(".", "/")
            if s not in sigs:
                sigs.append(s)
        if not name or not sigs:
            dropped += 1
            continue
        cats = t.get("categories") or t.get("category") or []
        out.append({"name": name, "cat": list(cats), "sig": sigs})
    out.sort(key=lambda x: x["name"].lower())
    if len(out) < 100:
        raise ValueError(f"exodus: подозрительно мало трекеров ({len(out)})")
    size = write_json("trackers.json", out)
    log(f"  trackers.json: {len(out)} трекеров (без сигнатур отброшено {dropped}), {mb(size)}")
    return {"records": len(out), "dropped": dropped, "bytes": size}


def build_malware_packages():
    packages = {}
    watchware = {}
    hashes = {}
    notes = {}

    # 1. stalkerware-indicators: ioc.yaml (сталкерское ПО)
    try:
        entries = parse_yaml_entries(fetch(SRC["stalkerware_ioc"]).decode("utf-8"))
        n = 0
        for e in entries:
            fam = e.get("name")
            for pkg in e.get("packages") or []:
                if fam and pkg and "." in pkg:
                    packages.setdefault(pkg, fam)
                    n += 1
        notes["stalkerware_ioc"] = {"families": len(entries), "packages": n}
        log(f"  stalkerware ioc.yaml: {len(entries)} семейств, {n} пакетов")
    except Exception as ex:  # noqa: BLE001
        notes["stalkerware_ioc"] = {"error": str(ex)}
        log(f"  ! stalkerware ioc.yaml: {ex}")

    # 2. stalkerware-indicators: watchware.yaml (родительский контроль и т.п. — отдельно)
    try:
        entries = parse_yaml_entries(fetch(SRC["stalkerware_watchware"]).decode("utf-8"))
        n = 0
        for e in entries:
            fam = e.get("name")
            for pkg in e.get("packages") or []:
                if fam and pkg and "." in pkg and pkg not in packages:
                    watchware.setdefault(pkg, fam)
                    n += 1
        notes["stalkerware_watchware"] = {"families": len(entries), "packages": n}
        log(f"  stalkerware watchware.yaml: {len(entries)} семейств, {n} пакетов")
    except Exception as ex:  # noqa: BLE001
        notes["stalkerware_watchware"] = {"error": str(ex)}
        log(f"  ! stalkerware watchware.yaml: {ex}")

    # 3. stalkerware-indicators: samples.csv (SHA256, Package Name, Certificate, Version, App)
    try:
        text = fetch(SRC["stalkerware_samples"]).decode("utf-8", "replace")
        n = 0
        for row in csv.DictReader(io.StringIO(text)):
            h = (row.get("SHA256") or "").strip().lower()
            fam = (row.get("App") or "").strip()
            if HASH_RE.match(h) and fam:
                hashes.setdefault(h, fam)
                n += 1
        notes["stalkerware_samples"] = {"hashes": n}
        log(f"  stalkerware samples.csv: {n} хешей")
    except Exception as ex:  # noqa: BLE001
        notes["stalkerware_samples"] = {"error": str(ex)}
        log(f"  ! stalkerware samples.csv: {ex}")

    # 4. MVT indicators → STIX2 бандлы
    try:
        ind = parse_mvt_indicators(fetch(SRC["mvt"]).decode("utf-8"))
        if not ind:
            raise ValueError("indicators.yaml: не разобрано ни одного github-источника")
        mvt_notes = []
        app_re = re.compile(r"app:id\s*=\s*'([^']+)'")
        sha_re = re.compile(r"file:hashes\.(?:'SHA-256'|\"SHA-256\"|SHA-256|sha256)\s*=\s*'([0-9a-fA-F]{64})'")
        for e in ind:
            url = f"https://raw.githubusercontent.com/{e['owner']}/{e['repo']}/{e['branch'] or 'main'}/{e['path']}"
            try:
                bundle = fetch_json(url)
            except Exception as ex:  # noqa: BLE001
                mvt_notes.append({"name": e.get("name"), "url": url, "error": str(ex)})
                log(f"  ! MVT {e.get('name')}: {ex}")
                continue
            objs = bundle.get("objects") or []
            malware_names = {o["id"]: o.get("name") for o in objs if o.get("type") == "malware" and o.get("id")}
            ind_to_mal = {}
            for o in objs:
                if o.get("type") == "relationship" and o.get("target_ref") in malware_names:
                    ind_to_mal[o.get("source_ref")] = malware_names[o["target_ref"]]
            default_fam = (list(malware_names.values())[0] if len(malware_names) == 1 else None) or e.get("name")
            np_ = nh = 0
            for o in objs:
                if o.get("type") != "indicator":
                    continue
                fam = ind_to_mal.get(o.get("id")) or o.get("name") or default_fam
                pat = o.get("pattern") or ""
                for pkg in app_re.findall(pat):
                    if "." in pkg:
                        packages.setdefault(pkg, fam)
                        np_ += 1
                for h in sha_re.findall(pat):
                    hashes.setdefault(h.lower(), fam)
                    nh += 1
            mvt_notes.append({"name": e.get("name"), "url": url, "packages": np_, "hashes": nh})
            log(f"  MVT {e.get('name')[:50]}: {np_} пакетов, {nh} хешей")
        notes["mvt"] = mvt_notes
    except Exception as ex:  # noqa: BLE001
        notes["mvt"] = {"error": str(ex)}
        log(f"  ! MVT: {ex}")

    if not packages:
        raise ValueError("malware-packages: ни одного пакета не собрано — файл не перезаписываем")
    out = {"packages": packages, "hashes": hashes, "watchware": watchware}
    size = write_json("malware-packages.json", out)
    log(f"  malware-packages.json: {len(packages)} пакетов, {len(hashes)} хешей, "
        f"{len(watchware)} watchware, {mb(size)}")
    return {"packages": len(packages), "hashes": len(hashes), "watchware": len(watchware),
            "bytes": size, "sources": notes}


def _is_apk_row(row):
    # "first_seen_utc","sha256_hash","md5_hash","sha1_hash","reporter","file_name",
    # "file_type_guess","mime_type","signature",...
    ftg = (row[6] or "").strip().lower()
    mime = (row[7] or "").strip().lower()
    fname = (row[5] or "").strip().lower()
    return ftg == "apk" or "android" in mime or (ftg == "zip" and fname.endswith(".apk"))


def _mb_from_zip(zip_path):
    hashes = set()
    rows = 0
    with zipfile.ZipFile(zip_path) as z:
        names = [i for i in z.infolist() if i.filename.lower().endswith(".csv")] or z.infolist()
        with z.open(names[0]) as raw:
            text = io.TextIOWrapper(raw, encoding="utf-8", errors="replace", newline="")
            reader = csv.reader((l for l in text if not l.startswith("#")), skipinitialspace=True)
            for row in reader:
                if len(row) < 9:
                    continue
                rows += 1
                if _is_apk_row(row):
                    h = row[1].strip().lower()
                    if HASH_RE.match(h):
                        hashes.add(h)
    return hashes, rows


def _mb_from_api():
    """Запасной путь: API MalwareBazaar (может требовать Auth-Key)."""
    key = os.environ.get("MB_AUTH_KEY", "").strip()
    hashes = set()
    queries = [
        {"query": "get_file_type", "file_type": "apk", "limit": "1000"},
        {"query": "get_taginfo", "tag": "apk", "limit": "1000"},
    ]
    for q in queries:
        body = urllib.parse.urlencode(q).encode()
        headers = {"User-Agent": UA}
        if key:
            headers["Auth-Key"] = key
        req = urllib.request.Request(SRC["malwarebazaar_api"], data=body, headers=headers)
        with urllib.request.urlopen(req, timeout=120) as r:
            res = json.loads(r.read().decode("utf-8", "replace"))
        status = res.get("query_status")
        if status != "ok":
            raise RuntimeError(f"API {q['query']}: {status}" + ("" if key else " (без Auth-Key)"))
        for item in res.get("data") or []:
            h = (item.get("sha256_hash") or "").lower()
            if HASH_RE.match(h):
                hashes.add(h)
    return hashes


def build_apk_hashes():
    hashes = None
    rows = 0
    source = SRC["malwarebazaar"]
    local = os.environ.get("MB_ZIP", "").strip()
    tmp = None
    try:
        if local and os.path.exists(local):
            log(f"  MalwareBazaar: беру локальный zip {local}")
            hashes, rows = _mb_from_zip(local)
            source = f"{source} (локальная копия {local})"
        else:
            fd, tmp = tempfile.mkstemp(prefix="mb_full_", suffix=".zip")
            os.close(fd)
            log(f"  MalwareBazaar: качаю полный CSV ({source}) ...")
            try:
                size = fetch_to_file(source, tmp)
            except urllib.error.HTTPError as ex:
                if ex.code in (401, 403):
                    log(f"  ! MalwareBazaar экспорт закрыт ({ex.code}), пробую API ...")
                    hashes = _mb_from_api()
                    source = SRC["malwarebazaar_api"]
                else:
                    raise
            else:
                log(f"  MalwareBazaar: скачано {mb(size)}, разбираю CSV ...")
                hashes, rows = _mb_from_zip(tmp)
    finally:
        if tmp and os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass
    if not hashes:
        raise ValueError("MalwareBazaar: не найдено ни одного APK-хеша — файл не перезаписываем")
    ordered = sorted(hashes)
    blob = b"".join(bytes.fromhex(h) for h in ordered)
    size = write_bytes("apk-hashes.bin", blob)
    log(f"  apk-hashes.bin: {len(ordered)} хешей из {rows or '?'} строк, {mb(size)}")
    return {"records": len(ordered), "csv_rows": rows, "bytes": size, "source": source}


# ------------------------------------------------------------------- main --

STEPS = [
    ("uad", "uad.json", build_uad),
    ("exodus", "trackers.json", build_trackers),
    ("malware", "malware-packages.json", build_malware_packages),
    ("malwarebazaar", "apk-hashes.bin", build_apk_hashes),
]


def main():
    os.makedirs(OUT, exist_ok=True)
    meta_path = os.path.join(OUT, "data-meta.json")
    old_meta = {}
    if os.path.exists(meta_path):
        try:
            with open(meta_path, encoding="utf-8") as f:
                old_meta = json.load(f)
        except Exception:  # noqa: BLE001
            old_meta = {}

    started = time.time()
    results = {}
    errors = {}
    for key, fname, fn in STEPS:
        log(f"[{key}] -> {fname}")
        t0 = time.time()
        try:
            results[key] = fn()
            results[key]["seconds"] = round(time.time() - t0, 1)
        except Exception as ex:  # noqa: BLE001
            errors[key] = f"{type(ex).__name__}: {ex}"
            kept = os.path.exists(os.path.join(OUT, fname))
            log(f"  ! {key}: {errors[key]}" + (" — оставлен старый файл" if kept else " — файла нет"))
            prev = (old_meta.get("files") or {}).get(key)
            if kept and prev:
                prev = dict(prev)
                prev["stale"] = True
                results[key] = prev

    meta = {
        "built_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "builder": "scripts/build-data.py",
        "files": results,
        "errors": errors,
        "sources": SRC,
        "licenses": LICENSES,
        "formats": {
            "uad.json": "{package: [list, removal]}; list: Google|Oem|Misc|Carrier|Aosp|Pending; "
                        "removal: Recommended|Advanced|Expert|Unsafe",
            "trackers.json": "[{name, cat: [...], sig: ['com/google/android/gms/ads/', ...]}] — "
                             "префиксы классов dex без 'L'",
            "malware-packages.json": "{packages: {pkg: family}, hashes: {sha256: family}, "
                                     "watchware: {pkg: family}} — watchware это родительский "
                                     "контроль/трекеры из watchware.yaml, не вредоносное ПО",
            "apk-hashes.bin": "SHA-256 по 32 байта подряд, отсортированы по значению — "
                              "бинарный поиск",
        },
    }
    with open(meta_path + ".tmp", "w", encoding="utf-8", newline="\n") as f:
        json.dump(meta, f, ensure_ascii=False, indent=1, sort_keys=True)
    os.replace(meta_path + ".tmp", meta_path)

    log("")
    log(f"Готово за {round(time.time() - started)} с. Файлы в {OUT}:")
    for name in sorted(os.listdir(OUT)):
        p = os.path.join(OUT, name)
        if os.path.isfile(p):
            log(f"  {name:24s} {mb(os.path.getsize(p))}")
    if errors:
        log("Ошибки:")
        for k, v in errors.items():
            log(f"  {k}: {v}")
    return 1 if len(errors) == len(STEPS) else 0


if __name__ == "__main__":
    sys.exit(main())
