'use strict';

// Фаза 15: «оживить телефон». Кроме удаления опасного и мусора программа
// выключает рекламные службы прошивки и ограничивает фон у приложений,
// которые чаще всех будят телефон. Всё, что можно вернуть, — возвращается:
// журнал действий лежит в userData/journal.json, у каждой записи «вернуть».

const path = require('node:path');
const fs = require('node:fs');
const { app } = require('electron');
const { shell, safe, isProtected } = require('./control');
const { runAdb } = require('./adb');

// Рекламные, аналитические и телеметрические службы прошивок — свои подписи,
// каждая сверена со списком UAD-ng (src/data/uad.json): уровень Recommended или
// Advanced, иначе в выдачу не попадает. Магазины и обновления прошивки не трогаем.
const AD_SERVICES = {
  // Xiaomi / Redmi / POCO
  'com.miui.msa.global': 'Реклама в системе Xiaomi (MSA)',
  'com.miui.systemAdSolution': 'Реклама в системе Xiaomi (MSA, китайская прошивка)',
  'com.miui.analytics': 'Сбор статистики Xiaomi',
  'com.miui.hybrid': 'Быстрые приложения Xiaomi (реклама)',
  'com.miui.daemon': 'Фоновая телеметрия Xiaomi',
  'com.mfashiongallery.emag': 'Карусель обоев Xiaomi (реклама на экране блокировки)',
  'com.miui.cloudservice': 'Облако Xiaomi (если не пользуетесь Mi Cloud)',
  // Samsung
  'com.samsung.android.mapsagent': 'Служба подсказок Samsung (сбор данных)',
  'com.samsung.android.rubin.app': 'Профилирование пользователя Samsung (Rubin)',
  'com.samsung.android.providers.context': 'Сбор контекста использования Samsung',
  'com.samsung.android.app.spage': 'Лента Samsung Free с рекламой',
  'com.aura.oobe.samsung': 'AppCloud — навязанная установка приложений',
  'com.samsung.android.game.gos': 'Оптимизатор игр Samsung (снижает FPS)',
  // Oppo / Realme / OnePlus (ColorOS)
  'com.nearme.statistics.rom': 'Сбор статистики Oppo/Realme',
  'com.oplus.statistics.rom': 'Сбор статистики Oppo/Realme (новые прошивки)',
  'com.heytap.mcs': 'Push-реклама HeyTap',
  'com.heytap.browser': 'Браузер HeyTap с рекламой',
  'com.oppo.quicksearchbox': 'Поисковая строка Oppo (реклама)',
  'com.coloros.gamespaceui': 'Игровое пространство ColorOS (сбор данных)',
  'net.oneplus.odm': 'Телеметрия OnePlus',
  // Vivo / iQOO
  'com.bbk.iqoo.logsystem': 'Сбор логов Vivo',
  'com.vivo.cota': 'Фоновые загрузки Vivo',
  'com.vivo.pushservice': 'Push-реклама Vivo',
  'com.vivo.abe': 'Фоновая телеметрия Vivo',
  'com.vivo.assistant': 'Ассистент Vivo (реклама)',
  // Huawei / Honor
  'com.huawei.bd': 'Телеметрия Huawei (Big Data)',
  // Tecno / Infinix / itel (Transsion)
  'com.transsion.trancare': 'Телеметрия Transsion',
  // Предустановленный Facebook
  'com.facebook.services': 'Службы Facebook, предустановленные производителем',
  'com.facebook.appmanager': 'Менеджер приложений Facebook',
  'com.facebook.system': 'Установщик Facebook',
};

const SAFE_LEVELS = new Set(['Recommended', 'Advanced']);

let uad = null;
function loadUad() {
  if (!uad) {
    try {
      uad = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'data', 'uad.json'), 'utf8'));
    } catch {
      uad = {};
    }
  }
  return uad;
}

// Приватный DNS с блокировкой рекламы: системная настройка Android 9+, без root,
// действует на все приложения и браузеры. Возврат — прежние значения из журнала.
const DNS_HOST = 'dns.adguard-dns.com';
const DNS_PKG = '_dns';
const CACHE_PKG = '_cache';

// Сколько пробуждений с последней зарядки считаем «жрёт батарею в фоне».
const WAKEUPS_MIN = 30;
// Сколько уведомлений одного приложения в шторке одновременно — уже спам.
const NOTIFICATIONS_MIN = 5;

const PKG_RE = /^[A-Za-z0-9_.]+$/;

async function listPackages(serial, flag) {
  const out = await safe(shell(serial, ['pm', 'list', 'packages', flag], 30000));
  return new Set(
    String(out)
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.startsWith('package:'))
      .map((line) => line.slice('package:'.length))
  );
}

async function findAdServices(serial) {
  const enabled = await listPackages(serial, '-e');
  const lists = loadUad();
  return Object.entries(AD_SERVICES)
    .filter(([pkg]) => enabled.has(pkg) && (!lists[pkg] || SAFE_LEVELS.has(lists[pkg][1])))
    .map(([pkg, label]) => ({ package: pkg, label }));
}

// Остальное лишнее от производителя/оператора по спискам UAD-ng (уровень Recommended):
// включено на телефоне, не стороннее, не из AD_SERVICES. Описаний у нас нет — показываем
// как «можно отключить», по умолчанию не отмечено. AOSP и Google не предлагаем.
async function findBloat(serial, userPackages) {
  const [enabled, third] = await Promise.all([listPackages(serial, '-e'), listPackages(serial, '-3')]);
  const lists = loadUad();
  const user = new Set(userPackages);
  return [...enabled]
    .filter((pkg) => !third.has(pkg) && !user.has(pkg) && !AD_SERVICES[pkg] && lists[pkg] && lists[pkg][1] === 'Recommended')
    .filter((pkg) => lists[pkg][0] !== 'Aosp' && lists[pkg][0] !== 'Google')
    .filter((pkg) => !pkg.startsWith('com.android.') && !/auto_generated_rro|\.overlay/.test(pkg))
    .sort()
    .map((pkg) => ({ package: pkg, label: pkg, list: lists[pkg][0] }));
}

// Текущие значения приватного DNS: {mode, host}. mode: off | opportunistic | hostname | ''.
async function dnsState(serial) {
  const [mode, host] = await Promise.all([
    safe(shell(serial, ['settings', 'get', 'global', 'private_dns_mode'])),
    safe(shell(serial, ['settings', 'get', 'global', 'private_dns_specifier'])),
  ]);
  const clean = (v) => (String(v).trim() === 'null' ? '' : String(v).trim());
  return { mode: clean(mode), host: clean(host) };
}

// «u0a187:com.foo +4m2s running, 1012 wakeups:» из раздела Alarm Stats.
function parseWakeups(dumpsysAlarm) {
  const result = {};
  const stats = String(dumpsysAlarm).split('Alarm Stats:')[1] || '';
  for (const m of stats.matchAll(/^\s+u\d+a\d+:([\w.]+) \+\S+ running, (\d+) wakeups/gm)) {
    result[m[1]] = (result[m[1]] || 0) + Number(m[2]);
  }
  return result;
}

// Сколько уведомлений приложения висит в шторке сейчас: «NotificationRecord(0x0abc: pkg=com.foo».
function parseNotifications(dumpsysNotification) {
  const seen = {};
  for (const m of String(dumpsysNotification).matchAll(/NotificationRecord\((0x[0-9a-f]+): pkg=([\w.]+)/g)) {
    (seen[m[2]] = seen[m[2]] || new Set()).add(m[1]);
  }
  return Object.fromEntries(Object.entries(seen).map(([pkg, ids]) => [pkg, ids.size]));
}

// Сторонние приложения, которые будят телефон чаще порога или засыпают шторку
// уведомлениями (кроме защищённых). userPackages — имена или {package, autostart}:
// autostart = просит RECEIVE_BOOT_COMPLETED, т.е. поднимается при включении телефона.
async function findBackgroundHogs(serial, userPackages) {
  const [alarm, notif] = await Promise.all([
    safe(shell(serial, ['dumpsys', 'alarm'], 30000)),
    safe(shell(serial, ['dumpsys', 'notification'], 30000)),
  ]);
  const wakeups = parseWakeups(alarm);
  const notifications = parseNotifications(notif);
  const list = userPackages.map((p) => (typeof p === 'string' ? { package: p, autostart: false } : p));
  return list
    .filter(({ package: pkg }) => ((wakeups[pkg] || 0) >= WAKEUPS_MIN || (notifications[pkg] || 0) >= NOTIFICATIONS_MIN) && !isProtected(pkg))
    .map(({ package: pkg, autostart }) => ({ package: pkg, wakeups: wakeups[pkg] || 0, notifications: notifications[pkg] || 0, autostart: Boolean(autostart) }))
    .sort((a, b) => b.wakeups + b.notifications * 10 - (a.wakeups + a.notifications * 10));
}

// ------------------------------------------------------------------ журнал

function journalPath() {
  return path.join(app.getPath('userData'), 'journal.json');
}

function readJournal() {
  try {
    return JSON.parse(fs.readFileSync(journalPath(), 'utf8'));
  } catch {
    return [];
  }
}

function addJournal(entry) {
  const journal = readJournal();
  journal.unshift({ ts: new Date().toISOString(), ...entry });
  fs.mkdirSync(path.dirname(journalPath()), { recursive: true });
  fs.writeFileSync(journalPath(), JSON.stringify(journal.slice(0, 500), null, 2), 'utf8');
}

// ------------------------------------------------------------------ копия перед удалением

// Удаление стороннего приложения Android не откатывает (install-existing его не вернёт),
// поэтому перед удалением забираем APK на компьютер; «вернуть» ставит его обратно.
// ponytail: копии не чистятся сами — добавить срок хранения, если начнут занимать место.
async function backupApk(serial, pkg) {
  if (!PKG_RE.test(pkg || '')) return null;
  const paths = String(await safe(shell(serial, ['pm', 'path', pkg], 30000)))
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.startsWith('package:'))
    .map((line) => line.slice('package:'.length));
  if (!paths.length) return null;
  const dir = path.join(app.getPath('userData'), 'backup', pkg);
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });
  try {
    for (const [i, remote] of paths.entries()) {
      await runAdb(['-s', serial, 'pull', remote, path.join(dir, `${i}.apk`)], { timeout: 300000 });
    }
    return dir;
  } catch {
    fs.rmSync(dir, { recursive: true, force: true });
    return null;
  }
}

async function restoreApk(serial, dir) {
  const files = fs.readdirSync(dir).filter((f) => f.endsWith('.apk')).map((f) => path.join(dir, f));
  const out = String(await safe(runAdb(['-s', serial, 'install-multiple', '-r', ...files], { timeout: 300000 }), 'error'));
  return /Success/.test(out) ? { ok: true } : { ok: false, error: out.trim() || 'телефон не подтвердил' };
}

// ------------------------------------------------------------------ действия

const ACTIONS = {
  disable: {
    run: ['pm', 'disable-user', '--user', '0'],
    ok: /disabled/i,
    undo: ['pm', 'enable', '--user', '0'],
    undoOk: /enabled/i,
  },
  restrict: {
    run: ['cmd', 'appops', 'set', '{pkg}', 'RUN_ANY_IN_BACKGROUND', 'ignore'],
    undo: ['cmd', 'appops', 'set', '{pkg}', 'RUN_ANY_IN_BACKGROUND', 'allow'],
  },
};

function command(template, pkg) {
  return template.includes('{pkg}') ? template.map((a) => (a === '{pkg}' ? pkg : a)) : [...template, pkg];
}

// Чистка кеша всех приложений: Android сам освобождает столько, сколько может.
// Не откатывается (кеш приложения пересоздадут), в журнал пишем без «вернуть».
async function clearCache(serial) {
  const out = String(await safe(shell(serial, ['pm', 'trim-caches', '128G'], 120000), 'error'));
  if (/error|exception|unknown/i.test(out)) return { ok: false, error: out.trim() };
  addJournal({ package: CACHE_PKG, label: 'Кеш приложений', action: 'cache', undone: true });
  return { ok: true };
}

async function setDns(serial) {
  const before = await dnsState(serial);
  await shell(serial, ['settings', 'put', 'global', 'private_dns_specifier', DNS_HOST]);
  await shell(serial, ['settings', 'put', 'global', 'private_dns_mode', 'hostname']);
  const after = await dnsState(serial);
  if (after.mode !== 'hostname' || after.host !== DNS_HOST) return { ok: false, error: 'телефон не принял настройку DNS' };
  addJournal({ package: DNS_PKG, label: 'Приватный DNS без рекламы', action: 'dns', before, undone: false });
  return { ok: true };
}

async function undoDns(serial, before) {
  const mode = before && before.mode ? before.mode : 'opportunistic';
  if (before && before.host) await shell(serial, ['settings', 'put', 'global', 'private_dns_specifier', before.host]);
  else await shell(serial, ['settings', 'delete', 'global', 'private_dns_specifier']);
  await shell(serial, ['settings', 'put', 'global', 'private_dns_mode', mode]);
  return { ok: true };
}

async function runAction(serial, pkg, action, label = '') {
  if (action === 'cache') return clearCache(serial);
  if (action === 'dns') return setDns(serial);
  const spec = ACTIONS[action];
  if (!spec || !PKG_RE.test(pkg || '')) return { ok: false, error: 'недопустимое действие' };
  const out = String(await safe(shell(serial, command(spec.run, pkg)), 'error'));
  const ok = spec.ok ? spec.ok.test(out) : !/error|exception|unknown/i.test(out);
  if (ok) addJournal({ package: pkg, label, action, undone: false });
  return ok ? { ok: true } : { ok: false, error: out.trim() || 'телефон не подтвердил' };
}

async function undo(serial, ts) {
  const journal = readJournal();
  const entry = journal.find((item) => item.ts === ts);
  if (!entry || entry.undone) return { ok: false, error: 'запись не найдена' };
  const spec = ACTIONS[entry.action];
  if (entry.action === 'dns') {
    await undoDns(serial, entry.before);
  } else if (entry.action === 'remove') {
    if (!entry.backup || !fs.existsSync(entry.backup)) {
      return { ok: false, error: 'копии нет — поставьте приложение заново из магазина' };
    }
    const res = await restoreApk(serial, entry.backup);
    if (!res.ok) return res;
  } else {
    if (!spec) return { ok: false, error: 'недопустимое действие' };
    const out = String(await safe(shell(serial, command(spec.undo, entry.package)), 'error'));
    const ok = spec.undoOk ? spec.undoOk.test(out) : !/error|exception|unknown/i.test(out);
    if (!ok) return { ok: false, error: out.trim() || 'телефон не подтвердил' };
  }
  entry.undone = true;
  fs.writeFileSync(journalPath(), JSON.stringify(journal, null, 2), 'utf8');
  return { ok: true };
}

module.exports = {
  AD_SERVICES,
  DNS_HOST,
  DNS_PKG,
  CACHE_PKG,
  findAdServices,
  findBloat,
  dnsState,
  findBackgroundHogs,
  parseWakeups,
  parseNotifications,
  runAction,
  backupApk,
  undo,
  readJournal,
  addJournal,
};
