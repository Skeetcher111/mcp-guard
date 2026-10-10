'use strict';

// Оценка приложений на компьютере, без сервера и без ИИ (фаза 16).
//
// Сигналы, от сильного к слабому:
// 1) базы угроз в пакете программы (src/data): хеш APK в MalwareBazaar — critical;
//    имя пакета у stalkerware-indicators / MVT — high;
// 2) поведение на телефоне (control.js): админ, спецвозможности, установка других
//    приложений, скрытый значок;
// 3) правила по фактам: подделка детского бренда, «конвейерный» издатель, рекламные
//    SDK внутри (sdk.js), разрешения не по назначению, откуда установлено, карточка
//    Google Play (если сервер доступен — необязательное уточнение).
// Итог — худший из сигналов. Оценка — эвристика, не вердикт антивируса.

const fs = require('node:fs');
const path = require('node:path');

const DATA_DIR = path.join(__dirname, '..', 'data');

const DISCLAIMER =
  'Оценка по признакам (разрешения, откуда установлено, рекламные SDK, карточка в магазине), ' +
  'а не вердикт антивируса. Совпадение с базой угроз и права управлять телефоном важнее оценки.';

const STORES = new Set([
  'com.android.vending', 'ru.vk.store', 'com.huawei.appmarket', 'com.xiaomi.market', 'com.xiaomi.mipicks',
  'com.sec.android.app.samsungapps', 'com.heytap.market', 'com.oppo.market', 'com.bbk.appstore', 'com.amazon.venezia',
]);

// Детские бренды, которые массово клонируют → префиксы настоящих пакетов.
const BRANDS = [
  [/toca/i, ['com.tocaboca.']],
  [/roblox|obby/i, ['com.roblox.']],
  [/minecraft|mcpe|craft/i, ['com.mojang.']],
  [/sprunki|incredibox/i, ['com.sozbit.']],
  [/skibidi|brainrot|tralalero/i, []],
  [/prank/i, []],
  [/poppy|huggy|playtime/i, ['com.mobentertainment.']],
  [/banban/i, ['com.euphoricbrothers.']],
  [/fnaf|freddy/i, ['com.scottgames.', 'com.clickteam.']],
  [/among.?us|impostor/i, ['com.innersloth.']],
  [/talking.?tom|angela/i, ['com.outfit7.']],
  [/subway.?surf/i, ['com.kiloo.', 'com.sybogames.']],
  [/brawl|clash/i, ['com.supercell.']],
  [/stumble/i, ['com.kitkagames.']],
];

const BIG_PUBLISHERS =
  /^(com\.google|com\.android|com\.yandex|ru\.yandex|com\.vkontakte|com\.vk|ru\.vk|ru\.mail|ru\.sberbank|ru\.sberbankmobile|ru\.tinkoff|com\.idamob|com\.samsung|com\.sec|com\.miui|com\.xiaomi|com\.huawei|com\.microsoft|com\.facebook|org\.telegram|ru\.ozon|com\.avito|ru\.mts|ru\.megafon|ru\.beeline|com\.wildberries|ru\.rostel|ru\.gosuslugi|ru\.alfabank|ru\.vtb24|ru\.raiffeisennews|com\.whatsapp|ru\.dodopizza|com\.sdv|ru\.kinopoisk|ru\.ivi|com\.rtlabs|ru\.auto|ru\.cian|ru\.hh|ru\.lenta|ru\.magnit|ru\.perekrestok|ru\.x5|com\.ozon|ru\.wildberries|ru\.aliexpress|com\.alibaba|com\.tencent|com\.netflix|com\.spotify|com\.duolingo|com\.supercell|com\.mojang|com\.roblox|com\.tocaboca|com\.outfit7|com\.innersloth|com\.king|com\.playrix|com\.rovio|com\.ea\.|com\.gameloft|com\.miniclip|com\.kiloo|com\.sybogames|com\.zeptolab|com\.mytona|com\.nexters|com\.wargaming|com\.pixonic|com\.gaijin|ru\.beeline|com\.lenovo|com\.hisense)/;

const SMS = new Set(['android.permission.READ_SMS', 'android.permission.RECEIVE_SMS', 'android.permission.SEND_SMS']);
const SPY = new Set([
  'android.permission.READ_CALL_LOG', 'android.permission.READ_CONTACTS',
  'android.permission.RECORD_AUDIO', 'android.permission.ACCESS_FINE_LOCATION',
]);
const MESSENGER = /sms|messag|messeng|telegram|whatsapp|viber|dialer|phone|contacts|bank|sber|tinkoff|alfa|vtb/i;
const CLUSTER_MIN = 4;

// Вес признаков «захвата телефона» (control.js).
const CONTROL_WEIGHTS = {
  device_admin: 3, accessibility: 3, installs_apps: 3, can_install: 1,
  overlay: 1, hidden_icon: 1, notification_listener: 1, home_launcher: 1,
};
const RISK_ORDER = { unknown: -1, low: 0, medium: 1, high: 2, critical: 3 };

// ------------------------------------------------------------------ базы угроз

let malware = null;
let hashes = null; // Buffer: отсортированные sha256 по 32 байта
function loadDb() {
  if (malware) return;
  try {
    malware = JSON.parse(fs.readFileSync(path.join(DATA_DIR, 'malware-packages.json'), 'utf8'));
  } catch {
    malware = { packages: {}, hashes: {} };
  }
  try {
    hashes = fs.readFileSync(path.join(DATA_DIR, 'apk-hashes.bin'));
  } catch {
    hashes = Buffer.alloc(0);
  }
}

function hashKnown(hex) {
  if (!hex || !/^[0-9a-f]{64}$/i.test(hex)) return false;
  const needle = Buffer.from(hex.toLowerCase(), 'hex');
  let lo = 0;
  let hi = hashes.length / 32 - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const cmp = hashes.compare(needle, 0, 32, mid * 32, mid * 32 + 32);
    if (cmp === 0) return true;
    if (cmp < 0) lo = mid + 1;
    else hi = mid - 1;
  }
  return false;
}

function dbInfo() {
  loadDb();
  let meta = {};
  try {
    meta = JSON.parse(fs.readFileSync(path.join(DATA_DIR, 'data-meta.json'), 'utf8'));
  } catch {
    /* нет метаданных */
  }
  return {
    updated: meta.built_at || '',
    hashes: hashes.length / 32,
    packages: Object.keys(malware.packages || {}).length,
  };
}

// -> {kind:'hash'|'package', text} | null
function dbLookup(pkg, sha256) {
  loadDb();
  const hex = (sha256 || '').toLowerCase();
  if (hex && malware.hashes && malware.hashes[hex]) return { kind: 'hash', text: `MVT: ${malware.hashes[hex]}` };
  if (hashKnown(hex)) return { kind: 'hash', text: 'MalwareBazaar: хеш APK в базе вредоносных файлов' };
  const family = malware.packages && malware.packages[pkg];
  if (family) return { kind: 'package', text: `Шпионское ПО: ${family}` };
  return null;
}

// ------------------------------------------------------------------ правила

function publisher(row) {
  if (row.play && row.play.developer) return row.play.developer;
  return row.package.split('.').slice(0, 2).join('.');
}

function kidsGame(play) {
  return String(play.category || '').startsWith('GAME') || ['0+', '3+', '6+'].includes(play.age || '');
}

function scorePackage(row, publishers) {
  const pkg = row.package;
  const perms = new Set(row.permissions || []);
  const play = row.play || null;
  const installer = row.installer || '';
  const fromStore = STORES.has(installer);
  const ads = (row.sdks || []).filter((s) => s.ads).map((s) => s.name);
  let score = 5;
  let scam = 0;
  const reasons = [];

  const big = BIG_PUBLISHERS.test(pkg) || Boolean(play && play.found && (play.installs || 0) >= 10_000_000);
  const name = `${pkg} ${row.label || ''} ${(play && play.title) || ''}`;

  for (const [re, official] of BRANDS) {
    const m = re.exec(name);
    if (m && !official.some((p) => pkg.startsWith(p))) {
      scam += 35;
      reasons.push(`похоже на подделку «${m[0]}» от стороннего разработчика`);
      break;
    }
  }

  const pub = publisher(row);
  if ((publishers.get(pub) || 0) >= CLUSTER_MIN && !BIG_PUBLISHERS.test(pkg)) {
    scam += 25;
    score += 15;
    reasons.push(`${publishers.get(pub)} однотипных приложений одного разработчика (${pub})`);
  }

  if (ads.length >= 3 && !big) {
    scam += 15;
    reasons.push(`внутри ${ads.length} рекламных SDK (${ads.slice(0, 3).join(', ')}${ads.length > 3 ? '…' : ''})`);
  } else if (ads.length && !big) {
    reasons.push(`показывает рекламу (${ads.join(', ')})`);
  }

  if (play) {
    if (!play.found) {
      if (!fromStore) {
        score += 20;
        reasons.push('нет в Google Play и установлено не из магазина');
      } else {
        scam += 10;
        reasons.push('карточки в Google Play больше нет');
      }
    } else if (!big) {
      const installs = play.installs || 0;
      if (installs < 50_000 && play.ads && kidsGame(play)) {
        scam += 25;
        reasons.push(`малоизвестная детская игра с рекламой (${installs.toLocaleString('ru-RU')} скачиваний)`);
      }
    }
  } else if (!fromStore) {
    score += 10;
    reasons.push('установлено не из магазина приложений');
  }

  if (row.targetSdk && row.targetSdk < 23 && !big) {
    score += 10;
    reasons.push(`собрано под старый Android (targetSdk ${row.targetSdk}), давно не обновлялось`);
  }

  if ([...perms].some((p) => SMS.has(p)) && !MESSENGER.test(name) && !big) {
    score += 35;
    reasons.push('читает или отправляет СМС');
  }
  const spy = [...perms].filter((p) => SPY.has(p));
  if (spy.length >= 3 && !fromStore && !big) {
    score += 20;
    reasons.push('просит звонки, контакты, микрофон или геолокацию');
  }
  if (perms.has('android.permission.SYSTEM_ALERT_WINDOW') && perms.has('android.permission.REQUEST_INSTALL_PACKAGES') && !big) {
    score += 15;
    reasons.push('может рисовать поверх окон и ставить другие приложения');
  }
  if (perms.has('android.permission.BIND_ACCESSIBILITY_SERVICE') && perms.has('android.permission.SYSTEM_ALERT_WINDOW') && !big) {
    score += 20;
    reasons.push('сочетание спецвозможностей и окон поверх — типично для банковских троянов');
  }

  if (scam >= 35) score = Math.max(score, Math.min(90, 30 + scam));
  const control = (row.control && row.control.flags) || [];
  if (big && !control.length) score = Math.min(score, 15);
  score = Math.max(0, Math.min(100, score));

  let shown = reasons;
  if (big && !control.length) shown = reasons.filter((r) => !/Google Play|магазина/.test(r));
  if (!shown.length) {
    shown = [
      big && fromStore ? 'популярное приложение из магазина'
        : big ? 'приложение известной компании'
          : fromStore ? 'установлено из магазина, явных признаков угрозы нет'
            : 'явных признаков угрозы нет',
    ];
  }
  const reason = shown.join('; ');
  return { score, reason: reason[0].toUpperCase() + reason.slice(1) + '.', kind: scam >= 35 ? 'scam' : '' };
}

// ------------------------------------------------------------------ сведение

function riskFromScore(score) {
  if (score >= 80) return 'critical';
  if (score >= 50) return 'high';
  if (score >= 25) return 'medium';
  return 'low';
}

function riskFromControl(flags) {
  const sum = (flags || []).reduce((n, f) => n + (CONTROL_WEIGHTS[f] || 0), 0);
  if (sum >= 6) return 'critical';
  if (sum >= 3) return 'high';
  if (sum >= 2) return 'medium';
  return 'unknown';
}

function combine(score, dbHit, flags) {
  let risk = riskFromScore(score);
  let source = 'rules';
  if (dbHit) {
    const dbRisk = dbHit.kind === 'hash' ? 'critical' : 'high';
    if (RISK_ORDER[dbRisk] >= RISK_ORDER[risk]) {
      risk = dbRisk;
      source = 'database';
    } else source = 'both';
  }
  const controlRisk = riskFromControl(flags);
  if (controlRisk !== 'unknown' && RISK_ORDER[controlRisk] > RISK_ORDER[risk]) {
    risk = controlRisk;
    source = 'behavior';
  }
  return { risk, source };
}

function category(p) {
  if (p.db_match || p.verdict_source === 'behavior' || (['high', 'critical'].includes(p.risk) && p.kind !== 'scam')) return 'danger';
  if (p.kind === 'scam') return 'junk';
  return p.risk === 'medium' ? 'check' : 'ok';
}

// entries — результат scan.scanDevice (+ play из сервера, если есть). -> отчёт в формате экрана «Итог».
function buildReport(device, entries) {
  const publishers = new Map();
  for (const e of entries) publishers.set(publisher(e), (publishers.get(publisher(e)) || 0) + 1);
  const packages = entries.map((e) => {
    const { score, reason, kind } = scorePackage(e, publishers);
    const dbHit = dbLookup(e.package, e.hash);
    const flags = (e.control && e.control.flags) || [];
    const { risk, source } = combine(score, dbHit, flags);
    const p = {
      package: e.package,
      label: e.label || '',
      installer: e.installer || '',
      permission_count: (e.permissions || []).length,
      permissions: e.permissions || [],
      apk_sha256: e.hash || '',
      score,
      reason,
      db_match: dbHit ? dbHit.text : '',
      control_text: (e.control && e.control.text) || '',
      risk,
      verdict_source: source,
      title: (e.play && e.play.title) || '',
      kind,
      sdks: (e.sdks || []).map((s) => s.name),
    };
    p.category = category(p);
    return p;
  });
  return {
    scan_id: Date.now(),
    created_at: new Date().toISOString(),
    status: 'analyzed',
    analysis: 'local-rules+threat-db',
    disclaimer: DISCLAIMER,
    device: device || {},
    package_count: packages.length,
    packages,
  };
}

module.exports = { buildReport, scorePackage, dbLookup, dbInfo, combine, category, DISCLAIMER, BIG_PUBLISHERS, STORES };
