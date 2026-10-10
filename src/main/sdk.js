'use strict';

// Рекламные SDK и трекеры внутри приложения — без сети, по данным Exodus Privacy
// (src/data/trackers.json: имя, категории, сигнатуры классов вида com/unity3d/ads/).
//
// Два источника на телефоне:
// 1) манифест — `dumpsys package <pkg>` перечисляет классы activity/receiver/service/
//    provider с intent-фильтрами, у рекламных SDK они почти всегда есть
//    (MobileAdsInitProvider, AppLovinInitProvider, AudienceNetworkActivity…);
// 2) dex — на самом телефоне `unzip -p base.apk 'classes*.dex' | grep -F -f sigs`
//    по таблице строк dex (`Lcom/google/android/gms/ads/AdView;`). Только рекламные
//    сигнатуры и только для APK до DEX_MAX_MB — иначе скан растягивается на минуты.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { runAdb } = require('./adb');

const DEX_MAX_MB = 80;
const SIGS_REMOTE = '/data/local/tmp/mcpguard-sigs.txt';

let trackers = null;
function load() {
  if (!trackers) {
    try {
      trackers = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'data', 'trackers.json'), 'utf8'));
    } catch {
      trackers = [];
    }
  }
  return trackers;
}

function isAds(t) {
  return (t.cat || []).some((c) => /advert/i.test(c));
}

// Сигнатура `com/google/android/gms/ads/` → имя трекера; для манифеста — тот же префикс с точками.
function byPrefix() {
  const list = [];
  for (const t of load()) {
    for (const sig of t.sig || []) list.push({ dotted: sig.replace(/\//g, '.'), slashed: sig, name: t.name, ads: isAds(t) });
  }
  return list;
}

// Имена классов компонентов из dumpsys package: «com.foo/com.google.android.gms.ads.AdActivity».
function componentClasses(dumpsysOutput, pkg) {
  const classes = new Set();
  const re = new RegExp(`${pkg.replace(/\./g, '\\.')}/(\\.?[A-Za-z_$][\\w.$]*)`, 'g');
  for (const m of String(dumpsysOutput).matchAll(re)) {
    const cls = m[1].startsWith('.') ? pkg + m[1] : m[1];
    classes.add(cls);
  }
  return [...classes];
}

// -> [{name, ads}] найденные по классам манифеста.
function fromManifest(dumpsysOutput, pkg) {
  const found = new Map();
  const classes = componentClasses(dumpsysOutput, pkg);
  for (const sig of byPrefix()) {
    if (classes.some((cls) => cls.startsWith(sig.dotted) || cls.includes('.' + sig.dotted))) {
      found.set(sig.name, { name: sig.name, ads: sig.ads });
    }
  }
  return [...found.values()];
}

// Файл сигнатур на телефоне (один раз на скан). Возвращает false, если на телефоне нет unzip.
async function prepareDevice(serial) {
  const which = await runAdb(['-s', serial, 'shell', 'which', 'unzip'], { timeout: 10000 }).catch(() => '');
  if (!which.trim()) return false;
  const lines = byPrefix().filter((s) => s.ads).map((s) => `L${s.slashed}`);
  if (!lines.length) return false;
  const local = path.join(os.tmpdir(), `mcpguard-sigs-${process.pid}.txt`);
  fs.writeFileSync(local, lines.join('\n') + '\n');
  try {
    await runAdb(['-s', serial, 'push', local, SIGS_REMOTE], { timeout: 20000 });
    return true;
  } catch {
    return false;
  } finally {
    fs.rmSync(local, { force: true });
  }
}

async function apkSizeMb(serial, apkPath) {
  const out = await runAdb(['-s', serial, 'shell', 'stat', '-c', '%s', apkPath], { timeout: 10000 }).catch(() => '');
  const bytes = Number(out.trim());
  return Number.isFinite(bytes) ? bytes / 1048576 : Infinity;
}

// -> [{name, ads:true}] по dex; [] если APK велик или unzip нет. Ошибки глушим: это уточнение, не вердикт.
async function fromDex(serial, apkPath) {
  if (!apkPath || (await apkSizeMb(serial, apkPath)) > DEX_MAX_MB) return [];
  const out = await runAdb(
    // toybox grep -F -f не ищет по бинарным данным (проверено на Android 12), поэтому
    // сначала strings — печатные строки dex, среди них все дескрипторы классов.
    ['-s', serial, 'shell', `unzip -p '${apkPath}' 'classes*.dex' | strings | grep -o -F -f ${SIGS_REMOTE} | sort -u`],
    { timeout: 120000 }
  ).catch(() => '');
  const hits = new Set(out.split('\n').map((l) => l.trim().replace(/^L/, '')).filter(Boolean));
  const found = new Map();
  for (const sig of byPrefix()) if (hits.has(sig.slashed)) found.set(sig.name, { name: sig.name, ads: sig.ads });
  return [...found.values()];
}

function merge(...lists) {
  const map = new Map();
  for (const list of lists) for (const t of list) map.set(t.name, t);
  return [...map.values()].sort((a, b) => a.name.localeCompare(b.name));
}

module.exports = { fromManifest, fromDex, prepareDevice, merge, componentClasses, DEX_MAX_MB };
