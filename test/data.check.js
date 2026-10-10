// node test/data.check.js — проверка формата локальных баз из src/data (собирает scripts/build-data.py).
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const DATA = path.join(__dirname, '..', 'src', 'data');
const loadJson = (name) => JSON.parse(fs.readFileSync(path.join(DATA, name), 'utf8'));

// uad.json: {package: [list, removal]}
const uad = loadJson('uad.json');
const LISTS = new Set(['Google', 'Oem', 'Misc', 'Carrier', 'Aosp', 'Pending']);
const REMOVALS = new Set(['Recommended', 'Advanced', 'Expert', 'Unsafe']);
assert.ok(Object.keys(uad).length > 1000, 'uad: слишком мало пакетов');
for (const [pkg, v] of Object.entries(uad)) {
  assert.ok(Array.isArray(v) && v.length === 2, `uad: ${pkg} не [list, removal]`);
  assert.ok(LISTS.has(v[0]), `uad: ${pkg} неизвестный list ${v[0]}`);
  assert.ok(REMOVALS.has(v[1]), `uad: ${pkg} неизвестный removal ${v[1]}`);
}
assert.ok(uad['com.miui.msa.global'], 'uad: нет com.miui.msa.global');
assert.ok(['Recommended', 'Advanced'].includes(uad['com.miui.msa.global'][1]), 'uad: com.miui.msa.global не Recommended/Advanced');

// trackers.json: [{name, cat, sig}]
const trackers = loadJson('trackers.json');
assert.ok(Array.isArray(trackers) && trackers.length > 100, 'trackers: слишком мало');
for (const t of trackers) {
  assert.ok(typeof t.name === 'string' && t.name, 'trackers: пустое имя');
  assert.ok(Array.isArray(t.cat), `trackers: ${t.name} cat не массив`);
  assert.ok(Array.isArray(t.sig) && t.sig.length > 0, `trackers: ${t.name} без сигнатур`);
  for (const s of t.sig) {
    assert.ok(s.length >= 8 && !s.includes('.'), `trackers: ${t.name} сигнатура «${s}» не в dex-виде`);
  }
}
const admob = trackers.find((t) => /AdMob|Google Ads/.test(t.name) && t.sig.some((s) => s.startsWith('com/google/android/gms/ads')));
assert.ok(admob, 'trackers: не найден AdMob/Google Ads с сигнатурой com/google/android/gms/ads');

// malware-packages.json: {packages, hashes, watchware}
const mal = loadJson('malware-packages.json');
assert.ok(mal.packages && Object.keys(mal.packages).length > 0, 'malware: packages пусто');
assert.ok(mal.hashes && Object.keys(mal.hashes).length > 0, 'malware: hashes пусто');
for (const [pkg, fam] of Object.entries(mal.packages)) {
  assert.ok(pkg.includes('.') && typeof fam === 'string' && fam, `malware: плохая запись ${pkg}`);
}
for (const [h, fam] of Object.entries(mal.hashes)) {
  assert.ok(/^[0-9a-f]{64}$/.test(h) && typeof fam === 'string' && fam, `malware: плохой хеш ${h}`);
}

// apk-hashes.bin: по 32 байта, отсортированы
const bin = fs.readFileSync(path.join(DATA, 'apk-hashes.bin'));
assert.ok(bin.length > 0 && bin.length % 32 === 0, `apk-hashes: длина ${bin.length} не кратна 32`);
const n = Math.min(1000, bin.length / 32);
for (let i = 1; i < n; i++) {
  const a = bin.subarray((i - 1) * 32, i * 32);
  const b = bin.subarray(i * 32, (i + 1) * 32);
  assert.ok(Buffer.compare(a, b) < 0, `apk-hashes: не отсортировано/дубликат на позиции ${i}`);
}

// data-meta.json
const meta = loadJson('data-meta.json');
assert.ok(meta.built_at && meta.files && meta.licenses, 'data-meta: нет полей');

console.log(`OK: uad ${Object.keys(uad).length}, trackers ${trackers.length}, malware packages ${Object.keys(mal.packages).length} / hashes ${Object.keys(mal.hashes).length}, apk hashes ${bin.length / 32}`);
