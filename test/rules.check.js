'use strict';
// Проверка локальной оценки (rules.js): подделка бренда → мусор, СМС-права вне мессенджера → опасно,
// известный издатель из магазина → норма, хеш из базы → critical/database, поведение → danger.
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const rules = require('../src/main/rules');

const store = 'com.android.vending';
const entries = [
  { package: 'com.vkontakte.android', label: 'VK', installer: store, permissions: ['android.permission.READ_SMS'], hash: 'a'.repeat(64) },
  { package: 'com.fakegames.tocaworldfree', label: 'Toca World Free', installer: store, permissions: [], hash: 'b'.repeat(64),
    sdks: [{ name: 'AdMob', ads: true }, { name: 'Unity Ads', ads: true }, { name: 'AppLovin', ads: true }] },
  { package: 'com.flash.light', label: 'Фонарик', installer: 'неизвестно', permissions: ['android.permission.READ_SMS', 'android.permission.RECEIVE_SMS'], hash: 'c'.repeat(64) },
  { package: 'com.weather.simple', label: 'Погода', installer: store, permissions: [], hash: 'd'.repeat(64), targetSdk: 33 },
  { package: 'com.spy.tool', label: 'Tool', installer: 'неизвестно', permissions: [], hash: 'e'.repeat(64),
    control: { flags: ['device_admin', 'accessibility'], text: 'админ, спецвозможности' } },
];
const known = fs.readFileSync(path.join(__dirname, '..', 'src', 'data', 'apk-hashes.bin')).subarray(0, 32).toString('hex');
entries.push({ package: 'com.some.app', label: 'App', installer: store, permissions: [], hash: known });

const report = rules.buildReport({ serial: 'test' }, entries);
const by = Object.fromEntries(report.packages.map((p) => [p.package, p]));

assert.strictEqual(by['com.vkontakte.android'].category, 'ok', 'VK с СМС-правами — норма (известный издатель)');
assert.strictEqual(by['com.fakegames.tocaworldfree'].category, 'junk', 'клон Toca — мусор');
assert.match(by['com.fakegames.tocaworldfree'].reason, /подделку/);
assert.match(by['com.fakegames.tocaworldfree'].reason, /рекламных SDK/);
assert.strictEqual(by['com.flash.light'].category, 'danger', 'фонарик с СМС не из магазина — опасно');
assert.strictEqual(by['com.weather.simple'].category, 'ok');
assert.strictEqual(by['com.spy.tool'].verdict_source, 'behavior');
assert.strictEqual(by['com.spy.tool'].category, 'danger');
assert.strictEqual(by['com.some.app'].risk, 'critical');
assert.strictEqual(by['com.some.app'].verdict_source, 'database');
assert.ok(by['com.some.app'].db_match.includes('MalwareBazaar'));
assert.ok(report.disclaimer && !/ИИ|Claude|нейро/i.test(JSON.stringify(report)), 'в отчёте нет упоминаний ИИ');
console.log('OK: rules', report.packages.map((p) => `${p.package}=${p.category}/${p.score}`).join(' '));
