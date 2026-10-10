// node test/tidy.check.js — разбор «Alarm Stats» из dumpsys alarm (фон, фаза 15).
const Module = require('node:module');
const load = Module._load;
Module._load = function (req, ...rest) {
  return req === 'electron' ? { app: {} } : load.call(this, req, ...rest);
};
const assert = require('node:assert');
const { parseWakeups, parseNotifications } = require('../src/main/tidy');

const sample = `Pending alarm batches: 3
  u0a99:com.fake.pending +1s running, 999 wakeups:
Alarm Stats:
  u0a136:com.android.systemui +13ms running, 1 wakeups:
  u0a187:com.kidzfun.dino1 +4m2s running, 1012 wakeups:
    +4m running 1012 wakeups 1012 alarms: *walarm*:ping
  u10a187:com.kidzfun.dino1 +1s running, 8 wakeups:
`;
assert.deepStrictEqual(parseWakeups(sample), { 'com.android.systemui': 1, 'com.kidzfun.dino1': 1020 });
assert.deepStrictEqual(parseWakeups('нет раздела'), {});
assert.deepStrictEqual(
  parseNotifications(`NotificationRecord(0x0a: pkg=com.kidzfun.dino1 user=0
  NotificationRecord(0x0b: pkg=com.kidzfun.dino1
  NotificationRecord(0x0a: pkg=com.kidzfun.dino1
  NotificationRecord(0x0c: pkg=com.android.vending`),
  { 'com.kidzfun.dino1': 2, 'com.android.vending': 1 }
);
console.log('OK');
