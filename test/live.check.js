'use strict';
// Живой прогон на эмуляторе без Electron: scan → rules → tidy.find. node test/live.check.js [serial]
const Module = require('node:module');
const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcpguard-live-'));
const realLoad = Module._load;
Module._load = function (request, ...rest) {
  if (request === 'electron') return { app: { getPath: () => dataDir } };
  return realLoad.call(this, request, ...rest);
};
const scan = require('../src/main/scan');
const rules = require('../src/main/rules');
const tidy = require('../src/main/tidy');

(async () => {
  const serial = process.argv[2] || 'emulator-5560';
  const t0 = Date.now();
  const entries = await scan.scanDevice(serial, ({ done, total, package: pkg }) => process.stdout.write(`\r${done}/${total} ${pkg}      `));
  console.log(`\nскан: ${entries.length} приложений за ${Math.round((Date.now() - t0) / 1000)} с`);
  for (const e of entries) console.log(` ${e.package} target=${e.targetSdk} sdks=${e.sdks.map((s) => s.name).join(',') || '-'} ctrl=${e.control.text || '-'}`);
  const device = await require('../src/main/adb').getDeviceInfo(serial);
  console.log('device:', device);
  const report = rules.buildReport(device, entries);
  console.log('warnings:', report.device_warnings);
  for (const p of report.packages) console.log(` ${p.category.padEnd(6)} ${String(p.score).padStart(3)} ${p.risk.padEnd(8)} ${p.verdict_source.padEnd(8)} ${p.package} — ${p.reason}`);
  const names = entries.map((e) => ({ package: e.package, autostart: e.permissions.includes('android.permission.RECEIVE_BOOT_COMPLETED') }));
  const [ads, bloat, hogs, dns] = await Promise.all([tidy.findAdServices(serial), tidy.findBloat(serial, names.map((n) => n.package)), tidy.findBackgroundHogs(serial, names), tidy.dnsState(serial)]);
  console.log('ads:', ads, '\nbloat:', bloat.length, bloat.slice(0, 8).map((b) => b.package), '\nhogs:', hogs, '\ndns:', dns);
  fs.writeFileSync(path.join(__dirname, '..', '..', 'agent-conveyor', 'runs', 'mcpguard', 'live-report.json'), JSON.stringify({ report, ads, bloat, hogs, dns }, null, 1));
  fs.rmSync(dataDir, { recursive: true, force: true });
})().catch((e) => { console.error(e); process.exit(1); });
