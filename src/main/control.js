'use strict';

// Фаза 12: признаки «захвата телефона» и безопасное удаление.
//
// Приложения-захватчики (часто — игры из сторонних магазинов) ставят другие
// приложения, делают себя администратором устройства, включают спецвозможности
// (Accessibility), чтобы самим нажимать кнопки и закрывать экран настроек,
// прячут значок. Всё это телефон честно отдаёт через adb — по списку имён
// такие приложения не поймать, по поведению — ловятся даже новые.
//
// Удаление идёт в безопасном порядке: остановить → отобрать спецвозможности,
// оверлей и право ставить приложения → снять права администратора →
// удалить. Системные приложения не трогаются НИКОГДА: пакет перед каждым
// шагом перепроверяется по живому списку сторонних приложений телефона.

const { runAdb } = require('./adb');

// Кто законно ставит приложения. Остальные «установщики» — подозрительны.
const STORE_INSTALLERS = new Set([
  'com.android.vending', // Google Play
  'com.google.android.packageinstaller', // ручная установка APK пользователем
  'com.android.packageinstaller',
  'com.google.android.apps.nbu.files',
  'ru.vk.store', // RuStore
  'com.huawei.appmarket',
  'com.xiaomi.market',
  'com.xiaomi.mipicks',
  'com.sec.android.app.samsungapps',
  'com.heytap.market',
  'com.oppo.market',
  'com.bbk.appstore',
  'com.amazon.venezia',
  'adb',
  'неизвестно',
  'null',
]);

// Эти пакеты не удаляем, даже если телефон почему-то отдал их как сторонние:
// без них телефон теряет магазин, сервисы Google, звонилку или настройки.
const PROTECTED_PREFIXES = [
  'android',
  'com.android.',
  'com.google.android.gms',
  'com.google.android.gsf',
  'com.google.android.packageinstaller',
  'com.android.vending',
  'com.samsung.',
  'com.sec.',
  'com.miui.',
  'com.xiaomi.',
  'com.huawei.',
  'com.oppo.',
  'com.coloros.',
  'com.oneplus.',
  'com.qualcomm.',
  'com.mediatek.',
];

const FLAG_LABELS = {
  device_admin: 'администратор устройства',
  accessibility: 'спецвозможности (управляет экраном)',
  installs_apps: 'установило другие приложения',
  can_install: 'разрешено ставить приложения',
  overlay: 'рисует поверх других окон',
  hidden_icon: 'скрыло значок',
  notification_listener: 'читает все уведомления',
  home_launcher: 'подменило рабочий стол',
};

// ------------------------------------------------------------------ сбор

function shell(serial, args, timeout = 20000) {
  return runAdb(['-s', serial, 'shell', ...args], { timeout });
}

function packagesFromComponents(text) {
  const set = new Set();
  for (const match of String(text).matchAll(/([A-Za-z][\w.]+)\/[\w.$]+/g)) {
    set.add(match[1]);
  }
  return set;
}

async function safe(promise, fallback = '') {
  try {
    return await promise;
  } catch {
    return fallback;
  }
}

// Один раз на скан: общие для телефона сведения.
async function collectDeviceSignals(serial) {
  const [policy, a11y, listeners, launcherActs, home] = await Promise.all([
    safe(shell(serial, ['dumpsys', 'device_policy'], 30000)),
    safe(shell(serial, ['settings', 'get', 'secure', 'enabled_accessibility_services'])),
    safe(shell(serial, ['settings', 'get', 'secure', 'enabled_notification_listeners'])),
    safe(
      shell(serial, [
        'cmd', 'package', 'query-activities', '--brief',
        '-a', 'android.intent.action.MAIN', '-c', 'android.intent.category.LAUNCHER',
      ], 30000)
    ),
    safe(
      shell(serial, [
        'cmd', 'package', 'resolve-activity', '--brief',
        '-a', 'android.intent.action.MAIN', '-c', 'android.intent.category.HOME',
      ])
    ),
  ]);

  // Активные администраторы: компоненты из секций admin в dumpsys device_policy.
  const adminComponents = new Map();
  for (const match of String(policy).matchAll(/ComponentInfo\{([\w.]+)\/([\w.$]+)\}/g)) {
    adminComponents.set(match[1], `${match[1]}/${match[2]}`);
  }

  const homeLines = String(home).trim().split('\n');
  const homePkg = (homeLines[homeLines.length - 1] || '').split('/')[0].trim();

  return {
    admins: adminComponents, // pkg -> "pkg/Receiver"
    accessibility: packagesFromComponents(a11y),
    accessibilityRaw: String(a11y).trim(),
    listeners: packagesFromComponents(listeners),
    listenersRaw: String(listeners).trim(),
    withLauncherIcon: packagesFromComponents(launcherActs),
    launcherQueryOk: String(launcherActs).includes('/'),
    homePkg,
  };
}

async function appopAllowed(serial, pkg, op) {
  const out = await safe(shell(serial, ['appops', 'get', pkg, op]));
  return /:\s*allow/i.test(out);
}

// Признаки для одного приложения. entries — все приложения скана (нужны,
// чтобы понять, кого это приложение установило).
async function collectPackageFlags(serial, entry, device, installedByMap) {
  const pkg = entry.package;
  const perms = new Set(entry.permissions || []);
  const flags = [];

  if (device.admins.has(pkg)) flags.push('device_admin');
  if (device.accessibility.has(pkg)) flags.push('accessibility');
  if (device.listeners.has(pkg)) flags.push('notification_listener');
  if (device.homePkg === pkg) flags.push('home_launcher');
  if (device.launcherQueryOk && !device.withLauncherIcon.has(pkg)) flags.push('hidden_icon');

  if (perms.has('android.permission.REQUEST_INSTALL_PACKAGES')) {
    if (await appopAllowed(serial, pkg, 'REQUEST_INSTALL_PACKAGES')) flags.push('can_install');
  }
  if (perms.has('android.permission.SYSTEM_ALERT_WINDOW')) {
    if (await appopAllowed(serial, pkg, 'SYSTEM_ALERT_WINDOW')) flags.push('overlay');
  }

  const installed = installedByMap.get(pkg) || [];
  if (installed.length > 0) flags.push('installs_apps');

  return { flags, installed };
}

// Кого установило каждое приложение (по полю installer у остальных).
function buildInstalledByMap(entries) {
  const map = new Map();
  for (const entry of entries) {
    const installer = entry.installer || '';
    if (STORE_INSTALLERS.has(installer) || installer === entry.package) continue;
    if (!map.has(installer)) map.set(installer, []);
    map.get(installer).push(entry.package);
  }
  return map;
}

function describeFlags(flags, installed) {
  return flags
    .map((flag) =>
      flag === 'installs_apps'
        ? `${FLAG_LABELS[flag]} (${installed.length}: ${installed.slice(0, 3).join(', ')}${installed.length > 3 ? '…' : ''})`
        : FLAG_LABELS[flag]
    )
    .join('; ');
}

// ------------------------------------------------------------------ удаление

function isProtected(pkg) {
  return PROTECTED_PREFIXES.some((prefix) => pkg === prefix || pkg.startsWith(prefix));
}

async function listThirdParty(serial) {
  const out = await shell(serial, ['pm', 'list', 'packages', '-3'], 30000);
  return new Set(
    out
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.startsWith('package:'))
      .map((line) => line.slice('package:'.length))
  );
}

async function listSystem(serial) {
  const out = await shell(serial, ['pm', 'list', 'packages', '-s'], 30000);
  return new Set(
    out
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.startsWith('package:'))
      .map((line) => line.slice('package:'.length))
  );
}

// Убрать pkg из списка компонентов в secure-настройке (спецвозможности,
// слушатели уведомлений). Остальные записи сохраняются как были.
async function removeFromSecureList(serial, key, pkg) {
  const current = (await safe(shell(serial, ['settings', 'get', 'secure', key]))).trim();
  if (!current || current === 'null') return false;
  const kept = current.split(':').filter((item) => item && !item.startsWith(`${pkg}/`));
  if (kept.length === current.split(':').filter(Boolean).length) return false;
  if (kept.length === 0) {
    await shell(serial, ['settings', 'delete', 'secure', key]);
  } else {
    await shell(serial, ['settings', 'put', 'secure', key, `'${kept.join(':')}'`]);
  }
  return true;
}

async function isInstalled(serial, pkg) {
  const out = await safe(shell(serial, ['pm', 'list', 'packages', pkg]));
  return out.split('\n').some((line) => line.trim() === `package:${pkg}`);
}

// Безопасное удаление одного приложения. report(step) пишет в журнал UI.
// Возвращает { ok, error?, needsManual? }.
async function safeRemove(serial, pkg, report) {
  if (!/^[A-Za-z0-9_.]+$/.test(pkg || '')) {
    return { ok: false, error: `недопустимое имя пакета: ${pkg}` };
  }

  // 1. Защита от кирпича: только сторонние, не системные, не из белого списка.
  const [thirdParty, system] = await Promise.all([listThirdParty(serial), listSystem(serial)]);
  // Уже нет на телефоне (удалили раньше, а отчёт старый) — это не ошибка.
  if (!thirdParty.has(pkg) && !system.has(pkg) && !(await isInstalled(serial, pkg))) {
    report('уже удалено с телефона');
    return { ok: true, alreadyGone: true };
  }
  if (system.has(pkg) || !thirdParty.has(pkg) || isProtected(pkg)) {
    return { ok: false, error: 'системное или защищённое приложение — удаление запрещено' };
  }

  // 2. Остановить, чтобы оно не мешало следующим шагам.
  await safe(shell(serial, ['am', 'force-stop', pkg]));
  report('остановлено');

  // 3. Отобрать управление экраном и прочие рычаги.
  if (await safe(removeFromSecureList(serial, 'enabled_accessibility_services', pkg), false)) {
    report('отключены спецвозможности');
  }
  if (await safe(removeFromSecureList(serial, 'enabled_notification_listeners', pkg), false)) {
    report('отключён доступ к уведомлениям');
  }
  await safe(shell(serial, ['appops', 'set', pkg, 'SYSTEM_ALERT_WINDOW', 'deny']));
  await safe(shell(serial, ['appops', 'set', pkg, 'REQUEST_INSTALL_PACKAGES', 'deny']));

  // 4. Снять права администратора устройства.
  const policy = await safe(shell(serial, ['dumpsys', 'device_policy'], 30000));
  const admins = [...String(policy).matchAll(/ComponentInfo\{([\w.]+)\/([\w.$]+)\}/g)]
    .filter((m) => m[1] === pkg)
    .map((m) => `${m[1]}/${m[2]}`);
  for (const component of new Set(admins)) {
    const out = await safe(shell(serial, ['dpm', 'remove-active-admin', component]), 'error');
    if (/success/i.test(out)) {
      report('сняты права администратора');
    } else {
      // Android разрешает снимать админа из adb не у всех приложений.
      // Тогда выключаем приложение и открываем экран администраторов —
      // владелец снимает галочку на телефоне сам.
      await safe(shell(serial, ['pm', 'disable-user', '--user', '0', pkg]));
      await safe(shell(serial, ['am', 'start', '-a', 'android.settings.SECURITY_SETTINGS']));
      report('приложение выключено; права администратора нужно снять на телефоне');
      return {
        ok: false,
        needsManual: true,
        error:
          'не удалось снять права администратора из программы. Приложение выключено. ' +
          'На телефоне открыт экран «Безопасность»: зайдите в «Приложения администратора устройства», ' +
          'снимите галочку с этого приложения и нажмите «Удалить выбранные» ещё раз.',
      };
    }
  }

  // 5. Удалить.
  await safe(shell(serial, ['am', 'force-stop', pkg]));
  const out = await safe(runAdb(['-s', serial, 'uninstall', pkg], { timeout: 60000 }), 'error');
  if (/^Success$/im.test(out.trim()) && !(await isInstalled(serial, pkg))) {
    report('удалено');
    return { ok: true };
  }

  // Удаление не прошло — хотя бы выключаем, чтобы оно больше не работало.
  await safe(shell(serial, ['pm', 'disable-user', '--user', '0', pkg]));
  return { ok: false, error: `${out.trim() || 'adb не подтвердил удаление'} — приложение выключено` };
}

module.exports = {
  FLAG_LABELS,
  collectDeviceSignals,
  collectPackageFlags,
  buildInstalledByMap,
  describeFlags,
  safeRemove,
  isProtected,
  shell,
  safe,
};
