const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('node:path');
const adb = require('./main/adb');
const scan = require('./main/scan');
const config = require('./main/config');
const api = require('./main/api');
const control = require('./main/control');
const tidy = require('./main/tidy');
const rules = require('./main/rules');
const { initAutoUpdate } = require('./main/updater');
const logger = require('./main/logger');

let mainWindow = null;

function createMainWindow() {
  mainWindow = new BrowserWindow({
    width: 1100,
    height: 700,
    minWidth: 800,
    minHeight: 500,
    title: 'MCP Guard',
    backgroundColor: '#0a0f0b',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));
}

ipcMain.handle('adb:list-devices', async () => {
  try {
    const devices = await adb.listDevices();
    return { ok: true, devices };
  } catch (error) {
    return { ok: false, error: error.message };
  }
});

ipcMain.handle('adb:device-info', async (_event, serial) => {
  try {
    const info = await adb.getDeviceInfo(serial);
    return { ok: true, info };
  } catch (error) {
    return { ok: false, error: error.message };
  }
});

// Фаза 16: оценка идёт на компьютере (rules.js + базы в src/data). Сервер нужен
// только за карточками Google Play — если его нет, отчёт всё равно будет.
const PLAY_TIMEOUT_MS = 25000;

async function playCards(packages) {
  try {
    return await api.playCards(packages.map((p) => p.package), PLAY_TIMEOUT_MS);
  } catch (error) {
    logger.error('Карточки Google Play недоступны, оценка без них', error);
    return {};
  }
}

ipcMain.handle('scan:run', async (_event, serial, device) => {
  const send = (channel, payload) => mainWindow && mainWindow.webContents.send(channel, payload);
  try {
    const packages = await scan.scanDevice(serial, (progress) => {
      send('scan:progress', { ...progress, entry: undefined });
    });
    send('scan:progress', { phase: 'finishing', total: packages.length });
    const cards = await playCards(packages);
    for (const p of packages) p.play = cards[p.package] || null;
    const report = rules.buildReport(device || { serial }, packages);
    logger.info(`Проверено ${packages.length} приложений: ${report.packages.filter((p) => p.category === 'danger').length} опасных, ${report.packages.filter((p) => p.category === 'junk').length} мусор`);
    return { ok: true, packages, report };
  } catch (error) {
    return { ok: false, error: error.message };
  }
});

// Удаление отмеченных приложений. Подтверждение показывает главный
// процесс нативным диалогом — renderer не может его обойти.
ipcMain.handle('adb:uninstall-many', async (_event, serial, packages) => {
  const list = Array.isArray(packages) ? packages.filter(Boolean) : [];
  if (list.length === 0) {
    return { ok: false, error: 'Не выбрано ни одного приложения.' };
  }

  const preview = list.slice(0, 15).join('\n');
  const more = list.length > 15 ? `\n…и ещё ${list.length - 15}` : '';

  const { response } = await dialog.showMessageBox(mainWindow, {
    type: 'warning',
    buttons: ['Отмена', 'Удалить'],
    defaultId: 0,
    cancelId: 0,
    title: 'Подтверждение удаления',
    message: `Удалить приложений: ${list.length}?`,
    detail:
      'Для каждого приложения по очереди: остановить → отключить спецвозможности и ' +
      'оверлей → снять права администратора → удалить.\n' +
      `Системные приложения программа не трогает.\n\n${preview}${more}\n\nПеред удалением программа копирует приложение на компьютер — вернуть можно в «Журнале».`,
  });

  if (response !== 1) {
    logger.info(`Удаление отменено пользователем (${list.length} пакетов)`);
    return { ok: false, cancelled: true };
  }

  logger.info(`Подтверждено удаление ${list.length} пакетов с ${serial}`);

  const results = [];
  for (const pkg of list) {
    const step = (text) => {
      if (mainWindow) mainWindow.webContents.send('uninstall:progress', { package: pkg, step: text });
    };
    try {
      step('копия на компьютер');
      const backup = await tidy.backupApk(serial, pkg);
      const outcome = await control.safeRemove(serial, pkg, step);
      if (outcome.ok && !outcome.alreadyGone) tidy.addJournal({ package: pkg, label: '', action: 'remove', backup, undone: false });
      if (outcome.ok) {
        logger.info(outcome.alreadyGone ? `Пакет ${pkg} уже был удалён` : `Удалён пакет ${pkg}`);
      } else {
        logger.error(`Не удалось удалить ${pkg}: ${outcome.error}`);
      }
      results.push({ package: pkg, ...outcome });
    } catch (error) {
      logger.error(`Не удалось удалить ${pkg}`, error);
      results.push({ package: pkg, ok: false, error: error.message });
    }
    if (mainWindow) {
      mainWindow.webContents.send('uninstall:progress', results[results.length - 1]);
    }
  }

  return { ok: true, results };
});

ipcMain.handle('config:get', async () => {
  try {
    return { ok: true, config: config.publicConfig() };
  } catch (error) {
    return { ok: false, error: error.message };
  }
});

ipcMain.handle('config:set', async (_event, patch) => {
  try {
    const next = {};
    if (typeof patch?.backendUrl === 'string') {
      next.backendUrl = patch.backendUrl.trim();
    }
    // Пустая строка = «не менять токен» (в UI он показан маской).
    if (typeof patch?.apiToken === 'string' && patch.apiToken.trim()) {
      next.apiToken = patch.apiToken.trim();
    }
    await config.writeConfig(next);
    return { ok: true, config: config.publicConfig() };
  } catch (error) {
    return { ok: false, error: error.message };
  }
});

ipcMain.handle('backend:pair', async (_event, code) => {
  try {
    const token = await api.pair(code);
    await config.writeConfig({ apiToken: token });
    return { ok: true, config: config.publicConfig() };
  } catch (error) {
    return { ok: false, error: error.message };
  }
});

ipcMain.handle('backend:check', async () => {
  try {
    const info = await api.checkAuth();
    return { ok: true, info };
  } catch (error) {
    return { ok: false, error: error.message };
  }
});

ipcMain.handle('rules:info', async () => ({ ok: true, info: rules.dbInfo() }));

// Фазы 15–16: рекламные службы прошивки, лишнее по спискам UAD, приложения, которые
// чаще всех будят телефон, и текущий приватный DNS. userPackages — [{package, autostart}].
ipcMain.handle('tidy:find', async (_event, serial, userPackages) => {
  try {
    const list = Array.isArray(userPackages) ? userPackages : [];
    const names = list.map((p) => (typeof p === 'string' ? p : p.package));
    const [ads, bloat, hogs, dns] = await Promise.all([
      tidy.findAdServices(serial),
      tidy.findBloat(serial, names),
      tidy.findBackgroundHogs(serial, list),
      tidy.dnsState(serial),
    ]);
    return { ok: true, ads, bloat, hogs, dns: { ...dns, blocking: dns.mode === 'hostname' && dns.host === tidy.DNS_HOST } };
  } catch (error) {
    return { ok: false, error: error.message };
  }
});

// «Привести телефон в порядок»: items = [{package, label, action: remove|disable|restrict}].
ipcMain.handle('tidy:apply', async (_event, serial, items) => {
  const list = (Array.isArray(items) ? items : []).filter((i) => i && i.package);
  if (list.length === 0) return { ok: false, error: 'Ничего не выбрано.' };
  const count = (a) => list.filter((i) => i.action === a).length;
  const { response } = await dialog.showMessageBox(mainWindow, {
    type: 'warning',
    buttons: ['Отмена', 'Выполнить'],
    defaultId: 0,
    cancelId: 0,
    title: 'Привести телефон в порядок',
    message: `Удалить: ${count('remove')}, отключить: ${count('disable')}, ограничить фон: ${count('restrict')}` +
      `${count('cache') ? ', очистить кеш' : ''}${count('dns') ? ', включить DNS без рекламы' : ''}`,
    detail:
      'Всё можно вернуть в «Журнале»: удалённое программа сначала копирует на компьютер ' +
      '(данные внутри приложения при этом не сохраняются). Системные приложения программа не удаляет, ' +
      'только отключает. Кеш приложения пересоздадут сами.',
  });
  if (response !== 1) return { ok: false, cancelled: true };

  const results = [];
  for (const item of list) {
    const step = (text) => mainWindow && mainWindow.webContents.send('uninstall:progress', { package: item.package, step: text });
    let outcome;
    try {
      if (item.action === 'remove') {
        step('копия на компьютер');
        const backup = await tidy.backupApk(serial, item.package);
        outcome = await control.safeRemove(serial, item.package, step);
        if (outcome.ok) tidy.addJournal({ package: item.package, label: item.label || '', action: 'remove', backup, undone: false });
      } else {
        outcome = await tidy.runAction(serial, item.package, item.action, item.label || '');
      }
    } catch (error) {
      outcome = { ok: false, error: error.message };
    }
    logger.info(`tidy ${item.action} ${item.package}: ${outcome.ok ? 'ok' : outcome.error}`);
    results.push({ ...item, ...outcome });
    if (mainWindow) mainWindow.webContents.send('uninstall:progress', results[results.length - 1]);
  }
  return { ok: true, results };
});

ipcMain.handle('tidy:journal', async () => ({ ok: true, journal: tidy.readJournal() }));

ipcMain.handle('tidy:undo', async (_event, serial, ts) => {
  try {
    return await tidy.undo(serial, ts);
  } catch (error) {
    return { ok: false, error: error.message };
  }
});

// Непойманные сбои тоже должны попадать в лог, а не исчезать вместе с окном.
process.on('uncaughtException', (error) => {
  logger.error('Непойманное исключение в главном процессе', error);
});
process.on('unhandledRejection', (reason) => {
  logger.error('Необработанный rejection', reason);
});

app.whenReady().then(() => {
  logger.init(app);
  logger.info(`MCP Guard ${app.getVersion()} запущен; adb: ${adb.resolveAdbPath()}`);
  createMainWindow();
  initAutoUpdate(() => mainWindow);

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createMainWindow();
    }
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});
