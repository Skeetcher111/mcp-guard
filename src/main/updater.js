'use strict';

// Автообновление: при запуске программа сама проверяет сервер владельца
// (download.mcpteam.ru, папка /mcp-guard-updates/), скачивает новую версию
// в фоне и предлагает перезапуститься. Выкладка новой версии —
// `npm run release` (scripts/release.sh).

const { app, dialog } = require('electron');
const { autoUpdater } = require('electron-updater');
const logger = require('./logger');

const CHECK_INTERVAL_MS = 4 * 60 * 60 * 1000;

function initAutoUpdate(getWindow) {
  // В режиме разработки (npm start) обновляться нечему.
  if (!app.isPackaged) return;

  autoUpdater.autoDownload = true;
  autoUpdater.autoInstallOnAppQuit = true;
  autoUpdater.logger = {
    info: (m) => logger.info(`[update] ${m}`),
    warn: (m) => logger.info(`[update] ${m}`),
    error: (m) => logger.error(`[update] ${m}`),
    debug: () => {},
  };

  autoUpdater.on('update-available', (info) => {
    logger.info(`Найдена новая версия ${info.version}, скачиваем`);
    const win = getWindow();
    if (win) win.webContents.send('update:status', { state: 'downloading', version: info.version });
  });

  autoUpdater.on('update-downloaded', async (info) => {
    const win = getWindow();
    if (win) win.webContents.send('update:status', { state: 'ready', version: info.version });
    const { response } = await dialog.showMessageBox(win, {
      type: 'info',
      buttons: ['Перезапустить сейчас', 'Позже'],
      defaultId: 0,
      cancelId: 1,
      title: 'Обновление MCP Guard',
      message: `Скачана новая версия ${info.version}.`,
      detail: 'Перезапустить программу и установить обновление? Если выбрать «Позже», оно установится при следующем закрытии программы.',
    });
    if (response === 0) {
      setImmediate(() => autoUpdater.quitAndInstall(true, true));
    }
  });

  autoUpdater.on('error', (error) => {
    logger.error('Автообновление не удалось', error);
  });

  const check = () => autoUpdater.checkForUpdates().catch((error) => {
    logger.error('Проверка обновлений не удалась', error);
  });
  check();
  setInterval(check, CHECK_INTERVAL_MS);
}

module.exports = { initAutoUpdate };
