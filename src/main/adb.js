'use strict';

const { execFile } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');

const logger = require('./logger');

function resolveAdbPath() {
  const candidates = [
    // Собранное приложение: extraResources кладёт adb в resources/bin.
    process.resourcesPath
      ? path.join(process.resourcesPath, 'bin', 'platform-tools', 'adb.exe')
      : null,
    // Запуск из исходников (npm start).
    path.join(__dirname, '..', '..', 'resources', 'bin', 'platform-tools', 'adb.exe'),
  ].filter(Boolean);

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }
  // Последняя попытка — adb из PATH.
  return 'adb';
}

function describeAdbFailure(error, stderr) {
  const text = (stderr || '').trim();
  if (text) return text;
  if (error.code === 'ENOENT') {
    return (
      'adb не найден. Запустите «npm run setup:adb» или установите ' +
      'Android Platform Tools и добавьте adb в PATH.'
    );
  }
  if (error.killed) {
    return 'adb не ответил вовремя (таймаут). Проверьте кабель и отладку по USB.';
  }
  return error.message;
}

function runAdb(args, { timeout = 15000 } = {}) {
  return new Promise((resolve, reject) => {
    execFile(
      resolveAdbPath(),
      args,
      { timeout, maxBuffer: 32 * 1024 * 1024 },
      (error, stdout, stderr) => {
        if (error) {
          const message = describeAdbFailure(error, stderr);
          logger.warn(`adb ${args.join(' ')} -> ${message}`);
          reject(new Error(message));
          return;
        }
        resolve(stdout);
      }
    );
  });
}

async function listDevices() {
  const output = await runAdb(['devices']);
  return output
    .split('\n')
    .slice(1)
    .map((line) => line.trim())
    .filter(Boolean)
    .filter((line) => !line.startsWith('*'))
    .map((line) => {
      const [serial, state] = line.split(/\s+/);
      return { serial, state };
    })
    .filter((device) => device.serial);
}

async function getProp(serial, prop) {
  const output = await runAdb(['-s', serial, 'shell', 'getprop', prop]);
  return output.trim();
}

async function getDeviceInfo(serial) {
  const [model, androidVersion] = await Promise.all([
    getProp(serial, 'ro.product.model'),
    getProp(serial, 'ro.build.version.release'),
  ]);
  return { serial, model: model || 'Неизвестная модель', androidVersion: androidVersion || '?' };
}

// Удаление приложения с телефона. Только через adb uninstall и только на
// физически подключённом владельцем устройстве (CLAUDE.md, раздел 3).
async function uninstallPackage(serial, pkg) {
  if (!serial) {
    throw new Error('не указано устройство');
  }
  if (!/^[A-Za-z0-9_.]+$/.test(pkg || '')) {
    throw new Error(`недопустимое имя пакета: ${pkg}`);
  }

  const output = await runAdb(['-s', serial, 'uninstall', pkg], { timeout: 60000 });
  const trimmed = output.trim();

  // adb uninstall возвращает код 0 даже при "Failure [...]" — проверяем текст.
  if (!/^Success$/im.test(trimmed)) {
    throw new Error(trimmed || 'adb не подтвердил удаление');
  }
  return trimmed;
}

module.exports = {
  resolveAdbPath,
  runAdb,
  listDevices,
  getDeviceInfo,
  uninstallPackage,
};
