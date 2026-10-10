// Скачивает Android Platform Tools (adb, fastboot) в resources/bin/platform-tools.
// Запуск: npm run setup:adb
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const https = require('node:https');
const { execFileSync } = require('node:child_process');

const PLATFORM_TOOLS_URL =
  'https://dl.google.com/android/repository/platform-tools-latest-windows.zip';

const RESOURCES_BIN_DIR = path.join(__dirname, '..', 'resources', 'bin');
const ZIP_PATH = path.join(RESOURCES_BIN_DIR, '_platform-tools.zip');
const TARGET_DIR = path.join(RESOURCES_BIN_DIR, 'platform-tools');

function download(url, destPath) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(destPath);
    https
      .get(url, (response) => {
        if (
          response.statusCode >= 300 &&
          response.statusCode < 400 &&
          response.headers.location
        ) {
          file.close();
          fs.unlinkSync(destPath);
          download(response.headers.location, destPath).then(resolve, reject);
          return;
        }
        if (response.statusCode !== 200) {
          reject(new Error(`Не удалось скачать ${url}: HTTP ${response.statusCode}`));
          return;
        }
        response.pipe(file);
        file.on('finish', () => file.close(resolve));
      })
      .on('error', reject);
  });
}

async function main() {
  if (fs.existsSync(path.join(TARGET_DIR, 'adb.exe'))) {
    console.log('adb уже загружен:', TARGET_DIR);
    return;
  }

  fs.mkdirSync(RESOURCES_BIN_DIR, { recursive: true });

  console.log('Скачивание platform-tools с', PLATFORM_TOOLS_URL);
  await download(PLATFORM_TOOLS_URL, ZIP_PATH);

  console.log('Распаковка в', RESOURCES_BIN_DIR);
  // Явно системный tar.exe (Windows 10 1803+/11): в PATH может быть подмешан
  // bsdtar из Git for Windows, который ломает пути вида "D:\..." (принимает
  // часть до ":" за имя хоста URL).
  const systemTar = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'tar.exe');
  execFileSync(systemTar, ['-xf', ZIP_PATH, '-C', RESOURCES_BIN_DIR], { stdio: 'inherit' });

  fs.unlinkSync(ZIP_PATH);

  if (!fs.existsSync(path.join(TARGET_DIR, 'adb.exe'))) {
    throw new Error('adb.exe не найден после распаковки');
  }

  console.log('Готово:', path.join(TARGET_DIR, 'adb.exe'));
}

main().catch((err) => {
  console.error('Ошибка setup-adb:', err.message);
  console.error(
    'Можно скачать platform-tools вручную и распаковать в resources/bin/platform-tools:',
    PLATFORM_TOOLS_URL
  );
  process.exitCode = 1;
});
