'use strict';

const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const fsp = require('node:fs/promises');

const { runAdb } = require('./adb');
const control = require('./control');
const sdk = require('./sdk');

async function listThirdPartyPackages(serial) {
  const output = await runAdb(['-s', serial, 'shell', 'pm', 'list', 'packages', '-3']);
  return output
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.startsWith('package:'))
    .map((line) => line.slice('package:'.length).trim())
    .filter(Boolean);
}

function parseInstaller(dumpsysOutput) {
  const match = dumpsysOutput.match(/installerPackageName=([^\s]+)/);
  return match ? match[1] : 'неизвестно';
}

function parsePermissions(dumpsysOutput) {
  const permissions = new Set();
  // В разных версиях Android секции называются по-разному
  // ("requested permissions:", "runtime permissions:", "declared permissions:").
  const sectionRegex = /(?:requested|runtime|install) permissions:\s*\n([\s\S]*?)(?:\n\s*\n|\n[a-zA-Z].*:\s*\n|$)/g;
  let sectionMatch;
  while ((sectionMatch = sectionRegex.exec(dumpsysOutput)) !== null) {
    sectionMatch[1].split('\n').forEach((line) => {
      const trimmed = line.trim();
      const nameMatch = trimmed.match(/^(android\.[\w.]+|com\.[\w.]+)(?::|$)/);
      if (nameMatch) {
        permissions.add(nameMatch[1]);
      }
    });
  }
  return Array.from(permissions);
}

function parseTargetSdk(dumpsysOutput) {
  const match = dumpsysOutput.match(/targetSdk=(\d+)/);
  return match ? Number(match[1]) : null;
}

async function getPackageDetails(serial, pkg) {
  const output = await runAdb(['-s', serial, 'shell', 'dumpsys', 'package', pkg]);
  return {
    installer: parseInstaller(output),
    permissions: parsePermissions(output),
    targetSdk: parseTargetSdk(output),
    // Рекламные SDK и трекеры по классам компонентов манифеста (фаза 16, без сети).
    sdks: sdk.fromManifest(output, pkg),
  };
}

async function getApkPath(serial, pkg) {
  const pathOutput = await runAdb(['-s', serial, 'shell', 'pm', 'path', pkg]);
  const remotePath = pathOutput
    .split('\n')
    .map((line) => line.trim())
    .find((line) => line.startsWith('package:'));
  if (!remotePath) {
    throw new Error('путь к APK не найден');
  }
  return remotePath.slice('package:'.length).trim();
}

// Хеш считает сам телефон (toybox sha256sum, Android 7+) — APK не гоняется
// по USB, это на порядок быстрее. Если на телефоне нет sha256sum —
// запасной путь: скачать APK и посчитать хеш на ПК.
async function getApkHash(serial, pkg, apkRemotePath) {
  if (!apkRemotePath) apkRemotePath = await getApkPath(serial, pkg);

  try {
    const output = await runAdb(['-s', serial, 'shell', 'sha256sum', apkRemotePath], {
      timeout: 60000,
    });
    const match = output.trim().match(/^([0-9a-f]{64})\s/i);
    if (match) return match[1].toLowerCase();
  } catch {
    /* нет sha256sum на телефоне — считаем на ПК */
  }

  const localPath = path.join(os.tmpdir(), `mcp-guard-${pkg}-${Date.now()}.apk`);
  try {
    await runAdb(['-s', serial, 'pull', apkRemotePath, localPath], { timeout: 60000 });
    const buffer = await fsp.readFile(localPath);
    return crypto.createHash('sha256').update(buffer).digest('hex');
  } finally {
    await fsp.unlink(localPath).catch(() => {});
  }
}

// Все сторонние пакеты вместе с установщиком — одной командой.
async function listPackagesWithInstaller(serial) {
  const output = await runAdb(['-s', serial, 'shell', 'pm', 'list', 'packages', '-3', '-i']);
  const map = new Map();
  for (const line of output.split('\n')) {
    const match = line.trim().match(/^package:(\S+)\s+installer=(\S*)/);
    if (match) map.set(match[1], match[2] || 'неизвестно');
  }
  return map;
}

async function scanPackage(serial, pkg, dexReady) {
  const entry = { package: pkg, installer: 'неизвестно', permissions: [], hash: null, hashError: null, targetSdk: null, sdks: [] };

  try {
    const details = await getPackageDetails(serial, pkg);
    Object.assign(entry, details);
  } catch (error) {
    entry.detailsError = error.message;
  }

  let apkPath = null;
  try {
    apkPath = await getApkPath(serial, pkg);
    entry.hash = await getApkHash(serial, pkg, apkPath);
  } catch (error) {
    entry.hashError = error.message;
  }

  if (dexReady && apkPath) {
    entry.sdks = sdk.merge(entry.sdks, await sdk.fromDex(serial, apkPath));
  }

  return entry;
}

// Сколько приложений читаем с телефона одновременно.
const SCAN_CONCURRENCY = 3;

// onProgress({ package, entry, done, total }) вызывается по мере готовности
// каждого приложения — по нему клиент сразу отправляет данные на сервер.
async function scanDevice(serial, onProgress) {
  const packages = await listThirdPartyPackages(serial);

  // Фаза 12: признаки управления телефоном. Кто кого установил — известно
  // сразу (pm list -i), поэтому флаги готовы уже при потоковой отправке.
  const [device, installers, dexReady] = await Promise.all([
    control.collectDeviceSignals(serial),
    listPackagesWithInstaller(serial).catch(() => new Map()),
    sdk.prepareDevice(serial),
  ]);
  const installedBy = control.buildInstalledByMap(
    [...installers].map(([name, installer]) => ({ package: name, installer }))
  );
  const results = new Array(packages.length);
  let next = 0;
  let done = 0;

  async function worker() {
    while (next < packages.length) {
      const index = next++;
      const entry = await scanPackage(serial, packages[index], dexReady);
      try {
        const { flags, installed } = await control.collectPackageFlags(serial, entry, device, installedBy);
        entry.control = { flags, installed, text: control.describeFlags(flags, installed) };
      } catch {
        entry.control = { flags: [], installed: [], text: '' };
      }
      results[index] = entry;
      done += 1;
      if (onProgress) {
        await onProgress({ package: entry.package, entry, done, total: packages.length });
      }
    }
  }

  await Promise.all(Array.from({ length: Math.min(SCAN_CONCURRENCY, packages.length) }, worker));
  return results;
}

module.exports = { listThirdPartyPackages, getPackageDetails, getApkHash, scanDevice, parseTargetSdk };
