'use strict';

// Локальные настройки клиента: адрес сервера и токен установки.
// Лежат в userData (%APPDATA%\mcp-guard\config.json). Токен программа
// получает сама при первом запуске (api.register), в сборку ничего не вшито.

const path = require('node:path');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const { app } = require('electron');

const DEFAULTS = {
  backendUrl: '',
  apiToken: '',
};

function configPath() {
  return path.join(app.getPath('userData'), 'config.json');
}

function readConfig() {
  try {
    const raw = fs.readFileSync(configPath(), 'utf8');
    const saved = JSON.parse(raw);
    return {
      ...DEFAULTS,
      ...saved,
      backendUrl: saved.backendUrl || DEFAULTS.backendUrl,
    };
  } catch {
    return { ...DEFAULTS };
  }
}

async function writeConfig(patch) {
  let saved = {};
  try {
    saved = JSON.parse(fs.readFileSync(configPath(), 'utf8'));
  } catch {
    /* ещё нет файла */
  }
  const next = { ...saved, ...patch };
  await fsp.mkdir(path.dirname(configPath()), { recursive: true });
  await fsp.writeFile(configPath(), JSON.stringify(next, null, 2), 'utf8');
  return next;
}

// В UI токен целиком не показываем — только хвост, чтобы было видно,
// что он задан, но нельзя было подсмотреть с экрана целиком.
function maskToken(token) {
  if (!token) return '';
  if (token.length <= 8) return '••••';
  return `••••${token.slice(-6)}`;
}

function publicConfig() {
  const cfg = readConfig();
  return {
    backendUrl: cfg.backendUrl,
    tokenSet: Boolean(cfg.apiToken),
    tokenMasked: maskToken(cfg.apiToken),
    configPath: configPath(),
  };
}

module.exports = { DEFAULTS, configPath, readConfig, writeConfig, publicConfig };
