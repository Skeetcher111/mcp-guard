'use strict';

// Клиент backend-сервиса MCP Guard (личный VPS владельца).
// Адрес и токен берутся из локального конфига, а не зашиты в код.

const { readConfig, writeConfig } = require('./config');
const logger = require('./logger');

const DEFAULT_TIMEOUT_MS = 60 * 1000;

function requireConfig() {
  const { backendUrl, apiToken } = readConfig();
  if (!backendUrl) {
    throw new Error('Не задан адрес сервера — откройте «Настройки».');
  }
  return { backendUrl: backendUrl.replace(/\/+$/, ''), apiToken };
}

// Своя установка — свой токен: при первом запросе программа сама
// регистрируется на сервере (POST /register) и запоминает токен.
async function register() {
  const result = await request('POST', '/register', null, { timeout: 20000, needToken: false });
  if (!result.api_token) throw new Error('Сервер не выдал токен.');
  await writeConfig({ apiToken: result.api_token, autoToken: true });
  return result.api_token;
}

async function request(method, endpoint, body, opts = {}) {
  const { needToken = true, retried = false } = opts;
  if (needToken && !readConfig().apiToken) await register();
  try {
    return await rawRequest(method, endpoint, body, opts);
  } catch (error) {
    // Токен установки потерялся на сервере — регистрируемся заново один раз.
    if (error.status === 401 && needToken && !retried && readConfig().autoToken) {
      await register();
      return request(method, endpoint, body, { ...opts, retried: true });
    }
    throw error;
  }
}

async function rawRequest(method, endpoint, body, { timeout = DEFAULT_TIMEOUT_MS, needToken = true } = {}) {
  const { backendUrl, apiToken } = requireConfig();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  let response;
  try {
    response = await fetch(`${backendUrl}${endpoint}`, {
      method,
      headers: {
        ...(needToken ? { Authorization: `Bearer ${apiToken}` } : {}),
        ...(body ? { 'Content-Type': 'application/json' } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    });
  } catch (error) {
    if (error.name === 'AbortError') {
      logger.error(`${method} ${endpoint}: таймаут`);
      throw new Error('Backend не ответил вовремя (таймаут запроса).');
    }
    logger.error(`${method} ${endpoint}: сеть`, error);
    // Причина сетевого сбоя обычно лежит в cause (DNS, TLS, отказ соединения).
    const reason = error.cause?.message || error.message;
    throw new Error(`Не удалось связаться с backend: ${reason}`);
  } finally {
    clearTimeout(timer);
  }

  const text = await response.text();

  if (!response.ok) {
    logger.error(`${method} ${endpoint}: HTTP ${response.status} ${text.slice(0, 300)}`);
    if (response.status === 403 && endpoint === '/pair') {
      throw new Error('Код неверный или устарел — попросите новый.');
    }
    if (response.status === 401) {
      throw Object.assign(new Error('Сервер отклонил токен (401).'), { status: 401 });
    }
    let detail = text.slice(0, 500);
    try {
      detail = JSON.parse(text).detail ?? detail;
    } catch {
      /* тело не JSON — покажем как есть */
    }
    throw new Error(`Backend вернул ${response.status}: ${detail}`);
  }

  try {
    return JSON.parse(text);
  } catch {
    throw new Error('Backend вернул не-JSON ответ.');
  }
}

async function health() {
  return request('GET', '/health', null, { timeout: 20000, needToken: false });
}

// Проверка «адрес + токен» разом: эндпоинт закрыт require_token.
async function checkAuth() {
  const info = await health();
  await request('GET', '/auth/check', null, { timeout: 20000 });
  return info;
}

// Карточки Google Play для списка пакетов (фаза 16): сервер только кэширует
// магазин, оценка идёт на компьютере. -> {pkg: {found,title,developer,category,age,ads,installs}}
async function playCards(packages, timeout = 25000) {
  const result = await request('POST', '/play', { packages }, { timeout });
  return result.cards || {};
}

// Одноразовый 6-значный код подключения → API-токен (backend POST /pair).
async function pair(code) {
  const result = await request('POST', '/pair', { code: String(code).trim() }, {
    timeout: 20000,
    needToken: false,
  });
  if (!result.api_token) throw new Error('Backend не вернул токен.');
  return result.api_token;
}

module.exports = { health, checkAuth, pair, playCards };
