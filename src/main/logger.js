'use strict';

// Простое файловое логирование главного процесса: ошибки adb и обращений
// к backend должны оставаться видимыми и в собранном exe, где консоли нет.
// Файл — в userData (%APPDATA%\mcp-guard\logs\mcp-guard.log), с обрезкой
// по размеру, чтобы не расти бесконечно.

const fs = require('node:fs');
const path = require('node:path');

const MAX_BYTES = 2 * 1024 * 1024;

let logFile = null;

function init(app) {
  try {
    const dir = path.join(app.getPath('userData'), 'logs');
    fs.mkdirSync(dir, { recursive: true });
    logFile = path.join(dir, 'mcp-guard.log');

    const stats = fs.statSync(logFile, { throwIfNoEntry: false });
    if (stats && stats.size > MAX_BYTES) {
      fs.renameSync(logFile, `${logFile}.old`);
    }
  } catch {
    logFile = null; // логи не критичны — приложение работает и без них
  }
}

function write(level, message, error) {
  const stamp = new Date().toISOString();
  const detail = error ? ` :: ${error.stack || error.message || error}` : '';
  const line = `${stamp} [${level}] ${message}${detail}\n`;

  if (level === 'ERROR') {
    console.error(line.trim());
  } else {
    console.log(line.trim());
  }

  if (!logFile) return;
  try {
    fs.appendFileSync(logFile, line, 'utf8');
  } catch {
    /* не смогли записать — молча продолжаем */
  }
}

module.exports = {
  init,
  logPath: () => logFile,
  info: (message) => write('INFO', message),
  warn: (message, error) => write('WARN', message, error),
  error: (message, error) => write('ERROR', message, error),
};
