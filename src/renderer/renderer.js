'use strict';

const connectBtn = document.getElementById('connect-btn');
const scanBtn = document.getElementById('scan-btn');
const settingsBtn = document.getElementById('settings-btn');
const contentEl = document.getElementById('content');
const deviceStatusEl = document.getElementById('device-status');
const statusTextEl = document.getElementById('status-text');

const state = {
  device: null, // { serial, model, androidVersion }
  packages: null, // результат сканирования телефона
  report: null, // отчёт локальной оценки (rules.js)
};

function setStatus(text) {
  statusTextEl.textContent = text;
}

let stopMatrix = null;

function clearContent() {
  if (stopMatrix) {
    stopMatrix();
    stopMatrix = null;
    contentEl.classList.remove('matrix-mode');
  }
  contentEl.innerHTML = '';
}

// Экран ожидания в стиле «Матрицы»: падающий код с Нео (matrix.js) и
// терминальная рамка поверх. Возвращает рамку — её наполняет вызывающий.
function openMatrixFrame() {
  clearContent();
  contentEl.classList.add('matrix-mode');
  stopMatrix = window.MatrixScene.mount(contentEl);
  const frame = el('div', 'matrix-frame');
  contentEl.appendChild(frame);
  return frame;
}

function renderMatrixWait(title, line) {
  const frame = openMatrixFrame();
  frame.appendChild(el('div', 'ptitle', title));
  const term = el('div', 'term');
  const row = el('div', 'l', `$ ${line}`);
  row.appendChild(el('span', 'caret'));
  term.appendChild(row);
  frame.appendChild(term);
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function renderPlaceholder(message) {
  clearContent();
  const wrap = el('div', 'content-placeholder');
  wrap.appendChild(el('p', null, message));
  contentEl.appendChild(wrap);
}

function setActiveSidebar(view) {
  document.querySelectorAll('.sidebar-item[data-view]').forEach((item) => {
    item.classList.toggle('active', item.dataset.view === view);
  });
}

// ---------------------------------------------------------------- устройство

function renderDeviceList(infos) {
  clearContent();
  const wrap = el('div', 'device-list');
  const list = el('ul');

  infos.forEach((result) => {
    const li = el('li');
    if (result.ok) {
      const { serial, model, androidVersion } = result.info;
      li.textContent = `${model} (Android ${androidVersion}) — ${serial}`;
    } else {
      li.textContent = `Ошибка получения информации об устройстве: ${result.error}`;
    }
    list.appendChild(li);
  });

  wrap.appendChild(list);
  contentEl.appendChild(wrap);
}

async function refreshDevices() {
  connectBtn.disabled = true;
  setStatus('Поиск устройств...');
  renderPlaceholder('Поиск устройств...');

  const result = await window.mcpGuard.listDevices();
  connectBtn.disabled = false;

  if (!result.ok) {
    deviceStatusEl.textContent = 'adb недоступен';
    scanBtn.disabled = true;
    state.device = null;
    setStatus('Ошибка adb');
    renderPlaceholder(`Не удалось выполнить adb: ${result.error}`);
    return;
  }

  const connected = result.devices.filter((device) => device.state === 'device');

  if (connected.length === 0) {
    deviceStatusEl.textContent = 'Нет подключённого устройства';
    scanBtn.disabled = true;
    state.device = null;
    setStatus('Готово');
    renderPlaceholder('Подключите Android-устройство через USB (включите отладку по USB).');
    return;
  }

  deviceStatusEl.textContent = `Устройств подключено: ${connected.length}`;
  scanBtn.disabled = false;
  setStatus('Устройство подключено');

  const infos = await Promise.all(
    connected.map((device) => window.mcpGuard.getDeviceInfo(device.serial))
  );

  const first = infos.find((info) => info.ok);
  state.device = first ? first.info : { serial: connected[0].serial };

  renderDeviceList(infos);
}

// ------------------------------------------------------------- список пакетов

function renderScanTable(packages) {
  setActiveSidebar('packages');
  clearContent();

  const table = el('table', 'scan-table');
  const thead = el('thead');
  const headRow = el('tr');
  ['Пакет', 'Разрешений', 'Источник установки', 'SHA-256 APK'].forEach((title) => {
    headRow.appendChild(el('th', null, title));
  });
  thead.appendChild(headRow);
  table.appendChild(thead);

  const tbody = el('tbody');
  packages.forEach((pkg) => {
    const row = el('tr');
    row.appendChild(el('td', null, pkg.package));
    row.appendChild(el('td', null, String(pkg.permissions.length)));
    row.appendChild(el('td', null, pkg.installer));
    row.appendChild(el('td', 'mono', pkg.hash ? `${pkg.hash.slice(0, 16)}…` : '—'));
    tbody.appendChild(row);
  });
  table.appendChild(tbody);

  contentEl.appendChild(table);
}

// -------------------------------------------------------------------- отчёт

const RISK_ORDER = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };
const RISK_LABELS = {
  critical: 'критический',
  high: 'высокий',
  medium: 'средний',
  low: 'низкий',
  unknown: 'неизвестно',
};

const VERDICT_SOURCE_LABELS = {
  behavior: 'Поведение на телефоне',
  database: 'База угроз',
  rules: 'Оценка по признакам',
  both: 'оба сигнала',
  none: '—',
};

// Состояние экрана отчёта: сортировка, фильтры, отметки.
const reportView = {
  sortKey: 'risk',
  sortAsc: false,
  filterText: '',
  minRisk: 'all',
  selected: new Set(),
  logEntries: [],
};

const REPORT_COLUMNS = [
  { key: 'package', title: 'Пакет' },
  { key: 'installer', title: 'Источник' },
  { key: 'permission_count', title: 'Прав' },
  { key: 'score', title: 'Оценка' },
  { key: 'db_match', title: 'База угроз' },
  { key: 'control_text', title: 'Управляет телефоном' },
  { key: 'risk', title: 'Риск' },
  { key: 'verdict_source', title: 'По какому сигналу' },
];

function sortValue(pkg, key) {
  switch (key) {
    case 'risk':
      return RISK_ORDER[pkg.risk] ?? 0;
    case 'score':
      return pkg.score === null ? -1 : pkg.score;
    case 'permission_count':
      return pkg.permission_count;
    default:
      return String(pkg[key] ?? '').toLowerCase();
  }
}

function visiblePackages() {
  const report = state.report;
  if (!report) return [];

  const needle = reportView.filterText.trim().toLowerCase();
  const minRank = reportView.minRisk === 'all' ? -1 : RISK_ORDER[reportView.minRisk];

  const rows = report.packages.filter((pkg) => {
    if (needle && !pkg.package.toLowerCase().includes(needle)) return false;
    if (minRank >= 0 && (RISK_ORDER[pkg.risk] ?? 0) < minRank) return false;
    return true;
  });

  rows.sort((a, b) => {
    const left = sortValue(a, reportView.sortKey);
    const right = sortValue(b, reportView.sortKey);
    if (left < right) return reportView.sortAsc ? -1 : 1;
    if (left > right) return reportView.sortAsc ? 1 : -1;
    return a.package.localeCompare(b.package);
  });

  return rows;
}

function appendLog(text, kind) {
  reportView.logEntries.push({ text, kind });
  const list = document.getElementById('op-log-list');
  if (!list) return;
  const item = el('li', `op-log-item op-log-${kind || 'info'}`, text);
  list.appendChild(item);
  list.scrollTop = list.scrollHeight;
}

function renderReportDetail(report) {
  setActiveSidebar('report');
  clearContent();

  const wrap = el('div', 'report-view');

  // --- шапка -------------------------------------------------------------
  const head = el('div', 'report-head');
  head.appendChild(
    el('div', 'report-title', `Отчёт #${report.scan_id} — приложений: ${report.package_count}`)
  );
  head.appendChild(
    el(
      'div',
      'report-mode',
      report.analysis === 'stub'
        ? 'Анализ не выполнялся: backend вернул отчёт без оценок (нет ключей или запрос не прошёл).'
        : `Сработавшие сигналы: ${report.analysis}`
    )
  );
  // Обязательная пометка: оценка — эвристика, не антивирусная база.
  head.appendChild(el('div', 'report-disclaimer', report.disclaimer));
  const back = el('button', 'topbar-btn', '← К итогу');
  back.type = 'button';
  back.addEventListener('click', () => renderReport(report));
  head.appendChild(back);
  wrap.appendChild(head);

  // --- панель фильтров ---------------------------------------------------
  const toolbar = el('div', 'report-toolbar');

  const filterInput = el('input', 'report-filter');
  filterInput.type = 'search';
  filterInput.placeholder = 'Фильтр по имени пакета';
  filterInput.value = reportView.filterText;
  filterInput.addEventListener('input', () => {
    reportView.filterText = filterInput.value;
    renderReportTable();
  });
  toolbar.appendChild(filterInput);

  const riskSelect = el('select', 'report-risk-filter');
  [
    ['all', 'Любой риск'],
    ['low', 'Низкий и выше'],
    ['medium', 'Средний и выше'],
    ['high', 'Высокий и выше'],
    ['critical', 'Только критический'],
  ].forEach(([value, title]) => {
    const option = el('option', null, title);
    option.value = value;
    if (value === reportView.minRisk) option.selected = true;
    riskSelect.appendChild(option);
  });
  riskSelect.addEventListener('change', () => {
    reportView.minRisk = riskSelect.value;
    renderReportTable();
  });
  toolbar.appendChild(riskSelect);

  const deleteBtn = el('button', 'topbar-btn danger', 'Удалить выбранные');
  deleteBtn.type = 'button';
  deleteBtn.id = 'delete-selected-btn';
  deleteBtn.disabled = true;
  deleteBtn.addEventListener('click', deleteSelected);
  toolbar.appendChild(deleteBtn);

  const selectionInfo = el('span', 'report-selection', 'Выбрано: 0');
  selectionInfo.id = 'report-selection';
  toolbar.appendChild(selectionInfo);

  wrap.appendChild(toolbar);

  // --- таблица -----------------------------------------------------------
  const tableHost = el('div', 'report-table-host');
  tableHost.id = 'report-table-host';
  wrap.appendChild(tableHost);

  // --- журнал операций ---------------------------------------------------
  const logBox = el('div', 'op-log');
  logBox.appendChild(el('div', 'op-log-title', 'Журнал операций'));
  const logList = el('ul', 'op-log-list');
  logList.id = 'op-log-list';
  reportView.logEntries.forEach((entry) => {
    logList.appendChild(el('li', `op-log-item op-log-${entry.kind || 'info'}`, entry.text));
  });
  logBox.appendChild(logList);
  wrap.appendChild(logBox);

  contentEl.appendChild(wrap);
  renderReportTable();
}

function updateSelectionUi() {
  const info = document.getElementById('report-selection');
  const btn = document.getElementById('delete-selected-btn');
  if (info) info.textContent = `Выбрано: ${reportView.selected.size}`;
  if (btn) btn.disabled = reportView.selected.size === 0 || !state.device;
}

function renderReportTable() {
  const host = document.getElementById('report-table-host');
  if (!host) return;
  host.innerHTML = '';

  const rows = visiblePackages();

  const table = el('table', 'scan-table report-table');
  const thead = el('thead');
  const headRow = el('tr');

  const checkAllCell = el('th', 'col-check');
  const checkAll = el('input');
  checkAll.type = 'checkbox';
  checkAll.title = 'Выбрать все показанные';
  checkAll.checked = rows.length > 0 && rows.every((pkg) => reportView.selected.has(pkg.package));
  checkAll.addEventListener('change', () => {
    rows.forEach((pkg) => {
      if (checkAll.checked) reportView.selected.add(pkg.package);
      else reportView.selected.delete(pkg.package);
    });
    renderReportTable();
  });
  checkAllCell.appendChild(checkAll);
  headRow.appendChild(checkAllCell);

  REPORT_COLUMNS.forEach((column) => {
    const th = el('th', 'sortable');
    const active = reportView.sortKey === column.key;
    th.textContent = column.title + (active ? (reportView.sortAsc ? ' ▲' : ' ▼') : '');
    if (active) th.classList.add('sorted');
    th.addEventListener('click', () => {
      if (reportView.sortKey === column.key) {
        reportView.sortAsc = !reportView.sortAsc;
      } else {
        reportView.sortKey = column.key;
        reportView.sortAsc = column.key === 'package' || column.key === 'installer';
      }
      renderReportTable();
    });
    headRow.appendChild(th);
  });

  thead.appendChild(headRow);
  table.appendChild(thead);

  const tbody = el('tbody');
  rows.forEach((pkg) => {
    const row = el('tr', `risk-row-${pkg.risk}`);

    const checkCell = el('td', 'col-check');
    const checkbox = el('input');
    checkbox.type = 'checkbox';
    checkbox.checked = reportView.selected.has(pkg.package);
    checkbox.addEventListener('change', () => {
      if (checkbox.checked) reportView.selected.add(pkg.package);
      else reportView.selected.delete(pkg.package);
      updateSelectionUi();
    });
    checkCell.appendChild(checkbox);
    row.appendChild(checkCell);

    const nameCell = el('td', null, pkg.title ? `${pkg.title} (${pkg.package})` : pkg.package);
    if (pkg.reason) nameCell.title = pkg.reason;
    row.appendChild(nameCell);

    row.appendChild(el('td', null, pkg.installer || '—'));
    row.appendChild(el('td', null, String(pkg.permission_count)));
    row.appendChild(el('td', null, pkg.score === null ? '—' : String(pkg.score)));

    row.appendChild(el('td', pkg.db_match ? 'db-hit' : 'muted', pkg.db_match || '—'));
    row.appendChild(el('td', pkg.control_text ? 'control-hit' : 'muted', pkg.control_text || '—'));

    const riskCell = el('td');
    riskCell.appendChild(el('span', `risk risk-${pkg.risk}`, RISK_LABELS[pkg.risk] || pkg.risk));
    row.appendChild(riskCell);

    row.appendChild(
      el('td', 'muted', VERDICT_SOURCE_LABELS[pkg.verdict_source] || pkg.verdict_source)
    );

    tbody.appendChild(row);
  });
  table.appendChild(tbody);

  if (rows.length === 0) {
    host.appendChild(el('div', 'content-placeholder', 'Под фильтр ничего не попало.'));
  } else {
    host.appendChild(table);
  }

  updateSelectionUi();
}

async function deleteSelected() {
  const packages = Array.from(reportView.selected);
  if (packages.length === 0 || !state.device) return;

  const btn = document.getElementById('delete-selected-btn');
  if (btn) btn.disabled = true;
  setStatus('Удаление приложений...');

  const stopProgress = window.mcpGuard.onUninstallProgress((entry) => {
    if (entry.step) {
      appendLog(`${entry.package}: ${entry.step}`, 'info');
      return;
    }
    if (entry.ok) {
      appendLog(`Удалено: ${entry.package}`, 'ok');
      reportView.selected.delete(entry.package);
      // И из списка скана — иначе повторная проверка вернёт его снова.
      if (state.packages) state.packages = state.packages.filter((pkg) => pkg.package !== entry.package);
      if (state.report) {
        state.report.packages = state.report.packages.filter(
          (pkg) => pkg.package !== entry.package
        );
      }
    } else {
      appendLog(`Ошибка ${entry.package}: ${entry.error}`, 'error');
    }
  });

  const result = await window.mcpGuard.uninstallPackages(state.device.serial, packages);
  stopProgress();

  if (!result.ok) {
    if (result.cancelled) {
      appendLog('Удаление отменено пользователем.', 'info');
      setStatus('Удаление отменено');
    } else {
      appendLog(`Не удалось начать удаление: ${result.error}`, 'error');
      setStatus('Ошибка удаления');
    }
    updateSelectionUi();
    return;
  }

  const failed = result.results.filter((entry) => !entry.ok).length;
  const removed = result.results.length - failed;
  appendLog(`Готово: удалено ${removed}, ошибок ${failed}.`, failed ? 'error' : 'ok');
  setStatus(`Удалено приложений: ${removed}`);

  renderReportTable();
}

// ---------------------------------------------------------- итог (фаза 15)
// Главный экран после проверки: группы «что сделать» и одна кнопка.

const KEEP_KEY = 'mcpguard.keep';
const keepSet = new Set(JSON.parse(localStorage.getItem(KEEP_KEY) || '[]'));
function saveKeep() {
  localStorage.setItem(KEEP_KEY, JSON.stringify([...keepSet]));
}

const GROUPS = [
  { key: 'danger', title: 'Опасное — удалить', action: 'remove', checked: true },
  { key: 'junk', title: 'Мусор и скам-игры — удалить', action: 'remove', checked: true },
  { key: 'ads', title: 'Реклама в системе — отключить', action: 'disable', checked: true },
  { key: 'bg', title: 'Сажают батарею в фоне — ограничить фон', action: 'restrict', checked: true },
  { key: 'tune', title: 'Ускорить и убрать рекламу', action: null, checked: null },
  { key: 'check', title: 'Проверьте сами', action: 'remove', checked: false },
  { key: 'bloat', title: 'Лишнее от производителя — можно отключить', action: 'disable', checked: false, folded: true },
  { key: 'ok', title: 'Нормальные приложения', action: 'remove', checked: false, folded: true },
];

const summary = { picked: new Map() }; // package -> {package, label, action}

function summaryItems(report) {
  const byGroup = Object.fromEntries(GROUPS.map((g) => [g.key, []]));
  const titles = new Map(report.packages.map((p) => [p.package, p.title || p.package]));
  const adPkgs = new Set((state.tidy?.ads || []).map((a) => a.package));
  for (const p of report.packages) {
    if (adPkgs.has(p.package) && p.category !== 'danger') continue;
    const group = keepSet.has(p.package) && p.category !== 'danger' ? 'ok' : p.category || 'ok';
    byGroup[group].push({ package: p.package, label: p.title || p.package, reason: p.reason || '' });
  }
  for (const a of state.tidy?.ads || []) {
    if (keepSet.has(a.package)) continue;
    byGroup.ads.push({
      package: a.package,
      label: a.label,
      reason: 'Показывает рекламу и собирает статистику. Можно вернуть в «Журнале».',
    });
  }
  const removing = new Set([...byGroup.danger, ...byGroup.junk].map((i) => i.package));
  for (const h of state.tidy?.hogs || []) {
    if (keepSet.has(h.package) || removing.has(h.package)) continue;
    byGroup.bg.push({
      package: h.package,
      label: titles.get(h.package) || h.package,
      reason:
        [
          h.wakeups ? `Будило телефон ${h.wakeups} раз с последней зарядки` : '',
          h.notifications ? `${h.notifications} уведомлений висят в шторке` : '',
          h.autostart ? 'запускается при включении телефона' : '',
        ].filter(Boolean).join(', ') + '. Ограничим работу в фоне, приложение останется.',
    });
  }
  for (const b of state.tidy?.bloat || []) {
    if (keepSet.has(b.package)) continue;
    byGroup.bloat.push({
      package: b.package,
      label: b.package,
      reason: `Предустановлено ${b.list === 'Carrier' ? 'оператором' : 'производителем'}; по спискам UAD отключается без последствий. Вернуть можно в «Журнале».`,
    });
  }
  // Действия для всего телефона, не для конкретного приложения.
  byGroup.tune.push({
    package: '_cache',
    label: 'Очистить кеш приложений',
    action: 'cache',
    checked: true,
    reason: 'Освободит место; приложения пересоздадут кеш сами. Данные и входы не трогаем.',
  });
  const dns = state.tidy?.dns;
  if (dns && !dns.blocking) {
    byGroup.tune.push({
      package: '_dns',
      label: 'Включить DNS без рекламы (AdGuard)',
      action: 'dns',
      checked: false,
      reason:
        'Системная настройка «Приватный DNS» — реклама и трекеры перестанут открываться во всех приложениях и браузерах. ' +
        'Может мешать отдельным сайтам и Wi-Fi с входом по странице; вернуть — в «Журнале».',
    });
  }
  return byGroup;
}

function renderReport(report) {
  setActiveSidebar('report');
  clearContent();
  const byGroup = summaryItems(report);
  summary.picked.clear();

  const wrap = el('div', 'report-view summary-view');
  const head = el('div', 'report-head');
  const todo = ['danger', 'junk', 'ads', 'bg'].reduce((n, k) => n + byGroup[k].length, 0);
  const dnsOn = state.tidy?.dns?.blocking;
  head.appendChild(
    el('div', 'report-title', todo
      ? `Найдено, что поправить: ${todo}`
      : 'Телефон в порядке — опасного и мусора не найдено')
  );
  head.appendChild(
    el('div', 'report-mode', `Проверено приложений: ${report.package_count}${dnsOn ? ' · DNS без рекламы включён' : ''}`)
  );
  head.appendChild(el('div', 'report-disclaimer', report.disclaimer));
  for (const w of report.device_warnings || []) head.appendChild(el('div', 'report-warning', w));
  wrap.appendChild(head);

  const toolbar = el('div', 'report-toolbar');
  const fixBtn = el('button', 'topbar-btn danger', 'Привести телефон в порядок');
  fixBtn.type = 'button';
  fixBtn.id = 'fix-btn';
  fixBtn.addEventListener('click', applyTidy);
  toolbar.appendChild(fixBtn);
  const info = el('span', 'report-selection');
  toolbar.appendChild(info);
  const detail = el('button', 'topbar-btn', 'Подробно');
  detail.type = 'button';
  detail.addEventListener('click', () => renderReportDetail(report));
  toolbar.appendChild(detail);
  wrap.appendChild(toolbar);

  const updateInfo = () => {
    info.textContent = `Выбрано: ${summary.picked.size}`;
    fixBtn.disabled = summary.picked.size === 0 || !state.device;
  };

  for (const g of GROUPS) {
    const items = byGroup[g.key];
    if (!items.length) continue;
    const box = el('details', `sum-group sum-${g.key}`);
    box.open = !g.folded;
    box.appendChild(el('summary', 'sum-title', `${g.title} · ${items.length}`));
    for (const item of items) {
      const row = el('label', 'sum-row');
      const cb = el('input');
      cb.type = 'checkbox';
      const pick = { package: item.package, label: item.label, action: item.action || g.action };
      cb.checked = typeof item.checked === 'boolean' ? item.checked : g.checked;
      if (cb.checked) summary.picked.set(item.package, pick);
      cb.addEventListener('change', () => {
        if (cb.checked) summary.picked.set(item.package, pick);
        else summary.picked.delete(item.package);
        updateInfo();
      });
      row.appendChild(cb);
      const text = el('div', 'sum-text');
      text.appendChild(
        el('div', 'sum-name', item.label === item.package || item.package.startsWith('_') ? item.label : `${item.label} · ${item.package}`)
      );
      if (item.reason) text.appendChild(el('div', 'sum-reason', item.reason));
      row.appendChild(text);
      if (g.key !== 'ok' && g.key !== 'danger' && g.key !== 'tune') {
        const keep = el('button', 'sum-keep', 'Оставить');
        keep.type = 'button';
        keep.addEventListener('click', (e) => {
          e.preventDefault();
          keepSet.add(item.package);
          saveKeep();
          renderReport(report);
        });
        row.appendChild(keep);
      }
      box.appendChild(row);
    }
    wrap.appendChild(box);
  }

  const logBox = el('div', 'op-log');
  logBox.appendChild(el('div', 'op-log-title', 'Журнал операций'));
  const logList = el('ul', 'op-log-list');
  logList.id = 'op-log-list';
  reportView.logEntries.forEach((entry) => {
    logList.appendChild(el('li', `op-log-item op-log-${entry.kind || 'info'}`, entry.text));
  });
  logBox.appendChild(logList);
  wrap.appendChild(logBox);

  contentEl.appendChild(wrap);
  updateInfo();
}

const ACTION_DONE = { remove: 'Удалено', disable: 'Отключено', restrict: 'Фон ограничен', cache: 'Кеш очищен', dns: 'DNS без рекламы включён' };

async function applyTidy() {
  const items = [...summary.picked.values()];
  if (!items.length || !state.device) return;
  document.getElementById('fix-btn').disabled = true;
  setStatus('Приводим телефон в порядок...');
  const stop = window.mcpGuard.onUninstallProgress((entry) => {
    const name = entry.label || entry.package;
    if (entry.step) appendLog(`${name}: ${entry.step}`, 'info');
    else if (entry.ok) appendLog(`${ACTION_DONE[entry.action] || 'Готово'}: ${name}`, 'ok');
    else appendLog(`Не вышло (${name}): ${entry.error}`, 'error');
  });
  const result = await window.mcpGuard.tidyApply(state.device.serial, items);
  stop();
  if (!result.ok) {
    appendLog(result.cancelled ? 'Отменено.' : `Ошибка: ${result.error}`, result.cancelled ? 'info' : 'error');
    document.getElementById('fix-btn').disabled = false;
    return;
  }
  const done = result.results.filter((r) => r.ok);
  const gone = new Set(done.filter((r) => r.action === 'remove').map((r) => r.package));
  state.report.packages = state.report.packages.filter((p) => !gone.has(p.package));
  if (state.packages) state.packages = state.packages.filter((p) => !gone.has(p.package));
  const handled = new Set(done.map((r) => r.package));
  if (state.tidy) {
    state.tidy.ads = state.tidy.ads.filter((a) => !handled.has(a.package));
    state.tidy.hogs = state.tidy.hogs.filter((h) => !handled.has(h.package));
    state.tidy.bloat = (state.tidy.bloat || []).filter((b) => !handled.has(b.package));
    if (handled.has('_dns') && state.tidy.dns) state.tidy.dns.blocking = true;
  }
  appendLog(
    `Готово: ${done.length} из ${result.results.length}. Отключённое можно вернуть в «Журнале».`,
    done.length === result.results.length ? 'ok' : 'error'
  );
  setStatus(`Сделано: ${done.length}`);
  renderReport(state.report);
}

async function loadTidy() {
  if (!state.device || !state.packages) return;
  const res = await window.mcpGuard.tidyFind(
    state.device.serial,
    state.packages.map((p) => ({
      package: p.package,
      autostart: (p.permissions || []).includes('android.permission.RECEIVE_BOOT_COMPLETED'),
    }))
  );
  state.tidy = res.ok
    ? { ads: res.ads, bloat: res.bloat || [], hogs: res.hogs, dns: res.dns || null }
    : { ads: [], bloat: [], hogs: [], dns: null };
}

const ACTION_TITLE = { remove: 'удалено', disable: 'отключено', restrict: 'фон ограничен', cache: 'кеш очищен', dns: 'DNS без рекламы включён' };

async function renderJournal() {
  setActiveSidebar('journal');
  clearContent();
  const wrap = el('div', 'report-view');
  const head = el('div', 'report-head');
  head.appendChild(el('div', 'report-title', 'Журнал: что программа сделала с телефоном'));
  wrap.appendChild(head);
  const { journal } = await window.mcpGuard.tidyJournal();
  if (!journal.length) wrap.appendChild(el('div', 'content-placeholder', 'Пока ничего не делали.'));
  for (const entry of journal) {
    const row = el('div', 'sum-row');
    const text = el('div', 'sum-text');
    const what = ACTION_TITLE[entry.action] || entry.action;
    text.appendChild(
      el('div', 'sum-name', `${entry.label || entry.package} — ${what}${entry.undone && entry.action !== 'cache' ? ' (возвращено)' : ''}`)
    );
    text.appendChild(el('div', 'sum-reason', new Date(entry.ts).toLocaleString('ru-RU')));
    row.appendChild(text);
    if (!entry.undone && (entry.action !== 'remove' || entry.backup)) {
      const btn = el('button', 'sum-keep', 'Вернуть как было');
      btn.type = 'button';
      btn.disabled = !state.device;
      btn.addEventListener('click', async () => {
        btn.disabled = true;
        const res = await window.mcpGuard.tidyUndo(state.device.serial, entry.ts);
        setStatus(res.ok ? `Возвращено: ${entry.label || entry.package}` : `Не вышло: ${res.error}`);
        renderJournal();
      });
      row.appendChild(btn);
    }
    wrap.appendChild(row);
  }
  contentEl.appendChild(wrap);
}

// ----------------------------------------------------------------- настройки

async function renderSettings() {
  setActiveSidebar('settings');
  clearContent();

  const result = await window.mcpGuard.getConfig();
  const cfg = result.ok ? result.config : { backendUrl: '', tokenMasked: '', configPath: '' };

  const wrap = el('div', 'settings-view');
  wrap.appendChild(el('h2', null, 'Настройки'));
  wrap.appendChild(
    el(
      'p',
      'settings-hint',
      'Проверка идёт на этом компьютере, без интернета. Сервер нужен только за карточками ' +
        'Google Play (название, издатель, число скачиваний) — без него отчёт тоже будет. ' +
        'Токен программа получает сама; код подключения нужен только владельцу сервера.'
    )
  );

  const urlLabel = el('label', 'settings-field');
  urlLabel.appendChild(el('span', null, 'Адрес сервера'));
  const urlInput = el('input');
  urlInput.type = 'text';
  urlInput.placeholder = 'https://example.org:8446';
  urlInput.value = cfg.backendUrl || '';
  urlLabel.appendChild(urlInput);
  wrap.appendChild(urlLabel);

  const tokenLabel = el('label', 'settings-field');
  tokenLabel.appendChild(el('span', null, 'Токен доступа (необязательно)'));
  const tokenInput = el('input');
  tokenInput.type = 'password';
  tokenInput.placeholder = cfg.tokenMasked
    ? `сохранён: ${cfg.tokenMasked} — оставьте пустым, чтобы не менять`
    : 'появится сам после первой проверки';
  tokenLabel.appendChild(tokenInput);
  wrap.appendChild(tokenLabel);

  // Быстрое подключение нового ПК: 6-значный код вместо длинного токена.
  const pairLabel = el('label', 'settings-field');
  pairLabel.appendChild(el('span', null, 'Код подключения (6 цифр) — вместо токена'));
  const pairRow = el('div', 'settings-actions');
  const pairInput = el('input');
  pairInput.type = 'text';
  pairInput.inputMode = 'numeric';
  pairInput.maxLength = 6;
  pairInput.placeholder = '123456';
  const pairBtn = el('button', 'topbar-btn', 'Подключить');
  pairBtn.type = 'button';
  pairRow.appendChild(pairInput);
  pairRow.appendChild(pairBtn);
  pairLabel.appendChild(pairRow);
  wrap.appendChild(pairLabel);

  const actions = el('div', 'settings-actions');
  const saveBtn = el('button', 'topbar-btn', 'Сохранить');
  saveBtn.type = 'button';
  const checkBtn = el('button', 'topbar-btn', 'Проверить соединение');
  checkBtn.type = 'button';
  actions.appendChild(saveBtn);
  actions.appendChild(checkBtn);
  wrap.appendChild(actions);

  const resultLine = el('div', 'settings-result');
  wrap.appendChild(resultLine);

  if (cfg.configPath) {
    wrap.appendChild(el('p', 'settings-hint', `Файл конфигурации: ${cfg.configPath}`));
  }

  saveBtn.addEventListener('click', async () => {
    saveBtn.disabled = true;
    const saved = await window.mcpGuard.setConfig({
      backendUrl: urlInput.value,
      apiToken: tokenInput.value,
    });
    saveBtn.disabled = false;
    if (!saved.ok) {
      resultLine.textContent = `Не удалось сохранить: ${saved.error}`;
      return;
    }
    tokenInput.value = '';
    tokenInput.placeholder = saved.config.tokenMasked
      ? `сохранён: ${saved.config.tokenMasked} — оставьте пустым, чтобы не менять`
      : 'вставьте токен';
    resultLine.textContent = 'Сохранено.';
    setStatus('Настройки сохранены');
  });

  pairBtn.addEventListener('click', async () => {
    pairBtn.disabled = true;
    resultLine.textContent = 'Подключаемся...';
    // Сначала сохраняем адрес, чтобы код ушёл на правильный сервер.
    await window.mcpGuard.setConfig({ backendUrl: urlInput.value });
    const paired = await window.mcpGuard.pairBackend(pairInput.value);
    pairBtn.disabled = false;
    if (!paired.ok) {
      resultLine.textContent = `Не удалось подключиться: ${paired.error}`;
      return;
    }
    pairInput.value = '';
    tokenInput.placeholder = `сохранён: ${paired.config.tokenMasked} — оставьте пустым, чтобы не менять`;
    resultLine.textContent = 'Подключено: токен получен и сохранён. Можно запускать анализ.';
    setStatus('Backend подключён');
  });

  checkBtn.addEventListener('click', async () => {
    checkBtn.disabled = true;
    resultLine.textContent = 'Проверяем...';
    const check = await window.mcpGuard.checkBackend();
    checkBtn.disabled = false;
    if (!check.ok) {
      resultLine.textContent = `Ошибка: ${check.error}`;
      setStatus('Backend недоступен');
      return;
    }
    const info = check.info;
    resultLine.textContent =
      `Соединение и токен в порядке. Сервис: ${info.service} ${info.version}.`;
    setStatus('Backend доступен');
  });

  contentEl.appendChild(wrap);
}

// ------------------------------------------------------------------ действия

connectBtn.addEventListener('click', refreshDevices);
settingsBtn.addEventListener('click', renderSettings);

document.querySelectorAll('.sidebar-item[data-view]').forEach((item) => {
  item.addEventListener('click', () => {
    const { view } = item.dataset;
    if (view === 'settings') renderSettings();
    else if (view === 'report' && state.report) renderReport(state.report);
    else if (view === 'journal') renderJournal();
    else if (view === 'packages' && state.packages) renderScanTable(state.packages);
  });
});

// ------------------------------------------------------------ экран прогресса
// Финальный вариант владельца: терминальная рамка с ASCII-полосами поверх
// падающего кода «Матрицы» с Нео (matrix.js).

const BAR = 28;
const progressView = { root: null, phone: { done: 0, total: 0 }, startedAt: 0, finishing: false, db: null };

function formatEta(seconds) {
  if (!Number.isFinite(seconds) || seconds <= 0) return 'меньше минуты';
  if (seconds < 60) return `${Math.max(5, Math.round(seconds / 5) * 5)} с`;
  return `${Math.round(seconds / 60)} мин`;
}

function estimateEta() {
  const { phone, startedAt } = progressView;
  if (!phone.total || !phone.done) return null;
  const elapsed = (Date.now() - startedAt) / 1000;
  return ((phone.total - phone.done) * elapsed) / phone.done;
}

// «$ телефон ██████░░░░ 55/77 71%»
function termBar(label, done, total) {
  const share = total ? Math.min(1, done / total) : 0;
  const on = Math.round(share * BAR);
  const row = el('div', 'l', `$ ${label.padEnd(8)} `);
  row.appendChild(el('span', 'blk', '█'.repeat(on)));
  row.appendChild(el('span', 'dim', '░'.repeat(BAR - on)));
  row.appendChild(document.createTextNode(` ${total ? `${done}/${total}` : '—'} `));
  row.appendChild(el('span', 'ok', `${Math.round(share * 100)}%`));
  return row;
}

function renderProgress() {
  const { phone, finishing, db } = progressView;
  const root = progressView.root;
  if (!root) return;
  root.innerHTML = '';

  root.appendChild(el('div', 'ptitle', 'Проверяем телефон'));
  const model = state.device?.model || 'Телефон';
  const eta = estimateEta();
  root.appendChild(
    el(
      'div',
      'psub',
      `${model} · ${phone.total ? `${phone.total} приложений` : 'считаем приложения...'} · осталось примерно ${
        eta === null ? '…' : formatEta(eta)
      }`
    )
  );

  const term = el('div', 'term');
  term.appendChild(termBar('телефон', phone.done, phone.total));

  const dbLine = el('div', 'l', '$ базы угроз: ');
  dbLine.appendChild(
    el('span', 'ok', db ? `${db.hashes} хешей, ${db.packages} пакетов, на компьютере` : 'на компьютере')
  );
  term.appendChild(dbLine);

  const stepLine = el('div', 'l', `$ ${finishing ? 'сводим отчёт…' : 'читаем разрешения, права, рекламные SDK…'}`);
  stepLine.appendChild(el('span', 'caret'));
  term.appendChild(stepLine);
  root.appendChild(term);
}

function openProgressView() {
  Object.assign(progressView, {
    root: openMatrixFrame(),
    phone: { done: 0, total: 0 },
    startedAt: Date.now(),
    finishing: false,
  });
  renderProgress();
  if (!progressView.db) {
    window.mcpGuard.rulesInfo().then((r) => {
      if (r.ok) {
        progressView.db = r.info;
        renderProgress();
      }
    });
  }
}

scanBtn.addEventListener('click', async () => {
  if (!state.device) return;

  scanBtn.disabled = true;
  connectBtn.disabled = true;
  openProgressView();

  const stopProgress = window.mcpGuard.onScanProgress(({ package: pkg, done, total, phase }) => {
    if (phase === 'finishing') {
      progressView.phone = { done: total, total };
      progressView.finishing = true;
      setStatus(`Телефон прочитан (${total}). Сводим отчёт...`);
      renderProgress();
      return;
    }
    progressView.phone = { done, total };
    setStatus(`Сканирование: ${done}/${total} — ${pkg}`);
    renderProgress();
  });

  const startedAt = Date.now();
  const result = await window.mcpGuard.scanDevice(state.device.serial, state.device);

  stopProgress();
  progressView.root = null;
  scanBtn.disabled = false;
  connectBtn.disabled = false;

  if (!result.ok) {
    setStatus('Ошибка сканирования');
    renderPlaceholder(`Ошибка сканирования: ${result.error}`);
    return;
  }

  state.packages = result.packages;
  const seconds = Math.round((Date.now() - startedAt) / 1000);
  state.report = result.report;
  reportView.selected.clear();
  appendLog(`Проверено ${result.packages.length} приложений за ${seconds} с.`, 'info');
  setStatus(`Отчёт готов за ${seconds} с`);
  await loadTidy();
  renderReport(result.report);
});

// Автообновление: показываем в строке состояния, что идёт скачивание.
window.mcpGuard.onUpdateStatus(({ state: updateState, version }) => {
  if (updateState === 'downloading') setStatus(`Скачивается обновление ${version}...`);
  if (updateState === 'ready') setStatus(`Обновление ${version} готово к установке`);
});
