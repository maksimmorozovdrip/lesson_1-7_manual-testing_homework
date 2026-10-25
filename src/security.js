import { PREFIX } from './api.js';

export const CANARY_KEY = `${PREFIX}canary`;
const LOG_KEY = `${PREFIX}incidents`;
const RESTRICTION_KEY = `${PREFIX}restriction`;
const LOG_LIMIT = 30;
const RESTRICTION_MS = 30000;

const ALLOWED_TOPICS = ['html', 'javascript', 'api'];
const REFRESH_WINDOW_MS = 5000;
const REFRESH_LIMIT = 6;

let incidents = [];
let refreshTimes = [];
let blockedUntil = 0;
let blockReason = '';
let timerId = null;

// localStorage может быть недоступен или подменён: ошибки не должны ломать приложение.
function readJson(key) {
  try {
    const raw = localStorage.getItem(key);
    return raw === null ? null : JSON.parse(raw);
  } catch {
    return null;
  }
}

function writeJson(key, value) {
  try { localStorage.setItem(key, JSON.stringify(value)); } catch { /* работаем в памяти */ }
}

function removeKey(key) {
  try { localStorage.removeItem(key); } catch { /* нечего удалять */ }
}

// ---------- Журнал ----------

function isValidEntry(item) {
  return item && typeof item === 'object' && Number.isFinite(item.time)
    && typeof item.type === 'string' && typeof item.reason === 'string';
}

function loadLog() {
  const value = readJson(LOG_KEY);
  incidents = Array.isArray(value) ? value.filter(isValidEntry).slice(-LOG_LIMIT) : [];
}

function renderLog() {
  const list = document.querySelector('#incident-list');
  const items = [...incidents].reverse().map(entry => {
    const item = document.createElement('li');
    const time = new Date(entry.time).toLocaleString('ru-RU');
    item.textContent = `${time} · ${entry.type}: ${entry.reason}`;
    return item;
  });
  list.replaceChildren(...items);
  document.querySelector('#incidents-empty').hidden = incidents.length > 0;
  document.querySelector('#incident-count').textContent = String(incidents.length);
}

// В журнал попадают только время, тип и причина — без содержимого формы.
export function reportIncident(type, reason) {
  incidents = [...incidents, { time: Date.now(), type, reason }].slice(-LOG_LIMIT);
  writeJson(LOG_KEY, incidents);
  renderLog();
  startRestriction(reason);
}

// ---------- Временное ограничение ----------

function setActionButtonsDisabled(disabled) {
  for (const id of ['#submit-button', '#refresh-button']) {
    document.querySelector(id).disabled = disabled;
  }
}

function renderRestriction() {
  const status = document.querySelector('#security-status');
  const detail = document.querySelector('#restriction-detail');
  if (!isRestricted()) {
    status.textContent = 'Ограничений нет';
    detail.hidden = true;
    return;
  }
  const seconds = Math.ceil((blockedUntil - Date.now()) / 1000);
  status.textContent = `Отправка и обновление недоступны: ${seconds} с`;
  detail.textContent = `Причина: ${blockReason}. Чтение заявок доступно.`;
  detail.hidden = false;
}

function finishRestriction() {
  clearInterval(timerId);
  timerId = null;
  blockedUntil = 0;
  blockReason = '';
  removeKey(RESTRICTION_KEY);
  setActionButtonsDisabled(false);
  renderRestriction();
}

function tick() {
  if (!isRestricted()) { finishRestriction(); return; }
  // Кнопки дублируют ограничение визуально; главная проверка — isRestricted() в обработчиках.
  setActionButtonsDisabled(true);
  renderRestriction();
}

function runTimer() {
  clearInterval(timerId);
  timerId = setInterval(tick, 1000);
  tick();
}

// Новые инциденты во время паузы попадают в журнал, но не продлевают её.
function startRestriction(reason) {
  if (isRestricted()) return;
  blockedUntil = Date.now() + RESTRICTION_MS;
  blockReason = reason;
  writeJson(RESTRICTION_KEY, { blockedUntil, reason });
  runTimer();
}

function restoreRestriction() {
  const saved = readJson(RESTRICTION_KEY);
  const until = saved && Number(saved.blockedUntil);
  // Время окончания не может быть дальше полной паузы: защищает от подмены огромного значения.
  if (Number.isFinite(until) && until > Date.now() && until <= Date.now() + RESTRICTION_MS) {
    blockedUntil = until;
    blockReason = typeof saved.reason === 'string' ? saved.reason : 'инцидент';
    runTimer();
  } else {
    removeKey(RESTRICTION_KEY);
  }
}

// Приложение вызывает эту функцию перед отправкой и обновлением списка.
export function isRestricted() {
  return blockedUntil > Date.now();
}

// ---------- Ловушки ----------

// T5: повреждённая или отсутствующая запись не считается атакой.
function readCanaryRole() {
  const value = readJson(CANARY_KEY);
  return value && typeof value === 'object' ? value.role : null;
}

// Сигналы при загрузке обрабатываются один раз: маркер и адрес возвращаются в обычное состояние.
function checkStartup() {
  if (readCanaryRole() === 'admin') {
    writeJson(CANARY_KEY, { role: 'visitor' });
    reportIncident('canary', 'Маркер посетителя изменён на role: "admin"');
  }
  const url = new URL(location.href);
  if (url.searchParams.get('staff') === '1') {
    url.searchParams.delete('staff');
    history.replaceState(history.state, '', url);
    reportIncident('url', 'Адрес открыт с параметром staff=1');
  }
}

// T1: скользящее окно — считаем только попытки за последние 5 секунд.
function checkRefresh() {
  const now = Date.now();
  refreshTimes = refreshTimes.filter(time => now - time < REFRESH_WINDOW_MS);
  refreshTimes.push(now);
  if (refreshTimes.length >= REFRESH_LIMIT) {
    refreshTimes = [];
    reportIncident('refresh', `${REFRESH_LIMIT} обновлений списка за 5 секунд`);
  }
}

function checkSubmit({ topic = '', supportCode = '' }) {
  if (supportCode !== '') reportIncident('honeypot', 'Заполнено скрытое поле supportCode');
  // Пустой выбор — обычная ошибка ввода, её покажет проверка формы.
  if (topic !== '' && !ALLOWED_TOPICS.includes(topic)) {
    reportIncident('topic', 'Получено направление вне списка');
  }
}

// События: startup, refresh, submit, decoy.
export function checkActivity(action, details = {}) {
  if (action === 'startup') checkStartup();
  else if (action === 'refresh') checkRefresh();
  else if (action === 'submit') checkSubmit(details);
  else if (action === 'decoy') reportIncident('decoy', 'Нажата скрытая кнопка staff-export');
}

// ---------- Запуск и сброс ----------

export function initializeSecurity() {
  loadLog();
  renderLog();
  restoreRestriction();
  try {
    if (localStorage.getItem(CANARY_KEY) === null) {
      localStorage.setItem(CANARY_KEY, JSON.stringify({ role: 'visitor' }));
    }
  } catch { /* без storage маркер не проверяется */ }
  checkActivity('startup');
}

export function resetSecurity() {
  clearInterval(timerId);
  timerId = null;
  blockedUntil = 0;
  blockReason = '';
  incidents = [];
  refreshTimes = [];
  try {
    for (const key of Object.keys(localStorage)) {
      if (key.startsWith(PREFIX) && key !== `${PREFIX}applications`) localStorage.removeItem(key);
    }
    localStorage.setItem(CANARY_KEY, JSON.stringify({ role: 'visitor' }));
  } catch { /* Учебный сброс остаётся доступным без storage. */ }
  setActionButtonsDisabled(false);
  renderLog();
  renderRestriction();
}
