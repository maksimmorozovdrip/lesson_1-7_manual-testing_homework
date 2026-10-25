import { PREFIX } from './api.js';

export const CANARY_KEY = `${PREFIX}canary`;

// Временный вывод для проверки ловушек. Постоянный журнал добавляется в бонусе.
export function reportIncident(type, reason) {
  const list = document.querySelector('#incident-list');
  const item = document.createElement('li');
  item.textContent = `${type}: ${reason}`;
  list.prepend(item);
  document.querySelector('#incidents-empty').hidden = true;
  document.querySelector('#incident-count').textContent = String(list.children.length);
}

const ALLOWED_TOPICS = ['html', 'javascript', 'api'];
const REFRESH_WINDOW_MS = 5000;
const REFRESH_LIMIT = 6;
let refreshTimes = [];

// T5: повреждённая или отсутствующая запись не считается атакой.
function readCanaryRole() {
  try {
    const value = JSON.parse(localStorage.getItem(CANARY_KEY));
    return value && typeof value === 'object' ? value.role : null;
  } catch {
    return null;
  }
}

function checkStartup() {
  if (readCanaryRole() === 'admin') {
    reportIncident('canary', 'Маркер посетителя изменён на role: "admin"');
  }
  if (new URLSearchParams(location.search).get('staff') === '1') {
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

// Приложение вызывает эту функцию перед отправкой и обновлением списка.
export function isRestricted() {
  return false;
}

export function initializeSecurity() {
  try {
    if (localStorage.getItem(CANARY_KEY) === null) {
      localStorage.setItem(CANARY_KEY, JSON.stringify({ role: 'visitor' }));
    }
  } catch { /* Бонус должен учитывать недоступное хранилище. */ }
  checkActivity('startup');
}

export function resetSecurity() {
  refreshTimes = [];
  try {
    for (const key of Object.keys(localStorage)) {
      if (key.startsWith(PREFIX) && key !== `${PREFIX}applications`) localStorage.removeItem(key);
    }
    localStorage.setItem(CANARY_KEY, JSON.stringify({ role: 'visitor' }));
  } catch { /* Учебный сброс остаётся доступным без storage. */ }
  document.querySelector('#incident-list').replaceChildren();
  document.querySelector('#incident-count').textContent = '0';
  document.querySelector('#incidents-empty').hidden = false;
  document.querySelector('#security-status').textContent = 'Ограничений нет';
  document.querySelector('#restriction-detail').hidden = true;
}
