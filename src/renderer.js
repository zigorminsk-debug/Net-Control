'use strict';
const $ = id => document.getElementById(id);
const api = window.netControl;
let selectedHost = '';
let selectedCategory = '';
let selectedThreat = '';
let reviewHost = '';
let securityPolicy = null;
let reputationLoaded = false;
let reputationStatus = null;
let historyLoaded = false;
let lastHistory = null;
let manualLocal = false;
let detectRevision = 0;
let hostSort = { by: 'bytes', direction: 'desc' };
let refreshRevision = 0;
function switchView(view) {
  if (view !== 'host-detail') selectedHost = '';
  if (view !== 'category-detail') selectedCategory = '';
  if (view !== 'threat-detail') selectedThreat = '';
  document.querySelectorAll('.view').forEach(el => el.classList.toggle('active-view', el.id === view));
  document.querySelectorAll('.nav-item').forEach(el => el.classList.toggle('active', el.dataset.view === view));
  $('breadcrumb').textContent = view === 'flow-search' ? 'Поиск потоков' : view === 'dashboard' ? 'Обзор сети' : view === 'host-detail' ? 'Анализ хоста' : view === 'category-detail' ? 'Тип трафика' : view === 'threat-detail' ? 'Подозрительная активность' : view === 'about' ? 'О программе' : 'Подключение';
}
document.querySelectorAll('.nav-item').forEach(button => button.addEventListener('click', () => switchView(button.dataset.view)));
$('open-settings').addEventListener('click', () => switchView('settings'));
$('banner-action').addEventListener('click', () => switchView('settings'));
$('direction-settings').addEventListener('click', () => { switchView('settings'); $('subnets').focus(); });
$('history-settings').addEventListener('click', () => { switchView('settings'); document.querySelector('.policy-panel').open = true; $('history-enabled').focus(); });
$('update-top').addEventListener('click', () => switchView('about'));
function message(id, text, error = false) { const el = $(id); el.textContent = text; el.classList.toggle('error', error); }
function usableIPv4(value) {
  const parts = value.split('.');
  if (parts.length !== 4 || parts.some(p => !/^(0|[1-9]\d{0,2})$/.test(p) || Number(p) > 255)) return false;
  const first = Number(parts[0]);
  return first !== 0 && first !== 127 && first < 224;
}
function commands() {
  const n = Number($('flow-port').value); const port = Number.isInteger(n) && n > 0 && n <= 65535 ? n : 2055;
  const input = $('local-address').value.trim();
  const address = usableIPv4(input) ? input : 'IP_КОМПЬЮТЕРА';
  $('commands').textContent = `/ip traffic-flow set enabled=yes interfaces=all\n/ip traffic-flow target add dst-address=${address} port=${port} version=9`;
}
$('flow-port').addEventListener('input', commands);
$('local-address').addEventListener('input', () => { manualLocal = true; detectRevision++; commands(); message('local-status', usableIPv4($('local-address').value.trim()) ? 'Указан вручную. Проверьте доступность адреса с роутера.' : 'Укажите корректный IPv4, отличный от localhost.', !usableIPv4($('local-address').value.trim())); });
async function detectAddress(force = false) {
  const revision = ++detectRevision;
  const router = $('address').value.trim();
  message('local-status', 'Определяем адрес по маршруту…');
  try {
    const result = await api.localAddress(router);
    if (revision !== detectRevision || router !== $('address').value.trim()) return;
    const options = $('local-addresses'); options.replaceChildren();
    for (const item of result.interfaces) { const option = document.createElement('option'); option.value = item.address; option.label = item.name; options.appendChild(option); }
    if (result.address && (force || !manualLocal)) {
      $('local-address').value = result.address; manualLocal = false; commands();
      message('local-status', `Маршрут через ${result.interfaceName}. Проверьте доступность адреса с MikroTik.`);
    } else if (result.address) {
      message('local-status', 'Сохранён введённый вручную адрес. Проверьте его доступность с MikroTik.');
    } else {
      if (!manualLocal) { $('local-address').value = ''; commands(); }
      message('local-status', 'Не удалось определить маршрут. Выберите адрес интерфейса или введите его вручную.', true);
    }
  } catch { if (revision === detectRevision) message('local-status', 'Не удалось определить адрес. Укажите его вручную.', true); }
}
$('detect-address').addEventListener('click', () => detectAddress(true));
let routerTimer;
$('address').addEventListener('input', () => {
  detectRevision++; clearTimeout(routerTimer);
  if (!manualLocal) { $('local-address').value = ''; commands(); }
  message('local-status', 'Адрес роутера изменён. Проверяем маршрут…');
  routerTimer = setTimeout(() => detectAddress(false), 600);
});
commands(); detectAddress();
function updateProtocol() {
  const secure = $('secure').checked;
  $('api-port').value = window.connectionSettings.portAfterProtocolChange($('api-port').value, secure);
  $('self-signed').disabled = !secure;
  $('protocol-note').textContent = secure
    ? 'HTTPS использует службу www-ssl (обычно порт 443). Доверие самоподписанному сертификату небезопасно. Пароль не сохраняется.'
    : 'HTTP использует службу www (обычно порт 80) и передаёт пароль без шифрования. Используйте только в доверенной сети. Пароль не сохраняется.';
}
$('secure').addEventListener('change', updateProtocol);
updateProtocol();
$('test-router').addEventListener('click', async () => {
  const button = $('test-router'); button.disabled = true; message('router-message', 'Проверяем подключение…');
  try {
    const result = await api.testRouter({ address: $('address').value.trim(), port: $('api-port').value, username: $('username').value, password: $('password').value, secure: $('secure').checked, allowSelfSigned: $('secure').checked && $('self-signed').checked });
    if (!result.ok) throw new Error(result.error);
    const data = result.data;
    message('router-message', `Подключено: ${data.board} · RouterOS ${data.version} · uptime ${data.uptime}`);
  } catch (err) { message('router-message', `Не удалось проверить REST API: ${err.message} Сбор Traffic Flow работает независимо.`, true); }
  finally { button.disabled = false; }
});
$('inspect-flow').addEventListener('click', async () => {
  const button=$('inspect-flow'); button.disabled=true; message('router-message','Читаем настройки Traffic Flow…');
  try {
    const result=await api.inspectTrafficFlow({address:$('address').value.trim(),port:$('api-port').value,username:$('username').value,password:$('password').value,secure:$('secure').checked,allowSelfSigned:$('secure').checked && $('self-signed').checked});
    if (!result.ok) throw new Error(result.error);
    const d=result.data, targets=d.targets.map(t=>`${t.address}:${t.port} v${t.version}${t.disabled==='true' ? ' (отключён)' : ''}`).join('; ') || 'нет';
    message('router-message',`Traffic Flow: enabled=${d.enabled}, интерфейсы=${d.interfaces}; targets (до 100): ${targets}. Проверка только читает конфигурацию и не подтверждает доставку UDP.`);
  } catch (err) { message('router-message',`Не удалось прочитать Traffic Flow: ${err.message}`,true); }
  finally {button.disabled=false;}
});
$('read-leases').addEventListener('click', async () => {
  const button = $('read-leases'); button.disabled = true; message('router-message', 'Получаем текущие DHCP-аренды…');
  try {
    const result = await api.readLeases({ address: $('address').value.trim(), port: $('api-port').value, username: $('username').value, password: $('password').value, secure: $('secure').checked, allowSelfSigned: $('secure').checked && $('self-signed').checked });
    if (!result.ok) throw new Error(result.error);
    message('router-message', `Получено ${result.count} действующих аренд. Сведения действуют в приложении до 5 минут и не подтверждают владельца IP в прошлом.`);
  } catch (err) { message('router-message', `Не удалось получить DHCP-аренды: ${err.message}. Приём Traffic Flow работает независимо.`, true); }
  finally { button.disabled = false; }
});
function renderUpdate(state) {
  $('about-version').textContent = `Версия ${state.currentVersion}`;
  $('app-version').textContent = `NET CONTROL · V${state.currentVersion}`;
  const labels = {
    idle: 'Автоматическая проверка запланирована.', checking: 'Проверяем GitHub Releases…',
    'up-to-date': 'Установлена последняя доступная стабильная версия.',
    available: `Доступна версия ${state.availableVersion}. Подготовка загрузки…`,
    downloading: `Загружается версия ${state.availableVersion}: ${Math.round(state.progress)}%.`,
    downloaded: `Версия ${state.availableVersion} загружена и готова к установке.`,
    error: `Не удалось проверить или загрузить обновление: ${state.error}`,
    disabled: 'Автообновление доступно только в установленной Windows-версии, не в режиме разработки.'
  };
  $('update-status').textContent = labels[state.status] || 'Неизвестное состояние обновления.';
  $('update-status').classList.toggle('error', state.status === 'error');
  $('check-updates').disabled = ['disabled', 'checking', 'available', 'downloading', 'downloaded'].includes(state.status);
  $('install-update').hidden = state.status !== 'downloaded';
  $('update-top').hidden = state.status !== 'downloaded';
}
async function refreshUpdate() {
  try { renderUpdate(await api.updateStatus()); }
  catch (err) { message('update-status', `Не удалось получить состояние обновления: ${err.message}`, true); }
}
$('check-updates').addEventListener('click', async () => {
  $('check-updates').disabled = true;
  try { renderUpdate(await api.checkUpdates()); }
  catch (err) { message('update-status', `Ошибка проверки: ${err.message}`, true); }
});
$('install-update').addEventListener('click', async () => {
  $('install-update').disabled = true;
  try {
    const result = await api.installUpdate();
    if (!result.ok && !result.canceled) message('update-status', `Не удалось установить обновление: ${result.error}`, true);
  } catch (err) { message('update-status', `Не удалось установить обновление: ${err.message}`, true); }
  finally { $('install-update').disabled = false; }
});
refreshUpdate(); setInterval(refreshUpdate, 2000);
function renderReputation(state) {
  reputationStatus = state;
  if (!reputationLoaded) { $('reputation-enabled').checked = state.enabled; reputationLoaded = true; }
  $('refresh-reputation').disabled = !state.enabled || state.refreshing;
  const active = state.feeds.filter(f => f.active).length;
  message('reputation-status', state.error ? `Ошибка кэша: ${state.error}` : !state.enabled ? 'Базы выключены; совпадения не анализируются.' : state.refreshing ? 'Загружаем и проверяем базы…' : `Активно баз: ${active} из ${state.feeds.length}. Совпадения вычисляются локально.`, !!state.error);
  const root = $('reputation-feeds'); root.replaceChildren();
  for (const feed of state.feeds) {
    const box = document.createElement('div'); box.className = `reputation-feed${feed.error || (state.enabled && !feed.active) ? ' error' : ''}`;
    const title = document.createElement('b'); title.textContent = `${feed.name} · ${feed.active ? 'активна' : 'не используется'}`; box.appendChild(title);
    const desc = document.createElement('div'); desc.textContent = `${feed.description} Записей: ${feed.count.toLocaleString('ru-RU')}.`; box.appendChild(desc);
    const dates = document.createElement('div'); dates.textContent = `Обновление источника: ${feed.sourceUpdatedAt ? new Date(feed.sourceUpdatedAt).toLocaleString('ru-RU') : 'неизвестно'} · загрузка: ${feed.fetchedAt ? new Date(feed.fetchedAt).toLocaleString('ru-RU') : 'не выполнялась'}.`; box.appendChild(dates);
    if (feed.error) { const error = document.createElement('div'); error.textContent = `Последняя ошибка: ${feed.error}`; box.appendChild(error); }
    root.appendChild(box);
  }
}
async function refreshReputationStatus() {
  try { renderReputation(await api.reputation()); }
  catch (err) { message('reputation-status', `Ошибка: ${err.message}`, true); }
}
$('save-reputation').addEventListener('click', async () => {
  try { const result = await api.enableReputation($('reputation-enabled').checked); if (!result.ok) throw new Error(result.error); await refreshReputationStatus(); await refresh(); }
  catch (err) { message('reputation-status', `Ошибка: ${err.message}`, true); }
});
$('refresh-reputation').addEventListener('click', async () => {
  $('refresh-reputation').disabled = true; message('reputation-status', 'Загружаем базы с GitHub…');
  try { const result = await api.refreshReputation(); if (!result.ok) throw new Error(result.error); renderReputation(result); await refresh(); }
  catch (err) { message('reputation-status', `Ошибка: ${err.message}`, true); $('refresh-reputation').disabled = false; }
});
$('clear-reputation').addEventListener('click', async () => {
  if (!window.confirm('Очистить локальный кэш баз репутации?')) return;
  try { const result = await api.clearReputation(); if (!result.ok) throw new Error(result.error); await refreshReputationStatus(); await refresh(); }
  catch (err) { message('reputation-status', `Ошибка: ${err.message}`, true); }
});
refreshReputationStatus(); setInterval(refreshReputationStatus, 10000);
api.notifications().then(state => { $('notifications-enabled').checked=state.enabled; $('notifications-minimum').value=state.minimum; if (!state.supported) message('notifications-status','Уведомления не поддерживаются этой системой.',true); }).catch(err=>message('notifications-status',`Ошибка: ${err.message}`,true));
$('notifications-save').addEventListener('click', async () => {
  try { await api.saveNotifications({enabled:$('notifications-enabled').checked,minimum:$('notifications-minimum').value}); message('notifications-status','Настройки сохранены.'); }
  catch (err) { message('notifications-status',`Ошибка: ${err.message}`,true); }
});
const policyKeys = ['scanDestinations','smtpDestinations','minerRecords','minerMinutes','ddosPackets','ddosBytesMB','ddosSources','excluded','mailServers','poolAddresses'];
api.policy().then(policy => { securityPolicy = policy; for (const key of policyKeys) $(`policy-${key}`).value = policy[key]; }).catch(err => message('policy-message', err.message, true));
$('save-policy').addEventListener('click', async () => {
  const policy = Object.fromEntries(policyKeys.map(key => [key, $(`policy-${key}`).value]));
  try { const result = await api.savePolicy(policy); if (!result.ok) throw new Error(result.error); securityPolicy = result.policy; message('policy-message', 'Правила сохранены. Текущее окно пересчитано.'); await refresh(); }
  catch (err) { message('policy-message', `Ошибка: ${err.message}`, true); }
});
$('save-history').addEventListener('click', async () => {
  try { const retention = await api.setHistoryRetention(Number($('history-retention').value)); if (!retention.ok) throw new Error(retention.error); const result = await api.enableHistory($('history-enabled').checked); if (!result.ok) throw new Error(result.error); message('history-message', 'Настройка сохранена. При выключении уже сохранённые данные не удаляются.'); await refreshHistory(); }
  catch (err) { message('history-message', `Ошибка: ${err.message}`, true); }
});
$('clear-history').addEventListener('click', async () => {
  if (!window.confirm('Безвозвратно удалить локальные события и агрегаты истории?')) return;
  try { const result = await api.clearHistory(); if (!result.ok) throw new Error(result.error); message('history-message', 'История очищена.'); await refreshHistory(); }
  catch (err) { message('history-message', `Ошибка: ${err.message}`, true); }
});
function renderCategoryHistory() {
  const category=$('history-category').value;
  const days=lastHistory?.days || [];
  const entries=days.slice(0,14).reverse().filter(d=>d.categories && Object.hasOwn(d.categories,category)).map(d=>({label:new Date(d.time).toISOString().slice(0,10), value:d.categories[category].bytes, flows:d.categories[category].flows}));
  renderRankChart('category-history-chart',entries,false,'Нет сохранённых данных этой категории.');
}
$('history-category').addEventListener('change',renderCategoryHistory);
async function refreshHistory() {
  try {
    const data = await api.history();
    lastHistory = data; renderCategoryHistory();
    if (!historyLoaded) { $('history-enabled').checked = data.enabled; $('history-retention').value = data.retentionDays || 7; historyLoaded = true; }
    $('history-note').textContent = data.error ? `Ошибка истории: ${data.error}` : `${data.enabled ? 'Запись включена' : 'Запись выключена'} · ${data.eventCount} событий · показаны последние ${data.events.length}. Карточка IP показывает только текущее окно.`;
    renderRankChart('daily-chart', data.days.slice(0, 14).reverse().map(d => ({ label: new Date(d.time).toISOString().slice(0,10), value:d.bytes, flows:d.flows })), false, data.enabled ? 'Пока нет сохранённых данных по дням.' : 'История выключена; сохранённые данные отсутствуют.');
    const tbody = $('history-list'); tbody.replaceChildren();
    if (!data.events.length) { const row = document.createElement('tr'); const cell = textCell(row, 'Нет сохранённых событий'); cell.colSpan = 4; cell.className = 'empty'; tbody.appendChild(row); }
    for (const e of data.events) { const row = document.createElement('tr'); textCell(row, new Date(e.time).toLocaleString('ru-RU')); textCell(row, e.type); const ip = document.createElement('td'); ip.appendChild(hostButton(e.ip)); row.appendChild(ip); const detail = textCell(row, e.detail + (e.device ? ` · DHCP: ${e.device.name || 'без имени'} ${e.device.mac || ''} (снимок ${new Date(e.device.observedAt).toLocaleString('ru-RU')})` : '')); detail.className = 'history-detail'; tbody.appendChild(row); }
  } catch (err) { $('history-note').textContent = `Ошибка истории: ${err.message}`; }
}
api.subnets().then(networks => { $('subnets').value = networks.join('\n'); }).catch(err => message('subnets-message', `Не удалось загрузить подсети: ${err.message}`, true));
$('save-subnets').addEventListener('click', async () => {
  $('save-subnets').disabled = true;
  try {
    const result = await api.saveSubnets($('subnets').value);
    if (!result.ok) throw new Error(result.error);
    $('subnets').value = result.subnets.join('\n');
    message('subnets-message', result.subnets.length ? 'Подсети сохранены. Направления пересчитаны для текущего окна.' : 'Список очищен. Направление трафика не определяется.');
    await refresh();
  } catch (err) { message('subnets-message', `Не удалось сохранить: ${err.message}`, true); }
  finally { $('save-subnets').disabled = false; }
});
$('save-report').addEventListener('click', async () => {
  const button = $('save-report'); button.disabled = true; message('report-status', 'Выберите место для сохранения отчёта…');
  try {
    const result = await api.saveReport();
    if (result.canceled) message('report-status', 'Сохранение отчёта отменено.');
    else if (!result.ok) throw new Error(result.error);
    else message('report-status', `Отчёт сохранён: ${result.path}. Он содержит IP-адреса и сетевые данные.`);
  } catch (err) { message('report-status', `Не удалось сохранить отчёт: ${err.message}`, true); }
  finally { button.disabled = false; }
});
document.querySelectorAll('.sort-button').forEach(button => button.addEventListener('click', () => {
  const by = button.dataset.sort;
  hostSort = { by, direction: hostSort.by === by ? (hostSort.direction === 'asc' ? 'desc' : 'asc') : (by === 'ip' ? 'asc' : 'desc') };
  for (const control of document.querySelectorAll('.sort-button')) {
    const active = control.dataset.sort === hostSort.by;
    control.parentElement.setAttribute('aria-sort', active ? (hostSort.direction === 'asc' ? 'ascending' : 'descending') : 'none');
    control.querySelector('span').textContent = active ? (hostSort.direction === 'asc' ? '↑' : '↓') : '';
  }
  refresh();
}));
$('start').addEventListener('click', async () => {
  $('start').disabled = true;
  try { render(await api.start({ address: $('address').value.trim(), port: $('flow-port').value, exporters:$('extra-exporters').value.split(/[\s,;]+/).filter(Boolean) })); message('collector-message', 'Сборщик запущен. Ожидание пакетов от роутера.'); }
  catch (err) { message('collector-message', `Не удалось запустить сбор: ${err.message}`, true); }
  finally { $('start').disabled = false; }
});
$('stop').addEventListener('click', async () => { render(await api.stop()); message('collector-message', 'Сбор остановлен.'); });
$('clear').addEventListener('click', async () => { render(await api.clear()); message('collector-message', 'Данные очищены.'); });
function formatBytes(n) { const units = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ']; let i = 0; while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; } return `${n.toLocaleString('ru-RU', { maximumFractionDigits: i ? 1 : 0 })} ${units[i]}`; }
function textCell(row, value) { const cell = document.createElement('td'); cell.textContent = value; row.appendChild(cell); return cell; }
function hostButton(ip) {
  const button = document.createElement('button'); button.className = 'host-link'; button.type = 'button'; button.textContent = ip;
  button.addEventListener('click', () => openHost(ip)); return button;
}
async function openHost(ip) {
  selectedHost = ip; $('host-title').textContent = ip; switchView('host-detail');
  for (const key of ['name','group','owner','note']) $(`device-${key}`).value = ''; message('device-status', '');
  try { const [data, device, history, bindings] = await Promise.all([api.host(ip),api.device(ip),api.hostHistory(ip),api.hostBindings(ip)]); if (selectedHost === ip) { renderHost(data); renderHostHistory(history); renderBindings(bindings); for (const key of ['name','group','owner','note']) $(`device-${key}`).value = device[key]; } }
  catch (err) { $('host-record-note').textContent = `Ошибка: ${err.message}`; }
}
function renderBindings(bindings) {
  const root=$('host-bindings'); root.replaceChildren();
  if (!bindings.length) { const el=document.createElement('p'); el.className='empty'; el.textContent='Нет сохранённых снимков.'; root.appendChild(el); return; }
  for (const b of bindings) {const el=document.createElement('p'); el.textContent=`${new Date(b.time).toLocaleString('ru-RU')} · роутер ${b.router} · ${b.name || 'без имени'} · ${b.mac || 'без MAC'}`; root.appendChild(el);}
}
function renderHostHistory(history) {
  renderRankChart('host-history-chart', history.days.map(d=>({label:new Date(d.time).toISOString().slice(0,10),value:d.bytes,flows:d.flows})), false, history.enabled ? 'Нет сохранённых исходящих агрегатов.' : 'История выключена; сохранённых данных нет.');
  const days=history.days; let comparison='';
  if (days.length>=2) { const a=days[days.length-2], b=days[days.length-1]; comparison=` Последние дни с данными: ${formatBytes(a.bytes)} → ${formatBytes(b.bytes)}; неполные дни и пропуски могут исказить сравнение.`; }
  $('host-history-note').textContent=`Исходящие агрегаты UTC за ${history.retentionDays || 7} дней; старые записи удаляются.${comparison}`;
}
$('device-save').addEventListener('click', async () => {
  const ip=selectedHost; if (!ip) return;
  try { await api.saveDevice(ip,Object.fromEntries(['name','group','owner','note'].map(k=>[k,$(`device-${k}`).value]))); if (selectedHost===ip) message('device-status','Данные сохранены локально.'); }
  catch (err) { message('device-status',`Ошибка: ${err.message}`,true); }
});
$('back-dashboard').addEventListener('click', () => { selectedHost = ''; switchView('dashboard'); });
function renderCategories(id, categories) {
  const root = $(id); root.replaceChildren();
  if (!categories.length) { const empty = document.createElement('div'); empty.className = 'empty'; empty.textContent = 'Пока нет данных о потоках'; root.appendChild(empty); return; }
  const total = categories.reduce((sum, item) => sum + item.bytes, 0);
  for (const item of categories) {
    const box = document.createElement('button'); box.type = 'button'; box.className = 'category-item'; box.setAttribute('aria-label', `Открыть тип трафика: ${item.label}`); box.addEventListener('click', () => openCategory(item.id));
    const line = document.createElement('div'); line.className = 'category-line';
    const name = document.createElement('span'); name.textContent = item.label;
    const bytes = document.createElement('strong'); bytes.textContent = formatBytes(item.bytes); line.append(name, bytes);
    const sub = document.createElement('div'); sub.className = 'category-sub'; sub.textContent = `${item.flows.toLocaleString('ru-RU')} потоков · ${total ? (item.bytes / total * 100).toFixed(1) : '0'}% объёма`;
    const track = document.createElement('div'); track.className = 'category-track'; const fill = document.createElement('div'); fill.className = 'category-fill'; fill.style.width = `${total ? item.bytes / total * 100 : 0}%`; track.appendChild(fill);
    box.append(line, sub, track); root.appendChild(box);
  }
}
function searchFilter() { return Object.fromEntries(['exporter','ip','port','protocol','direction','category','threat'].map(key => [key, $(`search-${key}`).value.trim()])); }
$('search-run').addEventListener('click', async () => {
  try {
    const result = await api.searchFlows(searchFilter());
    message('search-status', `Найдено: ${result.total}; показано: ${result.records.length}.`);
    const root = $('search-results'); root.replaceChildren();
    if (!result.records.length) { const row = document.createElement('tr'); const cell = textCell(row, 'Совпадений нет'); cell.colSpan = 6; cell.className = 'empty'; root.appendChild(row); }
    for (const f of result.records) {
      const row = document.createElement('tr'); textCell(row, new Date(f.time).toLocaleTimeString('ru-RU'));
      for (const [ip,port] of [[f.src,f.srcPort],[f.dst,f.dstPort]]) { const cell = document.createElement('td'); cell.append(hostButton(ip), document.createTextNode(`:${port}`)); row.appendChild(cell); }
      textCell(row, f.protocol === 6 ? 'TCP' : f.protocol === 17 ? 'UDP' : `IP ${f.protocol}`); textCell(row, `${f.direction} · ${f.category} · ${f.exporter || 'экспортёр неизвестен'}`); textCell(row, formatBytes(f.bytes)); root.appendChild(row);
    }
  } catch (err) { message('search-status', `Ошибка: ${err.message}`, true); }
});
for (const format of ['csv','json']) $(`search-${format}`).addEventListener('click', async () => {
  try { const result = await api.exportFlows(searchFilter(), format); if (result.canceled) return; if (!result.ok) throw new Error(result.error); message('search-status', `Сохранено записей: ${result.count}. ${result.path}`); }
  catch (err) { message('search-status', `Ошибка: ${err.message}`, true); }
});
const threatNames = { miner:'Возможный майнинг', spam:'Возможный спам', ddos:'Возможный DDoS / входящая атака', reputation:'Совпадение с базами репутации' };
document.querySelectorAll('.threat-tile').forEach(button => button.addEventListener('click', () => openThreat(button.dataset.threat)));
async function openThreat(id) {
  selectedThreat = id; reviewHost = ''; $('review-panel').hidden = true; switchView('threat-detail'); $('threat-title').textContent = threatNames[id];
  try { const data = await api.securityDetail(id); if (selectedThreat === id) renderThreat(data); }
  catch (err) { $('threat-detail-note').textContent = `Ошибка: ${err.message}`; }
}
$('back-threat').addEventListener('click', () => switchView('dashboard'));
function renderThreat(s) {
  $('threat-title').textContent = threatNames[s.id]; $('threat-host-count').textContent = s.hostCount.toLocaleString('ru-RU'); $('threat-flow-count').textContent = s.count.toLocaleString('ru-RU'); $('threat-bytes').textContent = formatBytes(s.bytes);
  $('threat-detail-note').textContent = s.id === 'ddos' ? 'Все входящие или исходящие записи, использованные для расчёта нагрузки у отмеченного хоста. Не каждый поток является атакой.' : 'Только записи, участвовавшие в расчёте активных сигналов за последние 5 минут. Не доказательство угрозы.';
  $('threat-record-note').textContent = `Показано ${s.records.length} из ${s.count} записей. Сигналы пропадают после выхода данных из окна.`;
  const hosts = $('threat-hosts'); hosts.replaceChildren();
  if (!s.hosts.length) { const row = document.createElement('tr'); const cell = textCell(row, 'Нет активных сигналов. Проверьте локальные подсети и состояние баз.'); cell.colSpan = 5; cell.className = 'empty'; hosts.appendChild(row); }
  for (const host of s.hosts) {
    const row = document.createElement('tr'); const cell = document.createElement('td'); cell.appendChild(hostButton(host.ip)); row.appendChild(cell);
    const evidence = document.createElement('td'); for (const alert of host.alerts) { const line = document.createElement('div'); line.className = 'history-detail'; line.textContent = `${alert.type}: ${alert.detail} ${alert.recommendation || ''}`; evidence.appendChild(line); } row.appendChild(evidence);
    const reviewButton = document.createElement('button'); reviewButton.className='button text-button'; reviewButton.textContent='Разобрать'; reviewButton.addEventListener('click', () => openReview(s.id, host)); evidence.appendChild(reviewButton);
    textCell(row, host.peers); textCell(row, host.flows); textCell(row, formatBytes(host.bytes)); hosts.appendChild(row);
  }
  const records = $('threat-records'); records.replaceChildren();
  if (!s.records.length) { const row = document.createElement('tr'); const cell = textCell(row, 'Нет записей в текущем окне'); cell.colSpan = 5; cell.className = 'empty'; records.appendChild(row); }
  for (const f of s.records) {
    const row = document.createElement('tr'); textCell(row, new Date(f.time).toLocaleTimeString('ru-RU'));
    for (const [ip,port] of [[f.src,f.srcPort],[f.dst,f.dstPort]]) { const cell = document.createElement('td'); cell.append(hostButton(ip), document.createTextNode(`:${port}`)); row.appendChild(cell); }
    textCell(row, `${f.direction === 'outgoing' ? 'Исходящий' : 'Входящий'}${f.evidence ? ` · ${f.evidence}` : ''}`); textCell(row, formatBytes(f.bytes)); records.appendChild(row);
  }
}
async function openReview(type, host) {
  reviewHost=host.ip; $('review-panel').hidden=false; $('review-title').textContent=`${threatNames[type]} · ${host.ip}`;
  $('review-evidence').textContent=host.alerts.map(a=>`${a.detail} ${a.recommendation}`).join(' ');
  const p=securityPolicy || {}; const threshold={miner:`Порог: ${p.minerRecords ?? '—'} записей или ${p.minerMinutes ?? '—'} минут, либо заданный адрес пула.`,spam:`Порог: ${p.smtpDestinations ?? '—'} SMTP-назначений.`,ddos:`Пороги: ${p.ddosPackets ?? '—'} пакетов и ${p.ddosBytesMB ?? '—'} МБ исходящих; либо ${p.ddosSources ?? '—'} источников и ${p.ddosPackets ?? '—'} пакетов входящих.`,reputation:'Порог: хотя бы одно совпадение с активной IPv4-базой.'};
  $('review-threshold').textContent=`Окно: последние 5 минут по времени получения. ${threshold[type]}`;
  try { const data=await api.review(type,host.ip); if (selectedThreat===type && reviewHost===host.ip) { $('review-status').value=data.status; $('review-note').value=data.note; message('review-message',''); } }
  catch (err) { message('review-message',`Ошибка: ${err.message}`,true); }
}
$('review-save').addEventListener('click', async () => {
  const type=selectedThreat, ip=reviewHost; if (!type || !ip) return;
  try { await api.saveReview(type,ip,{status:$('review-status').value,note:$('review-note').value}); if (selectedThreat===type && reviewHost===ip) message('review-message','Разбор сохранён локально.'); }
  catch (err) { message('review-message',`Ошибка: ${err.message}`,true); }
});
function renderRankChart(id, entries, clickable, emptyText) {
  const root = $(id); root.replaceChildren();
  if (!entries.length) { const empty = document.createElement('div'); empty.className = 'empty'; empty.textContent = emptyText; root.appendChild(empty); return; }
  const max = Math.max(1, ...entries.map(x => x.value));
  for (const item of entries) {
    const row = document.createElement('div'); row.className = 'rank-row';
    const label = clickable ? hostButton(item.label) : document.createElement('span'); if (!clickable) label.textContent = item.label;
    const track = document.createElement('div'); track.className = 'rank-track'; const fill = document.createElement('div'); fill.className = 'rank-fill'; fill.style.width = `${item.value / max * 100}%`; track.appendChild(fill);
    const value = document.createElement('span'); value.className = 'rank-value'; value.textContent = formatBytes(item.value); value.title = `${item.flows} записей`;
    row.append(label, track, value); root.appendChild(row);
  }
}
function renderTimeChart(id, values, formatter) {
  const root = $(id); root.replaceChildren(); const max = Math.max(1, ...values);
  for (const value of values) { const bar = document.createElement('div'); bar.className = 'bar'; bar.style.height = `${Math.max(1, value / max * 100)}%`; bar.title = formatter(value); root.appendChild(bar); }
}
async function openCategory(id) {
  selectedCategory = id; switchView('category-detail');
  try { const data = await api.category(id); if (selectedCategory === id) renderCategory(data); }
  catch (err) { $('category-record-note').textContent = `Ошибка: ${err.message}`; }
}
$('back-category').addEventListener('click', () => switchView('dashboard'));
function renderCategory(s) {
  $('category-title').textContent = s.label; $('category-bytes').textContent = formatBytes(s.bytes); $('category-flows').textContent = s.count.toLocaleString('ru-RU'); $('category-host-count').textContent = s.hostCount.toLocaleString('ru-RU');
  $('category-record-note').textContent = `Показано ${s.records.length} из ${s.count} записей за последние 5 минут`;
  const hosts = $('category-hosts'); hosts.replaceChildren();
  if (!s.hosts.length) { const row = document.createElement('tr'); const cell = textCell(row, 'Нет данных за последние 5 минут'); cell.colSpan = 4; cell.className = 'empty'; hosts.appendChild(row); }
  for (const host of s.hosts) { const row = document.createElement('tr'); const cell = document.createElement('td'); cell.appendChild(hostButton(host.ip)); row.appendChild(cell); textCell(row, host.targets); textCell(row, host.flows); textCell(row, formatBytes(host.bytes)); hosts.appendChild(row); }
  const records = $('category-records'); records.replaceChildren();
  if (!s.records.length) { const row = document.createElement('tr'); const cell = textCell(row, 'Нет записей'); cell.colSpan = 5; cell.className = 'empty'; records.appendChild(row); }
  for (const f of s.records) {
    const row = document.createElement('tr'); textCell(row, new Date(f.time).toLocaleTimeString('ru-RU'));
    for (const [ip,port] of [[f.src,f.srcPort],[f.dst,f.dstPort]]) { const cell = document.createElement('td'); cell.append(hostButton(ip), document.createTextNode(`:${port}`)); row.appendChild(cell); }
    textCell(row, f.evidence); textCell(row, formatBytes(f.bytes)); records.appendChild(row);
  }
}
function renderPeerGraph(ip, peers) {
  const root=$('host-graph'); root.replaceChildren(); if (!peers.length) return;
  const ns='http://www.w3.org/2000/svg', svg=document.createElementNS(ns,'svg');
  svg.setAttribute('viewBox','0 0 900 440'); svg.setAttribute('role','img'); svg.setAttribute('aria-label',`Связи хоста ${ip}, до десяти контрагентов`);
  const element=(tag,attrs)=>{const el=document.createElementNS(ns,tag); for (const [k,v] of Object.entries(attrs)) el.setAttribute(k,v); return el;};
  const max=Math.max(1,...peers.map(p=>p.bytes));
  peers.forEach((peer,index)=>{
    const angle=2*Math.PI*index/peers.length-Math.PI/2, x=450+290*Math.cos(angle), y=220+165*Math.sin(angle);
    const edge=element('line',{x1:450,y1:220,x2:x,y2:y,stroke:'#4fa379','stroke-width':1+6*peer.bytes/max,opacity:0.65}); svg.appendChild(edge);
    const group=element('g',{role:'button',tabindex:'0','aria-label':`Открыть ${peer.ip}: ${formatBytes(peer.bytes)}`});
    const circle=element('circle',{cx:x,cy:y,r:10,fill:'#70d6a0'}); const label=element('text',{x,y:y-17,'text-anchor':'middle',fill:'#cde2d8','font-size':'13'}); label.textContent=peer.ip;
    group.append(circle,label); group.addEventListener('click',()=>openHost(peer.ip)); group.addEventListener('keydown',event=>{if(event.key==='Enter'||event.key===' '){event.preventDefault();openHost(peer.ip);}}); svg.appendChild(group);
  });
  svg.appendChild(element('circle',{cx:450,cy:220,r:16,fill:'#d6fff0'})); const center=element('text',{x:450,y:255,'text-anchor':'middle',fill:'#effff8','font-size':'14'}); center.textContent=ip; svg.appendChild(center); root.appendChild(svg);
}
function renderHost(s) {
  $('host-title').textContent = s.ip;
  $('host-device').textContent = s.device ? `Текущая DHCP-аренда: ${s.device.name || 'имя не указано'} · ${s.device.mac || 'MAC не указан'} · получена ${new Date(s.device.observedAt).toLocaleString('ru-RU')}; не доказывает владельца IP в прошлом.` : 'Данные DHCP не загружены или старше 5 минут.';
  $('host-bytes').textContent = formatBytes(s.bytes);
  $('host-flows').textContent = s.count.toLocaleString('ru-RU'); $('host-peers').textContent = s.peers.toLocaleString('ru-RU'); $('host-packets').textContent = s.packets.toLocaleString('ru-RU');
  $('host-directions').textContent = `${s.outgoing} исходящих · ${s.incoming} входящих`;
  $('host-out-bytes').textContent = formatBytes(s.outgoingBytes); $('host-in-bytes').textContent = formatBytes(s.incomingBytes);
  $('host-out-flows').textContent = `${s.outgoing} потоков`; $('host-in-flows').textContent = `${s.incoming} потоков`;
  $('host-record-note').textContent = `Показано ${s.records.length} из ${s.count} записей за 5 минут (не более 200)`;
  renderCategories('host-categories', s.categories);
  renderPeerGraph(s.ip, s.topPeers);
  renderRankChart('host-links', s.topPeers.map(p=>({label:p.ip,value:p.bytes,flows:p.flows})), true, 'Нет связей за текущее окно.');
  const tbody = $('host-records'); tbody.replaceChildren();
  if (!s.records.length) { const row = document.createElement('tr'); const cell = textCell(row, 'Нет записей за последние 5 минут'); cell.colSpan = 7; cell.className = 'empty'; tbody.appendChild(row); }
  for (const f of s.records) {
    const row = document.createElement('tr'); textCell(row, new Date(f.time).toLocaleTimeString('ru-RU'));
    textCell(row, f.src === s.ip && f.dst === s.ip ? 'Внутри хоста' : f.src === s.ip ? 'Исходящий' : 'Входящий');
    const src = textCell(row, `${f.src}:${f.srcPort}`); src.className = 'host-records-address';
    const dst = textCell(row, `${f.dst}:${f.dstPort}`); dst.className = 'host-records-address';
    textCell(row, f.protocol === 6 ? 'TCP' : f.protocol === 17 ? 'UDP' : `IP ${f.protocol}`);
    const type = textCell(row, f.category); const evidence = document.createElement('span'); evidence.className = 'host-record-type'; evidence.textContent = f.evidence; type.appendChild(evidence);
    const metadata = []; if (f.startTime) metadata.push(`начало ${new Date(f.startTime).toLocaleString('ru-RU')}`); if (f.endTime) metadata.push(`конец ${new Date(f.endTime).toLocaleString('ru-RU')}`); if (f.tcpFlags != null) metadata.push(`TCP-флаги 0x${f.tcpFlags.toString(16)}`); if (f.inputInterface != null) metadata.push(`входной ifIndex ${f.inputInterface}`); if (f.outputInterface != null) metadata.push(`выходной ifIndex ${f.outputInterface}`); if (f.samplingInterval) metadata.push(`sampling 1:${f.samplingInterval}`); if (metadata.length) { const extra = document.createElement('span'); extra.className = 'host-record-type'; extra.textContent = metadata.join(' · '); type.appendChild(extra); }
    textCell(row, formatBytes(f.bytes)); tbody.appendChild(row);
  }
}
function render(s) {
  $('top-status').classList.toggle('online', s.running);
  $('top-status').innerHTML = '<i></i>'; $('top-status').append(document.createTextNode(s.running ? ' Сбор запущен' : ' Не подключено'));
  $('banner-title').textContent = s.running ? `Сборщик активен · UDP ${s.port}` : 'Подключите ваш MikroTik';
  $('banner-text').textContent = s.running ? (s.lastPacket ? `Последний пакет: ${new Date(s.lastPacket).toLocaleTimeString('ru-RU')} · ${s.address}` : `Ожидание пакетов от ${s.address}. Проверьте Traffic Flow и брандмауэр.`) : 'Настройте экспорт Traffic Flow, чтобы начать наблюдение за сетью.';
  $('banner-action').textContent = s.running ? 'Настройки →' : 'Начать настройку →';
  $('bytes').textContent = formatBytes(s.bytes); $('flows').textContent = s.flowCount.toLocaleString('ru-RU');
  // Host count is derived from the complete five-minute window, not the displayed top 30.
  $('hosts').textContent = s.hostCount.toLocaleString('ru-RU'); $('alert-count').textContent = s.alertCount.toLocaleString('ru-RU'); $('alert-badge').textContent = s.alertCount;
  $('updated').textContent = s.lastPacket ? `●  Обновлено ${new Date().toLocaleTimeString('ru-RU')}` : '●  Ожидание данных';
  $('footer-status').textContent = s.error ? `Ошибка: ${s.error}` : `${s.datagrams} UDP-пакетов · ${s.received} записей${s.dropped ? ` · ${s.dropped} отброшено из-за лимита` : ''}`;
  const list = $('alerts-list'); list.replaceChildren();
  if (!s.alerts.length) { const empty = document.createElement('div'); empty.className = 'empty'; empty.textContent = s.networks.length ? 'Сигналов пока нет. Это не подтверждает отсутствие угроз.' : 'Укажите локальные подсети: без них сигналы не анализируются.'; list.appendChild(empty); }
  for (const alert of s.alerts) { const row = document.createElement('div'); row.className = 'alert-row'; const symbol = document.createElement('span'); symbol.className = 'alert-symbol'; symbol.textContent = '⚑'; const content = document.createElement('div'); const title = document.createElement('strong'); title.textContent = `${alert.type} · ${alert.severity === 'medium' ? 'умеренное' : 'низкое'} подозрение · `; title.appendChild(hostButton(alert.ip)); const detail = document.createElement('p'); detail.textContent = alert.detail; content.append(title, detail); if (alert.device) { const device = document.createElement('p'); device.textContent = `DHCP: ${alert.device.name || 'имя не указано'} · ${alert.device.mac || 'MAC не указан'} (не подтверждает личность устройства)`; content.appendChild(device); } if (alert.recommendation) { const advice = document.createElement('p'); advice.textContent = alert.recommendation; content.appendChild(advice); } row.append(symbol, content); list.append(row); }
  const tbody = $('hosts-list'); tbody.replaceChildren();
  if (!s.hosts.length) { const row = document.createElement('tr'), cell = document.createElement('td'); cell.colSpan = 4; cell.className = 'empty'; cell.textContent = 'Пока нет данных о потоках'; row.appendChild(cell); tbody.appendChild(row); }
  for (const host of s.hosts) { const row = document.createElement('tr'); const hostCell = document.createElement('td'); hostCell.appendChild(hostButton(host.ip)); row.appendChild(hostCell); textCell(row, host.destinations); textCell(row, host.flows); textCell(row, formatBytes(host.bytes)); tbody.appendChild(row); }
  renderCategories('categories-list', s.categories);
  if (s.sources) { const lines=Object.entries(s.sources).map(([ip, x]) => `${ip}: ${x.datagrams} пакетов, ${x.flows} записей, последний ${x.lastPacket ? new Date(x.lastPacket).toLocaleString('ru-RU') : 'не получен'}`); $('collector-sources').textContent=lines.join(' · '); }
  if (s.diagnostics) { const d = s.diagnostics; $('collector-diagnostics').textContent = `Приём: ${s.running ? 'запущен' : 'остановлен'} · последний пакет: ${s.lastPacket ? new Date(s.lastPacket).toLocaleString('ru-RU') : 'не получен'} · пакеты v5/v9/IPFIX: ${d.versions[5]}/${d.versions[9]}/${d.versions[10]} · неизвестных версий: ${d.unsupported} · некорректных структур: ${d.malformed} · наборов без шаблона: ${d.unknownTemplates} · шаблонов: ${d.templates} · отклонено по IP: ${s.rejected} · ошибок обработки: ${s.parseErrors} · отброшено по лимиту окна: ${s.dropped}. Потери до приложения неизвестны.`; }
  const activeFeeds = reputationStatus?.feeds?.filter(f => f.active).length || 0;
  for (const id of ['miner','spam','ddos','reputation']) $(`threat-${id}`).textContent = s.networks.length && (id !== 'reputation' || activeFeeds > 0) ? s.securityGroups[id].toLocaleString('ru-RU') : '—';
  $('threat-note').textContent = !s.networks.length ? 'Укажите локальные подсети в настройках, чтобы включить анализ сигналов.' : `Число — локальные хосты с активными сигналами. Активных баз репутации: ${activeFeeds}. Сигналы не доказывают угрозу.`;
  renderTimeChart('volume-chart', s.byteBuckets, value => formatBytes(value));
  renderRankChart('top-host-chart', s.topTraffic.map(h => ({label:h.ip, value:h.bytes, flows:h.flows})), true, 'Пока нет потоков.');
  const totalDirection = Object.values(s.directions).reduce((sum,item) => sum + item.bytes,0); const directionChart = $('direction-chart'); directionChart.replaceChildren();
  for (const item of Object.values(s.directions)) { const part = document.createElement('span'); part.style.width = `${totalDirection ? item.bytes / totalDirection * 100 : 0}%`; part.title = `${item.label}: ${formatBytes(item.bytes)}`; directionChart.appendChild(part); }
  $('direction-note').textContent = s.networks.length ? `Относительно подсетей: ${s.networks.join(', ')} · IPv4 / IPv6` : 'Укажите локальные IP-подсети в настройках, чтобы определить направления.';
  const directionList = $('directions-list'); directionList.replaceChildren();
  for (const item of Object.values(s.directions)) {
    const box = document.createElement('div'); box.className = 'direction-card';
    const label = document.createElement('span'); label.textContent = item.label;
    const value = document.createElement('strong'); value.textContent = formatBytes(item.bytes);
    const sub = document.createElement('small'); sub.textContent = `${item.flows.toLocaleString('ru-RU')} потоков`;
    box.append(label, value, sub); directionList.appendChild(box);
  }
  const chart = $('chart'); chart.replaceChildren(); const max = Math.max(1, ...s.buckets);
  for (const count of s.buckets) { const bar = document.createElement('div'); bar.className = 'bar'; bar.style.height = `${Math.max(1, count / max * 100)}%`; bar.title = `${count} потоков`; chart.appendChild(bar); }
}
async function refresh() { const revision = ++refreshRevision; try { const data = await api.snapshot(hostSort); if (revision !== refreshRevision) return; render(data); const ip = selectedHost; if (ip) { const detail = await api.host(ip); if (revision === refreshRevision && selectedHost === ip) renderHost(detail); } const category = selectedCategory; if (category) { const detail = await api.category(category); if (revision === refreshRevision && selectedCategory === category) renderCategory(detail); } const threat = selectedThreat; if (threat) { const detail = await api.securityDetail(threat); if (revision === refreshRevision && selectedThreat === threat) renderThreat(detail); } } catch (err) { message('collector-message', err.message, true); } }
refresh(); setInterval(refresh, 2000); refreshHistory(); setInterval(refreshHistory, 10000);
