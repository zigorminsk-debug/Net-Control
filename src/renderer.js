'use strict';
const $ = id => document.getElementById(id);
const api = window.netControl;
function switchView(view) {
  document.querySelectorAll('.view').forEach(el => el.classList.toggle('active-view', el.id === view));
  document.querySelectorAll('.nav-item').forEach(el => el.classList.toggle('active', el.dataset.view === view));
  $('breadcrumb').textContent = view === 'dashboard' ? 'Обзор сети' : 'Подключение';
}
document.querySelectorAll('.nav-item').forEach(button => button.addEventListener('click', () => switchView(button.dataset.view)));
$('open-settings').addEventListener('click', () => switchView('settings'));
$('banner-action').addEventListener('click', () => switchView('settings'));
function message(id, text, error = false) { const el = $(id); el.textContent = text; el.classList.toggle('error', error); }
function commands() {
  const n = Number($('flow-port').value); const port = Number.isInteger(n) && n > 0 && n <= 65535 ? n : 2055;
  $('commands').textContent = `/ip traffic-flow set enabled=yes interfaces=all\n/ip traffic-flow target add dst-address=IP_КОМПЬЮТЕРА port=${port} version=9`;
}
$('flow-port').addEventListener('input', commands); commands();
$('test-router').addEventListener('click', async () => {
  const button = $('test-router'); button.disabled = true; message('router-message', 'Проверяем подключение…');
  try {
    const data = await api.testRouter({ address: $('address').value.trim(), port: $('api-port').value, username: $('username').value, password: $('password').value, secure: $('secure').checked, allowSelfSigned: $('self-signed').checked });
    message('router-message', `Подключено: ${data.board} · RouterOS ${data.version} · uptime ${data.uptime}`);
  } catch (err) { message('router-message', `Не удалось подключиться: ${err.message}`, true); }
  finally { button.disabled = false; }
});
$('start').addEventListener('click', async () => {
  $('start').disabled = true;
  try { render(await api.start({ address: $('address').value.trim(), port: $('flow-port').value })); message('collector-message', 'Сборщик запущен. Ожидание пакетов от роутера.'); }
  catch (err) { message('collector-message', `Не удалось запустить сбор: ${err.message}`, true); }
  finally { $('start').disabled = false; }
});
$('stop').addEventListener('click', async () => { render(await api.stop()); message('collector-message', 'Сбор остановлен.'); });
$('clear').addEventListener('click', async () => { render(await api.clear()); message('collector-message', 'Данные очищены.'); });
function formatBytes(n) { const units = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ']; let i = 0; while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; } return `${n.toLocaleString('ru-RU', { maximumFractionDigits: i ? 1 : 0 })} ${units[i]}`; }
function textCell(row, value) { const cell = document.createElement('td'); cell.textContent = value; row.appendChild(cell); }
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
  if (!s.alerts.length) { const empty = document.createElement('div'); empty.className = 'empty'; empty.innerHTML = '<span class="empty-icon">◇</span>Сигналов пока нет<br>Здесь появится подозрительная активность'; list.appendChild(empty); }
  for (const alert of s.alerts) { const row = document.createElement('div'); row.className = 'alert-row'; const symbol = document.createElement('span'); symbol.className = 'alert-symbol'; symbol.textContent = '⚑'; const content = document.createElement('div'); const title = document.createElement('strong'); title.textContent = `${alert.type} · ${alert.ip}`; const detail = document.createElement('p'); detail.textContent = alert.detail; content.append(title, detail); row.append(symbol, content); list.append(row); }
  const tbody = $('hosts-list'); tbody.replaceChildren();
  if (!s.hosts.length) { const row = document.createElement('tr'), cell = document.createElement('td'); cell.colSpan = 4; cell.className = 'empty'; cell.textContent = 'Пока нет данных о потоках'; row.appendChild(cell); tbody.appendChild(row); }
  for (const host of s.hosts) { const row = document.createElement('tr'); textCell(row, host.ip); textCell(row, host.destinations); textCell(row, host.flows); textCell(row, formatBytes(host.bytes)); tbody.appendChild(row); }
  const chart = $('chart'); chart.replaceChildren(); const max = Math.max(1, ...s.buckets);
  for (const count of s.buckets) { const bar = document.createElement('div'); bar.className = 'bar'; bar.style.height = `${Math.max(1, count / max * 100)}%`; bar.title = `${count} потоков`; chart.appendChild(bar); }
}
async function refresh() { try { render(await api.snapshot()); } catch (err) { message('collector-message', err.message, true); } }
refresh(); setInterval(refresh, 2000);
