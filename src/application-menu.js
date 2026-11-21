'use strict';
// Menu commands are fixed identifiers, not renderer-supplied code or URLs.
function createMenuTemplate(sendAction, toggleMaximize) {
  const action = (label, command, accelerator) => ({ label, ...(accelerator ? { accelerator } : {}), click: () => sendAction(command) });
  const edit = (label, role) => ({ label, role });
  return [
    { label:'Файл', submenu:[
      action('Обзор сети', 'dashboard', 'CmdOrCtrl+1'),
      action('Поиск потоков', 'flow-search', 'CmdOrCtrl+2'),
      action('Подключение и настройки', 'settings', 'CmdOrCtrl+3'),
      { type:'separator' },
      action('Сохранить отчёт…', 'save-report', 'CmdOrCtrl+S'),
      action('Экспорт потоков в CSV…', 'export-csv'),
      action('Экспорт потоков в JSON…', 'export-json'),
      { type:'separator' },
      edit('Выход', 'quit')
    ] },
    { label:'Правка', submenu:[
      edit('Отменить', 'undo'), edit('Повторить', 'redo'), { type:'separator' },
      edit('Вырезать', 'cut'), edit('Копировать', 'copy'), edit('Вставить', 'paste'), edit('Выделить всё', 'selectAll')
    ] },
    { label:'Вид', submenu:[
      action('Обзор сети', 'dashboard'), action('Поиск потоков', 'flow-search'),
      action('Подключение и настройки', 'settings'), action('О программе', 'about'),
      { type:'separator' }, edit('Увеличить масштаб', 'zoomIn'), edit('Уменьшить масштаб', 'zoomOut'),
      edit('Сбросить масштаб', 'resetZoom'), { type:'separator' }, edit('Полноэкранный режим', 'togglefullscreen')
    ] },
    { label:'Окно', submenu:[edit('Свернуть', 'minimize'), { label:'Развернуть / восстановить', click: () => toggleMaximize() }, edit('Закрыть окно', 'close')] },
    { label:'Справка', submenu:[
      action('Частые вопросы (FAQ)', 'help-faq', 'F1'),
      action('Руководство пользователя', 'help-guide', 'F2'),
      { type:'separator' },
      action('Первое подключение', 'help-start'),
      action('Правила и сигналы безопасности', 'help-security'),
      action('Устранение неполадок', 'help-troubleshooting'),
      action('История и конфиденциальность', 'help-privacy'),
      { type:'separator' },
      action('Проверить обновления', 'check-updates'), action('О программе', 'about')
    ] }
  ];
}
module.exports = { createMenuTemplate };
