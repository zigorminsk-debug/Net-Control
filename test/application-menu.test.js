'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createMenuTemplate } = require('../src/application-menu');
test('application menu is localized, populated and maps actions to safe commands', () => {
  const actions=[]; let maximized=0;
  const menu=createMenuTemplate(action=>actions.push(action),()=>maximized++);
  assert.deepEqual(menu.map(item=>item.label), ['Файл','Правка','Вид','Окно','Справка']);
  for (const item of menu) assert.ok(item.submenu.some(child=>child.type!=='separator'));
  const help=menu.find(item=>item.label==='Справка').submenu;
  help.find(item=>item.label.includes('FAQ')).click();
  help.find(item=>item.label==='Устранение неполадок').click();
  menu.find(item=>item.label==='Файл').submenu.find(item=>item.label?.startsWith('Экспорт потоков в CSV')).click();
  menu.find(item=>item.label==='Окно').submenu.find(item=>item.label?.startsWith('Развернуть')).click();
  assert.deepEqual(actions,['help-faq','help-troubleshooting','export-csv']); assert.equal(maximized,1);
  assert.equal(help.find(item=>item.label.includes('FAQ')).accelerator,'F1');
  assert.ok(menu.find(item=>item.label==='Правка').submenu.some(item=>item.role==='copy'));
});
