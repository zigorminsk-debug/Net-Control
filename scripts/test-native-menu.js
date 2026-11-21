'use strict';
// Run with Electron on Windows CI to validate the actual native menu template.
const assert = require('node:assert/strict');
const { app, Menu } = require('electron');
const { createMenuTemplate } = require('../src/application-menu');
app.whenReady().then(() => {
  const actions = []; let maximized = 0;
  const menu = Menu.buildFromTemplate(createMenuTemplate(action => actions.push(action), () => { maximized++; }));
  Menu.setApplicationMenu(menu);
  assert.deepEqual(menu.items.map(item => item.label), ['Файл', 'Правка', 'Вид', 'Окно', 'Справка']);
  const faq = menu.items[4].submenu.items.find(item => item.label.includes('FAQ'));
  assert.ok(faq); assert.equal(faq.accelerator, 'F1'); faq.click();
  const maximize = menu.items[3].submenu.items.find(item => item.label.startsWith('Развернуть'));
  assert.ok(maximize); maximize.click();
  assert.deepEqual(actions, ['help-faq']); assert.equal(maximized, 1);
  console.log('Electron native menu constructed and actions verified.');
  app.exit(0);
}).catch(err => { console.error(err.stack || err); app.exit(1); });
