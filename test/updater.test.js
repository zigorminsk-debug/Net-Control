'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { createUpdateController } = require('../src/updater');
class FakeUpdater extends EventEmitter {
  async checkForUpdates() { this.calls = (this.calls || 0) + 1; this.emit('checking-for-update'); return {}; }
  quitAndInstall(...args) { this.installed = args; }
}
test('disabled outside packaged Windows and never installs', async () => {
  const u = new FakeUpdater(); const c = createUpdateController({ updater:u, packaged:false, platform:'win32', version:'1.1.0' });
  assert.equal((await c.check()).status,'disabled'); assert.equal(u.calls,undefined); assert.equal(c.install(),false);
});
test('auto-downloads, displays progress, and requires explicit installation', async () => {
  const u = new FakeUpdater(); const c = createUpdateController({ updater:u, packaged:true, platform:'win32', version:'1.1.0' });
  assert.equal(u.autoDownload,true); assert.equal(u.autoInstallOnAppQuit,false); assert.equal(u.allowPrerelease,false); assert.equal(u.allowDowngrade,false);
  assert.equal((await c.check()).status,'checking');
  u.emit('update-available',{version:'1.2.0'}); assert.equal(c.install(),false);
  u.emit('download-progress',{percent:41.4}); assert.equal(c.status().progress,41.4);
  await c.check(); assert.equal(u.calls,1);
  u.emit('update-downloaded',{version:'1.2.0'}); assert.equal(c.status().status,'downloaded'); assert.equal(u.installed,undefined);
  assert.equal(c.install(),true); assert.deepEqual(u.installed,[false,true]);
});
test('handles missing metadata and retry without crashing', async () => {
  const u = new FakeUpdater(); const c = createUpdateController({ updater:u, packaged:true, platform:'win32', version:'1.1.0' });
  u.emit('error',new Error('404 latest.yml')); assert.match(c.status().error,/latest.yml/);
  await c.check(); u.emit('update-not-available'); assert.equal(c.status().status,'up-to-date');
});
test('handles background download failures', async () => {
  const u = new FakeUpdater();
  u.checkForUpdates = async () => { u.emit('update-available',{version:'1.2.0'}); return {downloadPromise: Promise.reject(new Error('network down'))}; };
  const c = createUpdateController({ updater:u, packaged:true, platform:'win32', version:'1.1.0' });
  await c.check(); await new Promise(resolve => setImmediate(resolve)); assert.equal(c.status().status,'error'); assert.match(c.status().error,/network down/);
});
