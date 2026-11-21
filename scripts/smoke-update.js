'use strict';
// Run under Electron on Windows. Exercise the real GitHub provider and download
// with the previous version simulated via an isolated AppAdapter. Never install.
const { app } = require('electron');
const { NsisUpdater } = require('electron-updater');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createUpdateController } = require('../src/updater');
const pkg = require('../package.json');
const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'net-control-updater-smoke-'));
const adapter = {
  version: process.env.SMOKE_PREVIOUS_VERSION,
  name: 'Net Control', isPackaged: true,
  appUpdateConfigPath: path.resolve('dist/win-unpacked/resources/app-update.yml'),
  userDataPath: path.join(directory, 'user-data'), baseCachePath: path.join(directory, 'cache'),
  whenReady: () => app.whenReady(), onQuit: () => {}, quit: () => {}, relaunch: () => {}
};
fs.mkdirSync(adapter.userDataPath, { recursive:true });
fs.mkdirSync(adapter.baseCachePath, { recursive:true });
async function run() {
  if (process.platform !== 'win32' || !adapter.version) throw new Error('Windows and SMOKE_PREVIOUS_VERSION are required.');
  await app.whenReady();
  const updater = new NsisUpdater(undefined, adapter);
  const controller = createUpdateController({ updater, packaged:true, platform:'win32', version:adapter.version });
  let finish, fail;
  const downloaded = new Promise((resolve,reject) => { finish=resolve; fail=reject; });
  updater.on('error', fail);
  updater.on('update-downloaded', finish);
  const timer = setTimeout(() => fail(new Error('Update download timed out.')), 180000);
  try {
    const result = await controller.check();
    if (result.status === 'error' || result.status === 'up-to-date') throw new Error(`Unexpected status ${result.status}: ${result.error}`);
    const info = await downloaded;
    if (info.version !== pkg.version || controller.status().status !== 'downloaded') throw new Error(`Unexpected downloaded version: ${info.version}`);
    console.log(`Electron updater found and downloaded ${info.version} from simulated ${adapter.version}; installation was not attempted.`);
  } finally { clearTimeout(timer); }
}
run().then(() => app.exit(0)).catch(err => { console.error(err.stack || err); app.exit(1); });
