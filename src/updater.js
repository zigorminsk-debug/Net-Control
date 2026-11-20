'use strict';
// The updater is kept outside the renderer; no GitHub credentials are needed.
function createUpdateController({ updater, packaged, platform, version }) {
  const enabled = packaged && platform === 'win32';
  let state = { status: enabled ? 'idle' : 'disabled', currentVersion: version, availableVersion: '', progress: 0, error: '' };
  let checking = false;
  function set(patch) { state = { ...state, ...patch }; }
  function setError(err) {
    const raw = String(err?.message || err || 'Неизвестная ошибка');
    const explanation = /latest\.yml|ERR_UPDATER_CHANNEL_FILE_NOT_FOUND|404/i.test(raw)
      ? 'В последнем GitHub Release не найдены данные обновления (latest.yml) или релиз недоступен. Нужен опубликованный релиз с setup.exe и latest.yml.'
      : `Проверьте интернет и доступ к GitHub Releases. ${raw.slice(0, 400)}`;
    set({ status: 'error', error: explanation });
  }
  if (enabled) {
    updater.autoDownload = true;
    updater.autoInstallOnAppQuit = false;
    updater.allowPrerelease = false;
    updater.allowDowngrade = false;
    updater.disableDifferentialDownload = true;
    updater.on('checking-for-update', () => set({ status: 'checking', error: '' }));
    updater.on('update-available', info => set({ status: 'available', availableVersion: String(info.version || ''), progress: 0, error: '' }));
    updater.on('update-not-available', () => set({ status: 'up-to-date', availableVersion: '', progress: 0, error: '' }));
    updater.on('download-progress', info => set({ status: 'downloading', progress: Math.max(0, Math.min(100, Number(info.percent) || 0)) }));
    updater.on('update-downloaded', info => set({ status: 'downloaded', availableVersion: String(info.version || state.availableVersion), progress: 100, error: '' }));
    updater.on('error', setError);
  }
  return {
    status: () => ({ ...state }),
    async check() {
      if (!enabled || checking || ['available', 'downloading', 'downloaded'].includes(state.status)) return { ...state };
      checking = true; set({ status: 'checking', error: '' });
      try {
        const result = await updater.checkForUpdates();
        if (result?.downloadPromise) void result.downloadPromise.catch(setError);
      }
      catch (err) { setError(err); }
      finally { checking = false; }
      return { ...state };
    },
    install() {
      if (!enabled || state.status !== 'downloaded') return false;
      updater.quitAndInstall(false, true);
      return true;
    }
  };
}
module.exports = { createUpdateController };
