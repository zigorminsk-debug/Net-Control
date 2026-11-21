'use strict';
// Preserve custom RouterOS service ports when switching protocols.
function portAfterProtocolChange(currentPort, secure) {
  const port = String(currentPort).trim();
  if (!port) return secure ? '443' : '80';
  if (secure && port === '80') return '443';
  if (!secure && port === '443') return '80';
  return port;
}
if (typeof module !== 'undefined') module.exports = { portAfterProtocolChange };
else window.connectionSettings = { portAfterProtocolChange };
