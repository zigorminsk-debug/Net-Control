'use strict';
// A stable release must increase monotonically; never publish if the latest
// release tag cannot be interpreted. This deliberately fails closed.
function parseVersion(value) {
  const match = /^(?:v)?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.exec(value);
  if (!match) throw new Error(`Invalid stable version: ${value}`);
  return match.slice(1).map(BigInt);
}
function isNewer(version, latest) {
  const a = parseVersion(version), b = parseVersion(latest);
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] > b[i];
  return false;
}
if (require.main === module) {
  try { console.log(isNewer(process.argv[2], process.argv[3]) ? 'true' : 'false'); }
  catch (err) { console.error(err.message); process.exitCode = 1; }
}
module.exports = { isNewer, parseVersion };
