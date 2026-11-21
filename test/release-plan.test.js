'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { isNewer } = require('../scripts/should-release');
test('only a newer stable release is published', () => {
  assert.equal(isNewer('1.4.0','v1.3.0'),true);
  assert.equal(isNewer('1.4.0','v1.4.0'),false);
  assert.equal(isNewer('1.3.99','v1.4.0'),false);
  assert.equal(isNewer('2.0.0','v1.999.999'),true);
  assert.equal(isNewer('1.10.0','v1.9.99'),true);
  assert.throws(()=>isNewer('1.4.0-rc.1','v1.3.0'));
  assert.throws(()=>isNewer('1.4.0','latest'));
});
