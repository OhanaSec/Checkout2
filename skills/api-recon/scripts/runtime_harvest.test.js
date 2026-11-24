'use strict';
// Regression tests for REM-JC-20261123-004: TLS verification must stay on by default and the
// explicit opt-out must never be combined with auth cookies.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { resolveTlsPolicy, forwardHeaders } = require('./runtime_harvest.js');

const SRC = fs.readFileSync(path.join(__dirname, 'runtime_harvest.js'), 'utf8');
const cookies = [{ name: 'auth', value: 'secret' }];

test('TLS verification is on by default', () => {
  const p = resolveTlsPolicy({}, {});
  assert.equal(p.insecure, false);
  assert.deepEqual(p.launchArgs, []);
});

test('default mode sends configured cookies over verified TLS', () => {
  const p = resolveTlsPolicy({ cookies }, {});
  const h = forwardHeaders({ accept: '*/*' }, { cookies }, p);
  assert.equal(h.cookie, 'auth=secret');
});

test('explicit opt-out via config or env is honoured without cookies', () => {
  for (const [cfg, env] of [[{ insecureTls: true }, {}], [{}, { API_RECON_INSECURE_TLS: '1' }]]) {
    const p = resolveTlsPolicy(cfg, env);
    assert.equal(p.insecure, true);
    assert.deepEqual(p.launchArgs, ['--ignore-certificate-errors']);
  }
});

test('opt-out is refused when auth cookies are configured', () => {
  assert.throws(() => resolveTlsPolicy({ insecureTls: true, cookies }, {}), /refusing/);
  assert.throws(() => resolveTlsPolicy({ cookies }, { API_RECON_INSECURE_TLS: '1' }), /refusing/);
});

test('insecure mode strips credential headers from forwarded requests', () => {
  const p = resolveTlsPolicy({ insecureTls: true }, {});
  const h = forwardHeaders({ Cookie: 'sid=1', Authorization: 'Bearer x', 'proxy-authorization': 'y', accept: '*/*' }, {}, p);
  assert.deepEqual(h, { accept: '*/*' });
});

test('no unconditional TLS bypass in source', () => {
  // the only assignment must be inside the opt-in branch
  const assigns = SRC.match(/NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*'0'/g) || [];
  assert.equal(assigns.length, 1);
  assert.match(SRC, /if \(tls\.insecure\) \{[\s\S]{0,200}NODE_TLS_REJECT_UNAUTHORIZED = '0'/);
  assert.doesNotMatch(SRC, /'--disable-dev-shm-usage',\s*'--ignore-certificate-errors'/);
});
