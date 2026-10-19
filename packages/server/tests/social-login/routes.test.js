import expressBoom from 'express-boom';
import './bootstrap';
import './providerMock';
import './testProvider';
import assert from 'node:assert/strict';
import express from 'express';
import JWT from 'jsonwebtoken';
import { Container } from 'typedi';
import Controller from '../../src/api/controllers/SocialAuthentication';
import { SocialAuthError } from '../../src/services/Authentication/SocialProviders';

it('HTTP boundaries: origin checks, authenticated self-only linking, validation and sanitized errors', async () => {
  const calls = [];
  Container.set('logger', { info() {}, error() {} });
  Container.set('repositories', { systemUserRepository: { findOneById: async (id) => ({ id, active: true, password: 'hash' }) } });
  const controller = new Controller();
  controller.social = {
    start: async (...args) => { calls.push(['start', ...args]); return 'https://identity.example/authorize'; },
    freshUser: async (...args) => { calls.push(['fresh', ...args]); },
    disconnect: async (...args) => { calls.push(['disconnect', ...args]); },
    complete: async () => { throw new Error('provider-secret-must-not-leak'); },
    callback: async () => { throw new SocialAuthError('SIGN_IN_TO_CONNECT'); },
  };
  const app = express();
  app.use(express.json());
  app.use(expressBoom());
  app.use('/api/auth/social', controller.router());
  const server = app.listen(0, '127.0.0.1');
  await new Promise((resolve) => server.once('listening', resolve));
  const base = `http://127.0.0.1:${server.address().port}/api/auth/social`;
  const token = JWT.sign({ id: 1 }, process.env.JWT_SECRET);
  const send = (url, data, options = {}) => fetch(base + url, {
    method: 'POST', redirect: 'manual', body: JSON.stringify(data),
    ...options, headers: { 'Content-Type': 'application/json', Origin: 'https://finance.example', ...options.headers },
  });
  try {
    let res = await send('/test/start', { intent: 'login' }, { headers: { Origin: 'https://evil.example' } });
    assert.equal(res.status, 403);
    assert.equal(calls.length, 0);
    res = await send('/test/start', { intent: 'link', user_id: 2 });
    assert.equal(res.status, 400);
    assert.equal(calls.length, 0);
    res = await send('/test/start', { intent: 'login' });
    assert.equal(res.status, 200);
    assert.match(res.headers.get('set-cookie'), /HttpOnly/);
    assert.match(res.headers.get('set-cookie'), /Secure/);
    assert.match(res.headers.get('set-cookie'), /SameSite=Lax/);
    assert.match(res.headers.get('cache-control'), /no-store/);
    res = await send('/connections/test', { password: 'correct', user_id: 2 });
    assert.equal(res.status, 401);
    res = await send('/connections/test', { password: 'correct', user_id: 2 }, { headers: { 'X-Access-Token': token } });
    assert.equal(res.status, 200);
    assert.deepEqual(calls.find((call) => call[0] === 'fresh').slice(1, 3), [1, 'correct']);
    assert.equal(calls.filter((call) => call[0] === 'start').at(-1)[4], 1);
    res = await send('/connections/test', { password: 'correct', user_id: 2 }, { method: 'DELETE', headers: { 'X-Access-Token': token } });
    assert.equal(res.status, 200);
    assert.deepEqual(calls.find((call) => call[0] === 'disconnect'), ['disconnect', 1, 'test']);
    res = await send('/complete', { ticket: 'invalid', email: 'not-email', first_name: '', last_name: '' });
    assert.equal((await res.json()).errors[0].type, 'INVALID_INPUT');
    res = await send('/complete', { ticket: 'invalid', email: 'a@example.com', first_name: 'A', last_name: 'B' });
    assert.equal(JSON.stringify(await res.json()).includes('provider-secret'), false);
    res = await fetch(base + '/test/callback?state=opaque&code=secret-code', { redirect: 'manual' });
    assert.equal(res.status, 303);
    assert.equal(res.headers.get('location'), 'https://finance.example/auth/social#error=SIGN_IN_TO_CONNECT');
    assert.ok(!res.headers.get('location').includes('secret-code'));
  } finally { await new Promise((resolve) => server.close(resolve)); }
});
